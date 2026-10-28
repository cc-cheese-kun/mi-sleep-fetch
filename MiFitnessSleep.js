// MiFitnessSleep.js — Scriptable 版小米运动健康（Mi Fitness）睡眠拉取
// 放到 iCloud Drive/Scriptable/ 里，然后在「捷徑」用「執行 Scriptable 腳本」调用。
//
// 为什么必须是 Scriptable 而不是纯捷徑：
//   hlth.io.mi.com 的请求体与响应体是 RC4-drop1024 加密 + base64，
//   还要算 SHA1/SHA256 签名；捷徑里没有任何加密动作，纯捷徑拿不到数据。
//   所以：Scriptable 负责「认证 + 签名 + 解密 + 规范化」，捷徑只负责「寫入 HealthKit」。
//
// 首次运行会弹窗让你填 userId / passToken，存进 Keychain，之后不再问。
// 输出（Shortcut Output）结构：
//   {
//     ok: true, date: "2025-10-27", sessionCount: 1,
//     primary: { start: "2025-10-26T23:20:00+08:00", end: "...", asleepMin, awakeMin, durationMin, score },
//     sessions: [ { start, end, asleepMin, awakeMin, durationMin, score, isNap,
//                   stages: [ { stage:"deep"|"light"|"rem"|"awake", start, end, minutes } ] } ]
//   }

const DEFAULTS = {
  region: "cn",
  dayOffset: 0,         // 0 = 今天。早上跑能拿到昨晚的睡眠（记录时间落在今天）
  lookbackDays: 1,      // 查询窗口往前多算几天，防止睡眠跨零点/跨日归属漏掉
  defaultZoneOffset: 28800,
  debug: false,
  // 可选：预填凭证，省去手机上手动粘贴 300 字符的 passToken。
  // 留空则首次运行时弹窗输入并存进 Keychain。跑通后建议清空这两行。
  seedUserId: "",
  seedPassToken: "",
};

// ===========================================================================
// 1) 纯 JS 加密原语（Scriptable 无 crypto，全部自实现）
// ===========================================================================
function utf8Bytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c >= 0xd800 && c <= 0xdbff) {
      const c2 = str.charCodeAt(++i);
      const cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}

function bytesToUtf8(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; ) {
    const b = bytes[i++];
    if (b < 0x80) s += String.fromCharCode(b);
    else if (b < 0xe0) s += String.fromCharCode(((b & 31) << 6) | (bytes[i++] & 63));
    else if (b < 0xf0)
      s += String.fromCharCode(((b & 15) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63));
    else {
      const cp =
        ((b & 7) << 18) | ((bytes[i++] & 63) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63);
      s += String.fromCodePoint(cp);
    }
  }
  return s;
}

const B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64encode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i],
      b1 = bytes[i + 1],
      b2 = bytes[i + 2];
    out += B64C[b0 >> 2];
    out += B64C[((b0 & 3) << 4) | ((b1 || 0) >> 4)];
    out += i + 1 < bytes.length ? B64C[((b1 & 15) << 2) | ((b2 || 0) >> 6)] : "=";
    out += i + 2 < bytes.length ? B64C[b2 & 63] : "=";
  }
  return out;
}

function b64decode(str) {
  const clean = String(str).replace(/[^A-Za-z0-9+/]/g, "");
  const out = [];
  for (let i = 0; i < clean.length; i += 4) {
    const n0 = B64C.indexOf(clean[i]),
      n1 = B64C.indexOf(clean[i + 1]),
      n2 = B64C.indexOf(clean[i + 2]),
      n3 = B64C.indexOf(clean[i + 3]);
    if (n0 < 0 || n1 < 0) break;
    out.push((n0 << 2) | (n1 >> 4));
    if (n2 >= 0) out.push(((n1 & 15) << 4) | (n2 >> 2));
    if (n3 >= 0) out.push(((n2 & 3) << 6) | n3);
  }
  return new Uint8Array(out);
}

function sha1(bytes) {
  const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const len = bytes.length;
  const bitLo = (len * 8) >>> 0;
  const bitHi = Math.floor(len / 536870912) >>> 0;
  const total = Math.ceil((len + 9) / 64) * 64;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[len] = 0x80;
  const pv = new DataView(buf.buffer);
  pv.setUint32(total - 8, bitHi);
  pv.setUint32(total - 4, bitLo);

  const w = new Uint32Array(80);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = pv.getUint32(off + i * 4);
    for (let i = 16; i < 80; i++) {
      const v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (v << 1) | (v >>> 31);
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = K[0]; }
      else if (i < 40) { f = b ^ c ^ d; k = K[1]; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = K[2]; }
      else { f = b ^ c ^ d; k = K[3]; }
      const t = ((((a << 5) | (a >>> 27)) >>> 0) + (f >>> 0) + (e >>> 0) + k + w[i]) >>> 0;
      e = d; d = c; c = ((b << 30) | (b >>> 2)) >>> 0; b = a; a = t;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  const out = new Uint8Array(20);
  const ov = new DataView(out.buffer);
  [h0, h1, h2, h3, h4].forEach((h, i) => ov.setUint32(i * 4, h >>> 0));
  return out;
}

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256(bytes) {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const len = bytes.length;
  const bitLo = (len * 8) >>> 0;
  const bitHi = Math.floor(len / 536870912) >>> 0;
  const total = Math.ceil((len + 9) / 64) * 64;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[len] = 0x80;
  const pv = new DataView(buf.buffer);
  pv.setUint32(total - 8, bitHi);
  pv.setUint32(total - 4, bitLo);

  const w = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = pv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const a1 = w[i - 15], a2 = w[i - 2];
      const s0 = (((a1 >>> 7) | (a1 << 25)) ^ ((a1 >>> 18) | (a1 << 14)) ^ (a1 >>> 3)) >>> 0;
      const s1 = (((a2 >>> 17) | (a2 << 15)) ^ ((a2 >>> 19) | (a2 << 13)) ^ (a2 >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((x, i) => ov.setUint32(i * 4, x >>> 0));
  return out;
}

// RC4-drop1024：丢弃前 1024 字节 keystream，加解密对称
function rc4Drop1024(key, payload) {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  const klen = key.length;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % klen]) & 255;
    const t = s[i]; s[i] = s[j]; s[j] = t;
  }
  let i = 0; j = 0;
  const nxt = () => {
    i = (i + 1) & 255;
    j = (j + s[i]) & 255;
    const t = s[i]; s[i] = s[j]; s[j] = t;
    return s[(s[i] + s[j]) & 255];
  };
  for (let n = 0; n < 1024; n++) nxt();
  const out = new Uint8Array(payload.length);
  for (let n = 0; n < payload.length; n++) out[n] = payload[n] ^ nxt();
  return out;
}

// ===========================================================================
// 2) 小米签名链
// ===========================================================================
function genNonce(nowMs) {
  const b = new Uint8Array(12);
  for (let i = 0; i < 8; i++) b[i] = Math.floor(Math.random() * 256);
  const mins = Math.floor((nowMs === undefined ? Date.now() : nowMs) / 60000) >>> 0;
  b[8] = (mins >>> 24) & 255; b[9] = (mins >>> 16) & 255;
  b[10] = (mins >>> 8) & 255; b[11] = mins & 255;
  return b;
}

function signedNonceOf(ssecurity, nonce) {
  const cat = new Uint8Array(ssecurity.length + nonce.length);
  cat.set(ssecurity, 0);
  cat.set(nonce, ssecurity.length);
  return sha256(cat);
}

function genSignature(method, path, values, sn) {
  let base = method + "&" + path + "&data=" + values["data"];
  if (values["rc4_hash__"] !== undefined) base += "&rc4_hash__=" + values["rc4_hash__"];
  base += "&" + b64encode(sn);
  return b64encode(sha1(utf8Bytes(base)));
}

function encryptForm(path, payloadObj, ssecurity, nonce) {
  const sn = signedNonceOf(ssecurity, nonce);
  const form = { data: JSON.stringify(payloadObj) };
  form["rc4_hash__"] = genSignature("POST", path, form, sn);
  const enc = {};
  for (const k of Object.keys(form)) {
    enc[k] = b64encode(rc4Drop1024(sn, utf8Bytes(form[k])));
  }
  enc["signature"] = genSignature("POST", path, enc, sn);
  enc["_nonce"] = b64encode(nonce);
  const qs = Object.keys(enc)
    .map((k) => encodeURIComponent(k) + "=" + encodeURIComponent(enc[k]))
    .join("&");
  return { body: qs, signedNonce: sn };
}

// ===========================================================================
// 3) HTTP
// ===========================================================================
const UA = "MiFit/6.0.0 (iPhone; iOS 17.5; Scale/3.00)";

function splitSetCookie(raw) {
  if (!raw) return [];
  // Scriptable 会把重复 header 用 ", " 合并，按 "key=" 模式拆回来
  return String(raw)
    .split(/,(?=\s*[A-Za-z0-9_\-]+=)/)
    .map((x) => x.split(";")[0].trim())
    .filter((x) => x.indexOf("=") > 0);
}

function headerLookup(headers, name) {
  const lower = name.toLowerCase();
  for (const k of Object.keys(headers || {})) {
    if (k.toLowerCase() === lower) return headers[k];
  }
  return undefined;
}

async function httpGet(url, headers, follow) {
  const req = new Request(url);
  req.method = "GET";
  req.timeoutInterval = 30;
  req.followRedirects = follow === undefined ? true : follow;
  req.headers = headers || {};
  const body = await req.loadString();
  return { status: req.response.statusCode, headers: req.response.headers || {}, body };
}

async function httpPostForm(url, body, headers) {
  const req = new Request(url);
  req.method = "POST";
  req.timeoutInterval = 30;
  req.followRedirects = false;
  req.headers = Object.assign({ "Content-Type": "application/x-www-form-urlencoded" }, headers || {});
  req.body = body;
  const text = await req.loadString();
  return { status: req.response.statusCode, headers: req.response.headers || {}, body: text };
}

// ===========================================================================
// 4) 客户端
// ===========================================================================
class MiFitness {
  constructor(userId, passToken, region) {
    this.userId = String(userId);
    this.passToken = passToken;
    this.region = region || "cn";
    this.ssecurity = null;
    this.cookies = "";
    this.base =
      this.region === "" || this.region === "cn"
        ? "https://hlth.io.mi.com"
        : "https://" + this.region + ".hlth.io.mi.com";
  }

  async login() {
    const loginUrl =
      "https://account.xiaomi.com/pass/serviceLogin?_json=true&sid=miothealth";
    const r1 = await httpGet(
      loginUrl,
      { Cookie: "userId=" + this.userId + "; passToken=" + this.passToken, "User-Agent": UA },
      true
    );
    const text = r1.body || "";
    const marker = "&&&START&&&";
    const idx = text.indexOf(marker);
    if (idx < 0) throw new Error("登录响应异常 (HTTP " + r1.status + "): " + text.slice(0, 200));
    const j = JSON.parse(text.slice(idx + marker.length));
    if (!j.ssecurity) throw new Error("登录失败，passToken 可能已失效: " + JSON.stringify(j).slice(0, 200));
    this.userId = String(j.userId);
    this.passToken = j.passToken;
    this.ssecurity = b64decode(j.ssecurity);

    const r2 = await httpGet(j.location, { "User-Agent": UA }, false);
    const parts = splitSetCookie(headerLookup(r2.headers, "Set-Cookie"));
    if (!parts.length) throw new Error("未取得 serviceToken Cookie (HTTP " + r2.status + ")");
    this.cookies = parts.join("; ");
    if (DEFAULTS.debug) console.log("cookies: " + this.cookies);
  }

  async post(path, payload) {
    const nonce = genNonce();
    const { body, signedNonce } = encryptForm(path, payload, this.ssecurity, nonce);
    const r = await httpPostForm(this.base + path, body, {
      Cookie: this.cookies,
      "User-Agent": UA,
    });
    const text = String(r.body).trim();
    // 出错时云端返回明文 JSON（如 {"code":2,"message":"auth err"}），正常才是 base64 密文
    let plainErr = null;
    if (text.charAt(0) === "{") {
      try {
        const maybe = JSON.parse(text);
        if (maybe && maybe.code !== 0) plainErr = maybe;
      } catch (e) {}
    }
    if (plainErr) {
      throw new Error(
        "明文错误 HTTP " + r.status + " code=" + plainErr.code + " message=" + plainErr.message +
        "（code=2/401 = Cookie 或签名无效，通常 passToken 过期，需重新抓取）"
      );
    }
    if (r.status !== 200) throw new Error("HTTP " + r.status + ": " + text.slice(0, 200));
    const plain = bytesToUtf8(rc4Drop1024(signedNonce, b64decode(text)));
    let j;
    try {
      j = JSON.parse(plain);
    } catch (e) {
      throw new Error("响应解密失败: " + plain.slice(0, 200));
    }
    if (j.code !== 0) throw new Error("接口 code=" + j.code + " message=" + j.message);
    return j.result || {};
  }

  async fetchKey(key, startTs, endTs) {
    const out = [];
    let nextKey = null;
    for (let page = 0; page < 20; page++) {
      const payload = { start_time: startTs, end_time: endTs, key: key };
      if (nextKey) payload.next_key = nextKey;
      const res = await this.post("/app/v1/data/get_fitness_data_by_time", payload);
      (res.data_list || []).forEach((x) => out.push(x));
      if (!res.has_more || !res.next_key) break;
      nextKey = String(res.next_key);
    }
    return out;
  }
}

// ===========================================================================
// 5) 规范化
// ===========================================================================
const STATE_MAP = { 1: "deep", 2: "light", 3: "light", 4: "awake", 5: "rem" };

function isoFromTs(ts, zoneOffsetSec) {
  const off = typeof zoneOffsetSec === "number" && !isNaN(zoneOffsetSec) ? zoneOffsetSec : DEFAULTS.defaultZoneOffset;
  const d = new Date((Number(ts) + off) * 1000);
  const p = (n) => String(n).padStart(2, "0");
  const sign = off < 0 ? "-" : "+";
  const abs = Math.abs(off);
  return (
    d.getUTCFullYear() + "-" + p(d.getUTCMonth() + 1) + "-" + p(d.getUTCDate()) +
    "T" + p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + ":" + p(d.getUTCSeconds()) +
    sign + p(Math.floor(abs / 3600)) + ":" + p(Math.floor((abs % 3600) / 60))
  );
}

function parseValue(item) {
  const raw = item.value;
  if (raw && typeof raw === "object") return raw;
  try {
    return JSON.parse(raw || "{}");
  } catch (e) {
    return {};
  }
}

function normalizeSleep(items, skipIncomplete) {
  const skip = skipIncomplete === undefined ? true : skipIncomplete;

  // 坑：同一次睡眠会随同步多次更新 —— sid 相同、time 递增的多条快照，
  // 未结束的那条还带 is_uncomplete。只留 time 最大的一条，否则写进 HealthKit 会重叠翻倍。
  const latest = {};
  for (const it of items) {
    const sid = String(it.sid || it.time);
    const t = Number(it.time || 0);
    if (!latest[sid] || t > Number(latest[sid].time || 0)) latest[sid] = it;
  }

  const sessions = [];
  for (const key of Object.keys(latest)) {
    const item = latest[key];
    const v = parseValue(item);
    let zo = Number(item.zone_offset || 0);
    if (!zo) zo = DEFAULTS.defaultZoneOffset;

    if (skip && v.is_uncomplete) continue;

    const start = v.bedtime || v.device_bedtime || v.bed_timestamp;
    const end = v.wake_up_time || v.device_wake_up_time || v.out_bed_timestamp || item.time;
    if (!start || !end) continue;

    const dur = Number(v.duration || Math.max(0, Math.floor((end - start) / 60))); // 分钟
    const awake0 = Number(v.sleep_awake_duration || v.awake_duration || 0); // 分钟
    const asleep = Math.max(0, dur - awake0);

    const stages = [];
    const acc = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    for (const seg of v.items || []) {
      const sTs = Number(seg.start_time || 0);
      const eTs = Number(seg.end_time || 0);
      if (!sTs || !eTs) continue;
      const st = Number(seg.state);
      const mins = Math.max(0, Math.floor((eTs - sTs) / 60));
      acc[st] = (acc[st] || 0) + mins;
      stages.push({
        state: st,
        stage: STATE_MAP[st] || "light",
        start: isoFromTs(sTs, zo),
        end: isoFromTs(eTs, zo),
        startTs: sTs,
        endTs: eTs,
        minutes: mins,
      });
    }

    const deep = v.sleep_deep_duration !== undefined ? Number(v.sleep_deep_duration) : acc[1] || 0;
    const light = v.sleep_light_duration !== undefined ? Number(v.sleep_light_duration) : (acc[2] || 0) + (acc[3] || 0);
    const rem = v.sleep_rem_duration !== undefined ? Number(v.sleep_rem_duration) : acc[5] || 0;
    const awake = awake0 || acc[4] || 0;

    const startHour = new Date((Number(start) + zo) * 1000).getUTCHours();
    const inferredNight = startHour >= 18 || startHour < 8;

    sessions.push({
      id: String(item.sid || "") + "_" + String(item.time || end),
      sid: String(item.sid || ""),
      startTs: Number(start),
      endTs: Number(end),
      start: isoFromTs(start, zo),
      end: isoFromTs(end, zo),
      durationMin: dur,
      asleepMin: asleep,
      awakeMin: awake,
      deepMin: deep,
      lightMin: light,
      remMin: rem,
      score: v.score || v.sleep_score || null,
      isNap: v.is_nap ? true : !inferredNight,
      avgHr: v.avg_hr || null,
      avgSpo2: v.avg_spo2 || null,
      stages: stages,
    });
  }
  sessions.sort((a, b) => a.startTs - b.startTs);
  return sessions;
}

function pickPrimary(sessions, includeNaps) {
  let pool = includeNaps ? sessions.slice() : sessions.filter((s) => !s.isNap);
  if (!pool.length) pool = sessions.slice();
  if (!pool.length) return null;
  pool.sort((a, b) => (b.asleepMin - a.asleepMin) || (a.startTs - b.startTs));
  return pool[0];
}

// ===========================================================================
// 6) 入口
// ===========================================================================
function ymd(date) {
  const p = (n) => String(n).padStart(2, "0");
  return date.getFullYear() + "-" + p(date.getMonth() + 1) + "-" + p(date.getDate());
}

function dayRange(dateStr) {
  // 固定按 +08:00 归日（小米中国区日聚合口径）
  const start = Math.floor(Date.parse(dateStr + "T00:00:00+08:00") / 1000);
  return [start, start + 86399];
}

async function loadConfig() {
  const KM = { u: "mifit.userId", p: "mifit.passToken", r: "mifit.region" };
  let userId = Keychain.contains(KM.u) ? Keychain.get(KM.u) : null;
  let passToken = Keychain.contains(KM.p) ? Keychain.get(KM.p) : null;
  let region = Keychain.contains(KM.r) ? Keychain.get(KM.r) : DEFAULTS.region;

  // 预填凭证优先落进 Keychain，之后就不再依赖脚本里的明文
  if ((!userId || !passToken) && DEFAULTS.seedUserId && DEFAULTS.seedPassToken) {
    userId = userId || DEFAULTS.seedUserId;
    passToken = passToken || DEFAULTS.seedPassToken;
    Keychain.set(KM.u, userId);
    Keychain.set(KM.p, passToken);
    Keychain.set(KM.r, region);
    console.log("已从脚本内置凭证写入 Keychain");
  }

  if (!userId || !passToken) {
    const a = new Alert();
    a.title = "小米运动健康凭证";
    a.message = "userId：账号数字 ID（account.xiaomi.com 的 cookie）";
    a.addTextField("userId", userId || "");
    a.addTextField("passToken", passToken || "");
    a.addTextField("region (cn/sg/de/us/i2/ru)", region);
    a.addAction("保存");
    a.addCancelAction("取消");
    const i = await a.presentAlert();
    if (i === -1) throw new Error("已取消");
    userId = a.textFieldValue(0).trim();
    passToken = a.textFieldValue(1).trim();
    region = a.textFieldValue(2).trim() || "cn";
    Keychain.set(KM.u, userId);
    Keychain.set(KM.p, passToken);
    Keychain.set(KM.r, region);
  }
  return { userId, passToken, region };
}

// setShortcutOutput 只在被捷徑调用时有效，手动运行会抛异常 —— 必须包起来，
// 否则异常会把后面的 Alert 一起吞掉，表现就是「点了没反应」。
function safeSetOutput(obj) {
  if (typeof Script === "undefined") return;
  try {
    Script.setShortcutOutput(typeof obj === "string" ? obj : JSON.stringify(obj));
  } catch (e) {
    console.log("setShortcutOutput 不可用: " + e);
  }
}

function isInShortcut() {
  try {
    return typeof config !== "undefined" && config && config.runsInShortcut === true;
  } catch (e) {
    return false;
  }
}

async function showResult(result) {
  const a = new Alert();
  const p = result.primary;
  if (p) {
    a.title = result.date + " 睡眠";
    a.message =
      p.start + " → " + p.end +
      "\n卧 " + p.durationMin + "min / 睡 " + p.asleepMin + "min" +
      "\n深 " + p.deepMin + " / 浅 " + p.lightMin + " / REM " + p.remMin + " / 醒 " + p.awakeMin +
      (p.isNap ? "\n（白天睡眠）" : "");
  } else {
    a.title = result.date;
    a.message = "当天没有睡眠记录。\n手环需要先和「小米运动健康」App 同步。";
  }
  a.addAction("好");
  await a.presentAlert();
}

async function main() {
  if (typeof Script === "undefined") {
    // node 环境（自检脚本）下不执行真实流程
    return { ok: false, error: "not running in Scriptable" };
  }
  // 坑：Scriptable 里 args / config 是全局变量。绝不能写 const args = ...，
  // 否则同一作用域内 typeof args 会命中 TDZ，抛 ReferenceError 且 stack 里只有 main@。
  const inputArgs = typeof args !== "undefined" && args ? args : {};
  const qp = inputArgs.queryParameters || {};
  if (qp.debug === "1") DEFAULTS.debug = true;

  const cfg = await loadConfig();
  const client = new MiFitness(cfg.userId, cfg.passToken, cfg.region);
  await client.login();

  let dateStr = qp.date;
  if (!dateStr) {
    const offset = qp.offset !== undefined ? parseInt(qp.offset, 10) : DEFAULTS.dayOffset;
    const d = new Date();
    d.setDate(d.getDate() + offset);
    dateStr = ymd(d);
  }

  const [s0, e] = dayRange(dateStr);
  const s = s0 - 86400 * (DEFAULTS.lookbackDays || 0);
  const items = await client.fetchKey("sleep", s, e);
  const sessions = normalizeSleep(items, !(qp.keepIncomplete === "1"));

  const primary = pickPrimary(sessions, qp.includeNaps === "1");

  const result = {
    ok: true,
    date: dateStr,
    sessionCount: sessions.length,
    primary: primary
      ? {
          start: primary.start,
          end: primary.end,
          asleepMin: primary.asleepMin,
          awakeMin: primary.awakeMin,
          durationMin: primary.durationMin,
          deepMin: primary.deepMin,
          lightMin: primary.lightMin,
          remMin: primary.remMin,
          score: primary.score,
          isNap: primary.isNap,
        }
      : null,
    sessions: sessions,
  };

  if (DEFAULTS.debug) console.log(JSON.stringify(result, null, 2));

  if (typeof Script !== "undefined") {
    const inShortcut = isInShortcut();
    if (inShortcut) safeSetOutput(result);
    if (!inShortcut) await showResult(result);
    Script.complete();
  }
  return result;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    utf8Bytes, bytesToUtf8, b64encode, b64decode, sha1, sha256,
    rc4Drop1024, genNonce, signedNonceOf, genSignature, encryptForm,
    normalizeSleep, pickPrimary, isoFromTs, dayRange,
  };
}

// ===== Scriptable 启动 =====
// 必须是文件最外层的裸 await：不能包在 if/else 或 try 块里，
// 否则 JavaScriptCore 会按普通 script 解析而报语法错误（表现就是完全没反应）。
await main().catch(async (err) => {
  const detail = err
    ? ((err.name || "Error") + ": " + (err.message || String(err)) + (err.stack ? "\n\n" + err.stack : ""))
    : "未知错误";
  const msg = String(detail);
  try {
    if (isInShortcut()) {
      safeSetOutput({ ok: false, error: msg });
    } else {
      const a = new Alert();
      a.title = "出错了";
      a.message = msg;
      a.addAction("好");
      await a.presentAlert();
    }
  } catch (e) {
    console.log("弹窗失败: " + e);
  }
  try { Script.complete(); } catch (e) {}
});
