# MiFitnessSleep

从小米运动健康云端拉取睡眠分期（深睡 / 浅睡 / REM / 清醒），输出 JSON。

两个版本，逻辑同源：

- `mifit-sleep.mjs`：给 AI / 服务器用的 Node 版，推荐用这个
- `MiFitnessSleep.js`：给 iPhone 用的 Scriptable 版，输出给捷径写入 HealthKit

## Node 版用法

```bash
export MIFIT_USER_ID=你的小米账号数字ID
export MIFIT_PASS_TOKEN=你的passToken
node mifit-sleep.mjs --date=2026-10-28 --keep-incomplete=1 --include-naps=1
```

不带 `--date` 默认查今天；`--keep-incomplete=1` 会包含云端未完成标记的记录，刚起床那段常用到。

## Scriptable 版用法

1. 把 `MiFitnessSleep.js` 放到 iCloud Drive / Scriptable / 里
2. 在捷径里用「执行 Scriptable 脚本」调用，输出为 Shortcut Output
3. 首次运行会弹窗让你填 userId / passToken，存进 Keychain，之后不再问

## 凭证说明

- 本仓库版本已清空预填凭证，`seedUserId` / `seedPassToken` 均为空
- 不要把自己填好凭证的版本传到公开仓库，跑通后也不要把含凭证的脚本发给别人
- passToken 会过期，过期后需重新从小米账号抓取

## 注意

- 睡眠记录刚结束时云端可能带未完成标记，脚本默认跳过未完成记录，避免同一晚重叠翻倍
- 手环需先和「小米运动健康」App 同步，云端有数据才能拉到
- 本脚本只读睡眠数据，不改账号设置
