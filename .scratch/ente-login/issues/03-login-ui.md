# 03: TokenPage Ente 登录交互

**Status:** ready-for-agent
**Type:** task

## Question

前端把 ente 接入现有 TokenPage:表单、二次验证步、结果区、i18n。

## Notes

- `frontend/src/lib/drivers.ts`:DRIVERS 增加 ente 项(i18nKey `driver.options.ente`);不适用 isCredentialHidden/isServerUseForced*。
- i18n:11 个 locale 文件补 key(未翻译语言回退 en-US,对齐现有惯例)。
- 交互(非 OAuth redirect 型):表单(email/password/endpoint,默认官方)→ 依 01/02 执行:attributes → (OTP 分支:发送 OTT → 输入码)→ KDF(Web Worker,loading 态)→ SRP → (TOTP 分支:输入 6 位码)→ 解密 → 结果区。
- 结果区:CopyableField 展示 `token`、`master_key`(base64)、可选 `secret_key`,附 Worker `ente` 驱动字段填法(`endpoint`、`show_hidden`)与保活提示(365 天未使用才过期)。
- 密码/密钥不落 localStorage/cookie/日志;流程结束或出错后清空内存态。
- 错误展示全部走 02 的映射;KDF 内存不足(大 memLimit + 低内存浏览器)单独可读文案。
- 验收以浏览器手动走查 + `npm run typecheck`;不为 ente 引入 UI 测试框架。

## Acceptance

- frontend `npm run typecheck` 通过;zh-CN/en-US 手动走查 SRP、TOTP、OTP、错误分支;结果字段可一键复制且命名对齐 Worker 驱动配置。
