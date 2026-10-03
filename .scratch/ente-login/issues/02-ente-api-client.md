# 02: Ente API client(浏览器直连)

**Status:** ready-for-agent
**Type:** task

## Question

类型化的 ente museum HTTP client:登录族端点、响应解析、错误映射。端点与字段见 research §3/§5/§6/§8。

## Notes

- fetch 以构造参数注入(便于零依赖测试);headers:`Content-Type: application/json`、`X-Client-Package: io.ente.photos`。
- 端点:GET `users/srp/attributes`(404 → OTP 路径信号)、POST `users/srp/create-session`、POST `users/srp/verify-session`、POST `users/ott`、POST `users/verify-email`、POST `users/two-factor/verify`。
- endpoint 可配置,默认 `https://api.ente.com`,去除末尾斜杠。
- 响应解析:keyAttributes、encryptedToken、twoFactorSessionID/passkeySessionID 判空(空 token + passKeySessionID → 抛「v1 不支持 passkey」)。
- 错误映射:401(凭证/验证码错)、404(账号不存在)、429(限流,提示稍后再试)、fetch 异常(endpoint 不可达)。保留 server error 字段原文用于展示。
- 测试:`node:test` + 注入假 fetch,断言 URL/payload/分支/错误映射;不 mock crypto。

## Acceptance

- client 模块导出类型化方法与可读 Error;单测覆盖每端点与 2FA/OTP/限流分支。
