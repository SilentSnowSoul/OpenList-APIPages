## Purpose

提供浏览器端 Ente 账号登录页,为 OpenList-Worker 的 `ente` 只读驱动导出长期凭证(`token`/`master_key`/可选 `secret_key`),登录与解密全程在本页浏览器内完成,不经本服务后端。

## Requirements

### Requirement: Browser-side Ente password login
系统 SHALL 在浏览器内完成 Ente SRP-4096 密码登录(argon2id KEK 派生、SRP 会话、keyAttributes 解密、sealed token 解封),且 MUST NOT 向本服务后端发送密码或任何派生密钥。

#### Scenario: 成功导出凭证
- **WHEN** 用户选择 Ente 驱动并提交正确的 email、密码与 endpoint
- **THEN** 页面展示可复制的 `token`、`master_key`(base64)与可选 `secret_key`,字段命名对齐 OpenList-Worker `ente` 驱动配置

#### Scenario: 密码错误
- **WHEN** SRP verify-session 因凭证错误被拒绝
- **THEN** 页面展示可读错误且不展示任何凭证

### Requirement: Second-factor verification (TOTP)
已开启 TOTP 的账号,系统 SHALL 在 SRP 成功后要求 6 位验证码并调用 two-factor/verify 完成登录。二次验证会话 ID SHALL 同时接受 `twoFactorSessionID` 与 `twoFactorSessionIDV2`(passkey 与 TOTP 同时开启时服务端只回后者,且 V1 字段因无 omitempty 会是空串),两者等价。

#### Scenario: TOTP 账号完成二次验证
- **WHEN** SRP 响应含 twoFactorSessionID 且 token 为空,用户随后输入正确验证码
- **THEN** 二次验证成功并导出凭证

#### Scenario: passkey + TOTP 账号完成二次验证
- **WHEN** SRP 响应含 `twoFactorSessionIDV2`(同时含 `passkeySessionID`)且 token 为空
- **THEN** 页面要求 TOTP 验证码(而非报「不支持 passkey」),验证成功后导出凭证

#### Scenario: 验证码错误
- **WHEN** 用户输入错误验证码
- **THEN** 页面展示可读错误,允许重试

### Requirement: Email OTP login path
无 SRP 记录或开启 email-MFA 的账号,系统 SHALL 走邮箱 OTP 路径(发送 OTT、校验 verify-email),并在校验后仍用密码派生 KEK 解密 keyAttributes。

#### Scenario: email-MFA 账号登录
- **WHEN** srp/attributes 返回 isEmailMFAEnabled 或 404,用户输入邮箱收到的 OTT 与密码
- **THEN** 登录成功并导出凭证

#### Scenario: email-MFA + TOTP 账号登录
- **WHEN** verify-email 响应含 twoFactorSessionID 或 twoFactorSessionIDV2 且 token 为空
- **THEN** 页面要求 TOTP 验证码,验证成功后用密码派生 KEK 解密 keyAttributes 并导出凭证

### Requirement: Passkey accounts rejected with explicit notice
v1 系统 SHALL 对仅支持 passkey 登录的账号给出明确的「不支持」提示,而不是模糊报错;passkey 与 TOTP 同时开启的账号 SHALL 走 TOTP 路径(见二次验证要求)。

#### Scenario: 仅 passkey 账号
- **WHEN** 登录响应含 `passkeySessionID` 且无 twoFactorSessionID / twoFactorSessionIDV2(server/ente/user.go:56)
- **THEN** 页面提示 v1 不支持 passkey 登录并建议改用密码/TOTP 方式

### Requirement: Custom endpoint support
系统 SHALL 允许用户自定义 Ente API endpoint(默认 `https://api.ente.com`),浏览器直连该 endpoint。

#### Scenario: 自托管 museum
- **WHEN** 用户填入自托管 museum 的 endpoint 并登录
- **THEN** 全流程对该 endpoint 直连完成,行为与官方 endpoint 一致

#### Scenario: endpoint 不可达
- **WHEN** 自定义 endpoint 无法访问
- **THEN** 页面展示可读网络错误

### Requirement: Credentials never leave the browser
密码与派生密钥 MUST NOT 离开浏览器:不发给本服务后端、不写入持久化存储( localStorage/cookie)、不输出到控制台日志。

#### Scenario: 无本服务后端参与
- **WHEN** 登录流程执行
- **THEN** 除静态资源外没有请求发往本服务域名,流程结束或出错后内存中的密码与密钥被清空

### Requirement: Readable error mapping
系统 SHALL 将服务端与网络错误映射为可读提示:401 凭证/验证码错误、404 账号不存在、429 限流(提示稍后再试)、endpoint 不可达、KDF 内存不足。

#### Scenario: 触发限流
- **WHEN** 服务端返回 429
- **THEN** 页面提示限流并建议稍后再试

### Requirement: Output copyable and aligned with worker driver config
结果区 SHALL 用现有 CopyableField 展示凭证,附 OpenList-Worker `ente` 驱动其余字段填法(`endpoint`、`show_hidden`)与 token 保活语义(365 天未使用才过期);界面文案覆盖站点全部 locale(未翻译回退 en-US)。

#### Scenario: 一键复制
- **WHEN** 登录成功
- **THEN** token、master_key、secret_key(如有)均可一键复制,且 README 驱动列表包含 Ente
