# Ente 登录协议调研(供 OpenList-APIPages ente-login 页面参考)

来源:本地 ente monorepo(相对本仓库 `../ente`)源码核查,全部带 file:line。日期:2026-10。

## 1. CORS(server/museum)
**任意 origin 可浏览器直连**(museum 层无需代理),含自托管与官方 `api.ente.com`。

`server/cmd/museum/main.go:1439-1455`(全局挂载于 `main.go:540`):
- `Access-Control-Allow-Origin` = 原样反射请求 `Origin`(等效 `*` 且带 credentials)
- `Access-Control-Allow-Credentials: true`
- Allow-Headers 含 `Content-Type, X-Auth-Token, X-Client-Package, X-Client-Version, Authorization` 等
- OPTIONS 预检返回 200(`main.go:1448-1451`)
- 未确认:官方 hosted 端点是否有仓库之外的边缘 CDN 附加策略(仓库内无迹象)

## 2. 浏览器先例(ente/web)
ente 官方 web 端**在浏览器完成完整 SRP 密码登录**,但 SRP 数学是私有的 Rust→WASM 包 `ente-prelogin-wasm`(`web/packages/wasm/prelogin/`,workspace 私有、version 0.0.0,**未发布 npm**,build 脚本 `wasm-pack build ../../rust/bindings/wasm/prelogin`),不可直接引用。

- 编排:`web/packages/accounts/services/srp.ts`(getSRPAttributes :40-50、verifySRP :170-191、createSRPSessionOnRemote :193-207、verifySRPSession :209-225)
- 登录 UI 分支:`web/packages/accounts/pages/credentials.tsx`(:236-276)、`components/LoginContents.tsx`(:52-89)
- KDF:`web/packages/accounts/services/crypto/index.ts:57-67` → wasm `deriveKey`;Rust `rust/crates/core/src/crypto/argon.rs:54-98`(Argon2id v0x13,注释明确等价 libsodium `crypto_pwhash` ALG_ARGON2ID13)
- **ente/web 的 eslint 禁用 JS SRP 库**(`fast-srp-hap`,`web/packages/accounts/eslint.config.mjs:28-31`),仅代表其内部工程选择,非协议限制

## 3. SRP-4096 流程(端点与字段)
路由注册:`server/cmd/museum/main.go:712-714`(全部 public)。

1. **GET `/users/srp/attributes?email=...`** → `{attributes:{srpUserID,srpSalt,kekSalt,memLimit,opsLimit,isEmailMFAEnabled}}`(server 类型 `server/ente/srp.go:59-70`;CLI `cli/internal/api/login.go:13-27`)。404 = 账号无 SRP verifier(走 email OTP)。
2. **POST `/users/srp/create-session`** body `{srpUserID, srpA(b64)}`(`cli/internal/api/login.go:36-39`;server `ente/srp.go:73-79`)。**srpA 解码后必须恰为 512 字节**(`server/pkg/controller/user/srp.go:233-235`)。响应 `{sessionID, srpB}`。每用户未验证 session 数有上限(TOO_MANY_UNVERIFIED_SESSIONS,srp.go:236-245)。
3. **POST `/users/srp/verify-session`** body `{srpUserID, sessionID, srpM1(b64)}`(`cli/internal/api/login.go:64-68`)。handler `srp.go:203-224`(未知用户用 FakeVerifier 防枚举),返回完整 AuthorizationResponse 含 `srpM2` —— **客户端必须验证 M2**(`session.verifyM2`,web srp.ts:188)。

**AuthorizationResponse**(`cli/internal/api/login_type.go:34-45`):`ID, keyAttributes, encryptedToken, accountsUrl, token, twoFactorSessionID, passkeySessionID, srpM2`。SRP 成功路径返回 `keyAttributes` + `encryptedToken`(sealed),**明文 token 不在响应里**(见 §7)。

## 4. KEK 派生与 keyAttributes 解密
KDF 参数来自 srp/attributes 响应(`kekSalt, opsLimit, memLimit`)。

- **KEK** = argon2id(password, b64dec(kekSalt), time=opsLimit, memory=memLimit bytes, parallelism=1, 32B out)(`cli/internal/crypto/crypto.go:34-45`)
- **loginKey** = blake2b keyed subkey 的前 16 字节:context=`"loginctx"`(8B 零填充到 16B personalization)、salt=LE64(subKeyID=1) 零填充到 16B、输出 32B(`crypto.go:13-15, 49-74`;Rust 参照 `rust/crates/core/src/crypto/kdf.rs:15-49,58-63`,等价 libsodium `crypto_kdf_derive_from_key`)
- **KeyAttributes**(`cli/internal/api/login_type.go:24-33`):`kekSalt, encryptedKey, keyDecryptionNonce, publicKey, encryptedSecretKey, secretKeyDecryptionNonce, memLimit, opsLimit`(除整数外均 base64 std)
- **解密链**(`cli/pkg/sign_in.go:79-106`):
  ```
  masterKey = SecretBoxOpen(b64(encryptedKey),       b64(keyDecryptionNonce),       KEK)
  secretKey = SecretBoxOpen(b64(encryptedSecretKey), b64(secretKeyDecryptionNonce), masterKey)
  token     = SealedBoxOpen(b64(encryptedToken),     b64(publicKey),                secretKey)
  ```
  每个 nonce 是独立 JSON 字段(不是密文前缀)。

## 5. 2FA(TOTP + passkey)
**token 在 2FA 完成前为空 —— 已确认**(`server/pkg/controller/user/userauth.go:663-670`):开启 passkey/TOTP 时响应只含 `ID + twoFactorSessionID/passkeySessionID + accountsUrl`。

- **TOTP**:POST `/users/two-factor/verify` body `{sessionID: twoFactorSessionID, code: 6位}`(CLI `login.go` VerifyTotp;web `web/packages/accounts/services/user.ts:401-406`);响应同 AuthorizationResponse(含 keyAttributes+encryptedToken,`server/pkg/controller/user/twofactor.go:196-224`)
- **passkey**:客户端跳转 `{accountsUrl}/passkeys/verify?clientPackage=...&passkeySessionID=...&redirect={origin}/passkeys/finish`(web `services/passkey.ts:21-39`),WebAuthn 仪式在 accounts.ente.io 页完成,本页轮询 `GET /users/two-factor/passkeys/get-token?sessionID=...`(404=session 过期;passkey.ts:127-130;CLI `cli/pkg/sign_in.go` verifyPassKey 同款)

## 6. Email OTP 路径
触发条件:attributes 404 或 `isEmailMFAEnabled==true`(`cli/pkg/account.go:38-52`;web `LoginContents.tsx:53-56`)。

1. POST `/users/ott` body `{email, purpose:"login"}`(CLI login.go:86-93)
2. POST `/users/verify-email` body `{email, ott}`(login.go:96-118)→ 响应即 onVerificationSuccess 形状(userauth.go:611-712)
3. **OTP 验证后仍需密码**:keyAttributes 要 KEK 才能解开(先例:`web/apps/space/src/services/login.ts:200-206`)

## 7. Token 格式 / headers / 过期
- **非 JWT**:`GenerateURLSafeRandomString(32)` = base64url(32 随机字节),约 43 字符(`server/pkg/utils/auth/auth.go:48-50`;`controller/user/userauth.go:680`)
- 正常登录响应里 token 是 sealed(`GetEncryptedToken(token, keyAttributes.PublicKey)`,userauth.go:697-704),客户端用 secretKey 做 libsodium sealed box open
- 后续请求 header:`X-Auth-Token`;`X-Client-Package` 选择 app 上下文(`auth.go:78-86`:`io.ente.auth`→Auth、`io.ente.locker`→Locker、其余→Photos 族),登录路径无白名单校验(按推断标注:仓库内未见校验)
- **过期**:无绝对 TTL;仅 365 天未使用(`server/pkg/repo/userauth.go:285-289`)
- **CLI 无 hex 导出 masterKey 的代码**(全仓库仅 `utils/encoding/encoding.go:16-18` EncodeBase64)——hex/base64 是调用方选择

## 8. 限流
**登录族 10 req/min,键 = clientIP + path**(`server/pkg/middleware/rate_limit.go:313-337`):`/users/ott`、`/users/verify-email`、`/users/srp/attributes`、`/users/srp/create-session`、`/users/srp/verify-session`、前缀 `/users/srp/`、前缀 `/users/two-factor/`。429 响应 `{"error":"Rate limit breached, try later"}`。附加:OTT 发送限制(50/5min 告警、200/5min 全局封禁,`controller/user/ott_send_limiter.go:12-16`)、SRP 未验证 session 上限。

## 9. SRP 语义参照
- server 用 `github.com/ente/go-srp`（fork，MIT；`server/go.mod:15`），Go CLI 用 `github.com/kong/go-srp`（`cli/go.mod:30`；`cli/pkg/sign_in.go:31` `srp.GetParams(4096)`）；identity=srpUserID 字节、salt=b64dec(srpSalt)、password 输入=loginKey
- ente 的 Rust 实现注释明确:**srp crate 直接用 S 算 M2,而 ente server 用 K=H(S)**(即标准 SRP-6a),并做 group 大小左填充(`rust/crates/accounts/src/auth/srp.rs:49-84`)
- **TS 移植应对齐 ente server 实际运行的 ente/go-srp 的 SRP-6a/4096/SHA-256 语义（哈希输入按 group 大小左填充）**;ente/web 无纯 TS 实现,官方测试向量在 `web/packages/wasm/prelogin/tests/auth.test.ts` 与 `tests/crypto.test.ts`(数据可作测试参照)
- ente/go-srp 许可证 MIT（Insomnia 血统），kong/go-srp 为 Apache-2.0；从语义移植无 AGPL 顾虑;ente monorepo 整体 AGPL-3.0,**不得复制其代码或 vendored WASM 产物进本仓库(MIT)**,仅参照协议事实与测试向量

## 未确认项
1. 官方 hosted api.ente.com 边缘层是否附加 CORS/防护策略(仓库外)
2. `X-Client-Package` 是否存在登录路径外的校验(登录路径未见)
3. 浏览器 WASM/JS 内存上限对 1GB memLimit 账号的实际影响(Safari 尤甚)——需实现期验证
