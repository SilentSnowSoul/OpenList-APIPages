# Ente 登录页(ente-login)

Status: ready-for-agent

## Problem Statement

OpenList-Worker 的 `ente` 驱动只接受长期凭证 `token` + `master_key`(可选 `secret_key`),登录(SRP-4096 + argon2id KDF)被 Worker 侧 ADR-0002 外置到本仓库:argon2 内存参数(256MB/1GB)超出 CF Workers 128MB 上限。目前用户只能本地安装 ente CLI 自行导出凭证,门槛高且 CLI 并无现成导出命令(见调研 §7)。OpenList-APIPages 作为「OpenList API Token Generator」正是承接该登录页的仓库。

## Solution

前端新增 `ente` 驱动选项与纯浏览器登录流:密码与全部解密只在浏览器完成,浏览器直连用户指定的 ente endpoint(museum CORS 全放行,调研 §1),APIPages 后端零新增路由。登录成功后展示可直接粘贴进 Worker `ente` 驱动配置的凭证字段。

## User Stories

1. As an OpenList 管理员, I want 在驱动下拉中选择 Ente 并输入 email/密码/endpoint, so that 不装 ente CLI 也能拿到 Worker 驱动凭证。
2. As an OpenList 管理员, I want 密码登录(SRP)成功后看到 `token`、`master_key`(及可选 `secret_key`), so that 直接粘进 Worker `ente` 驱动配置。
3. As an OpenList 管理员(已开 TOTP), I want 输入 6 位验证码完成二次验证, so that 2FA 账号也能导出凭证。
4. As an OpenList 管理员(email-MFA 或无 SRP 记录账号), I want 走邮箱 OTP + 密码路径, so that 非 SRP 账号也可登录。
5. As an OpenList 管理员(passkey 账号), I want 得到明确的「v1 不支持 passkey 登录」提示, so that 知道改用其它方式而非报错迷雾。
6. As an OpenList 管理员, I want 自定义 endpoint(默认 `https://api.ente.com`), so that 自托管 museum 也能用。
7. As an OpenList 管理员, I want 凭证一键复制且字段名对齐 Worker 驱动配置, so that 不做手工转换。
8. As an OpenList 管理员, I want 密码错误 / 验证码错误 / 429 限流 / endpoint 不可达都得到可读错误, so that 知道下一步怎么办。
9. As a 用户, I want 密码与派生密钥不离开浏览器(不发往 APIPages 后端、不持久化), so that 凭证安全面与 ente 官方 web 客户端一致。
10. As a 用户, I want 登录界面多语言可用(对齐站点 11 个 locale), so that 与其余页面一致。
11. As an OpenList 管理员, I want 页面提示 token 保活语义(365 天未使用才过期,由 Worker 驱动定期使用维持), so that 理解凭证寿命。
12. As an OpenList 管理员, I want README 驱动列表包含 Ente, so that 功能可被发现。

## Implementation Decisions

- **纯前端 crypto,零后端路由**:浏览器直连 museum(调研 §1 CORS);同时规避公共部署共享出口 IP 的登录族 10 req/min 限流(浏览器直连按用户自身 IP 计数,调研 §8)与后端 argon2 内存不可行。`src/index.ts` 不加任何 ente 路由。
- **依赖选型(MIT/公有领域,拒绝 AGPL 源码)**:argon2id 用 WASM 库(hash-wasm;纯 JS 在 256MB 参数下太慢),blake2b(keyed/personalization)用 @noble/hashes,secretbox/sealed-box 用 tweetnacl;SRP-4096 用 TS BigInt 自实现(SRP-6a、SHA-256、K=H(S)、group 左填充,对齐 ente server 实际运行的 ente/go-srp 语义,调研 §9)。ente 官方 `ente-prelogin-wasm` 为 workspace 私有包不可引用;ente monorepo 是 AGPL-3.0,**不复制其代码或 WASM 产物**,仅以协议事实与官方测试向量做互操作。
- **登录编排**(细节以 `.scratch/ente-login/research/ente-login.md` 为准):
  1. `GET users/srp/attributes?email=`;404 或 `isEmailMFAEnabled` → email OTP 路径(`users/ott` + `users/verify-email`,验证后仍需密码派生 KEK 解密)
  2. KEK = argon2id(password, kekSalt, opsLimit, memLimit, p=1, 32B);loginKey = blake2b keyed subkey(`loginctx`, id=1)前 16 字节
  3. SRP:identity=srpUserID 字节、salt=b64dec(srpSalt)、password=loginKey;srpA 须 512 字节;verify-session 响应必须验证 srpM2
  4. 响应含 `twoFactorSessionID` 且 token 为空 → `POST users/two-factor/verify`
  5. 解密链:masterKey←KEK、secretKey←masterKey、token←sealedbox(publicKey, secretKey)
  6. argon2 在 Web Worker 中执行(KDF 期间 UI 不冻结;大 memLimit 账号在低内存浏览器可能失败,需可读错误)
- **请求头**:`Content-Type: application/json` + `X-Client-Package: io.ente.photos`。
- **输出格式**:token 原样(base64url 字符串);`master_key`/`secret_key` 输出 base64 std(全链本就 base64,零转换;Worker 驱动接受 hex/base64)。附 Worker `ente` 驱动其余字段(`endpoint`、`show_hidden`)填法提示。
- **前端接入**:`frontend/src/lib/drivers.ts` DRIVERS 增加 ente 项;TokenPage 为 ente 增加非 OAuth 交互模式(表单 → 可选二次验证步 → 结果区);结果用既有 `CopyableField`;不适用「官方参数」开关体系;i18n key 补进 11 个 locale(未翻译语言回退 en-US)。
- **错误映射**:401(密码/验证码错)、404(账号不存在或无 SRP,视语境)、429(限流,稍后再试)、网络错误(endpoint 不可达)、KDF 内存不足。

## Testing Decisions

- 只测外部行为;测试零外部依赖(仓库前端无测试框架,不为 ente 引入);Node 内置 `node:test` 直接跑 TS 逻辑模块(模块保持 Node 可导入,DOM 依赖隔离在 UI 层)。
- crypto 层固定向量:SRP/KEK/loginKey 用 ente 官方公开测试数据交叉生成的向量;secretbox/sealedbox 用 tweetnacl 向量 + keyAttributes 形状解析测试。防移植漂移是第一目标。
- 登录编排:client 的 fetch 以构造参数注入,假 fetch 断言端点序列、payload 字段、2FA/OTP 分支、错误映射;不 mock crypto。
- 真实 museum 冒烟:env-gated 手动脚本,不进 CI。
- 零后端改动 → 无后端测试。

## Out of Scope

- passkey 登录(跳转 accounts.ente.io WebAuthn + 轮询 get-token;留作后续 ticket,先给明确不支持提示)
- OpenList-Worker 侧任何改动(ente 驱动本体在 Worker 仓库的 ente-driver change)
- 恢复密钥(recovery key)登录、注册、改密、删除账号
- 凭证刷新接口(token 无 TTL,由 Worker 驱动定期使用保活;失效后重跑本页)
- 密码保护分享相册的 argon2 派生(Worker 侧已裁决不支持)

## Further Notes

- 完整调研(端点、字段、KDF、限流、许可证约束,带 ente 源码行号):`.scratch/ente-login/research/ente-login.md`
- 上游参照:ente 官方 web 端浏览器登录先例(`../ente/web/packages/accounts/`,仅参照不复制);SRP 语义 = ente server 实际运行的 `github.com/ente/go-srp`(MIT)
- 跨仓库背景:OpenList-Worker 的 `openspec/changes/ente-driver`(其 ADR-0002 把登录外置到本仓库)
