# 01: Ente crypto 层(KEK/loginKey/SRP/解密)

**Status:** ready-for-agent
**Type:** task

## Question

浏览器端 ente crypto 模块:argon2id KEK、blake2b `loginctx` subkey、SRP-6a 4096、keyAttributes 解密链。参数与语义见 `.scratch/ente-login/research/ente-login.md` §4/§9。

## Notes

- 依赖(MIT/公有领域):hash-wasm(argon2id,WASM)、@noble/hashes(blake2b keyed/personalization)、tweetnacl(secretbox/sealed box open)。禁止复制 ente(AGPL-3.0)代码或 vendored WASM。
- argon2id 参数:password、b64dec(kekSalt)、time=opsLimit、memory=memLimit/1024(KiB)、parallelism=1、32B 输出。
- loginKey = blake2b keyed subkey(context=`loginctx` 右零填充至 16B personalization、salt=LE64(1) 零填充至 16B、32B 输出)的前 16 字节。
- SRP:group 4096、SHA-256、K=H(S)、大整数按 group 大小左填充、identity=srpUserID 字节、salt=b64dec(srpSalt)、password 输入=loginKey;srpA 必须输出 512 字节;须实现 verifyM2。
- 解密链:masterKey=secretbox_open(encryptedKey, keyDecryptionNonce, KEK);secretKey=secretbox_open(encryptedSecretKey, secretKeyDecryptionNonce, masterKey);token=sealedbox_open(encryptedToken, publicKey, secretKey)。b64 一律 base64 std;token 为 base64url 原样字符串。
- 模块保持 Node 可导入(无 DOM 依赖);argon2 的 Web Worker 封装放 UI 层(ticket 03)。
- 测试:Node 内置 `node:test`,零测试依赖;向量与 ente 官方公开测试数据(`../ente/web/packages/wasm/prelogin/tests/auth.test.ts`、`crypto.test.ts`)交叉生成,防移植漂移。

## Acceptance

- crypto 模块导出:deriveKEK、deriveLoginKey、SrpSession(publicA/computeM1/verifyM2)、openKeyAttributes(→masterKey/secretKey)、openToken。
- 固定向量单测全绿(KEK/loginKey/SRP M1/M2/secretbox/sealedbox)。
