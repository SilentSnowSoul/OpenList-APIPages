/**
 * ente 登录响应 → Worker 驱动凭证 的组合层。
 *
 * UI（components/EnteLoginForm.tsx）与冒烟脚本（scripts/test-ente-login.mjs）共用这里的实现，
 * 避免「凭证格式」与「srpM2 校验」这两处关键逻辑出现两份会各自漂移的副本。
 * 只做组合，不含 DOM/React 依赖，Node 可直接导入。
 */
import type { AuthSuccess, AuthResult } from './client'
// 显式 .ts 扩展名：本模块需保持 Node 可直接导入（node:test / 冒烟脚本），见 tsconfig allowImportingTsExtensions
import { SrpSession, b64decode, b64encode, openKeyAttributes, openToken } from './crypto.ts'

/** 可直接粘贴进 OpenList-Worker `ente` 驱动的三个字段 */
export interface EnteCredentials {
  /** base64url（解密出的 token 是原始字节，按 ente cli TokenStr 的 base64.URLEncoding 编码） */
  token: string
  /** base64 std */
  masterKey: string
  /** base64 std */
  secretKey: string
}

/**
 * SRP verify-session 的响应必须携带并可验证 srpM2（2FA 分支同样返回，见 client.ts）。
 * /users/two-factor/verify 的响应不含 srpM2，所以必须在进入 2FA 之前调用本函数。
 */
export function verifySrpM2(auth: AuthResult, session: SrpSession): void {
  if (!auth.srpM2) throw new Error('server did not return srpM2')
  if (!session.verifyM2(b64decode(auth.srpM2))) throw new Error('srpM2 verification failed')
}

/** 解密链：masterKey←KEK、secretKey←masterKey、token←sealedbox(publicKey, secretKey) */
export function openCredentials(auth: AuthSuccess, kek: Uint8Array): EnteCredentials {
  const { masterKey, secretKey } = openKeyAttributes(auth.keyAttributes, kek)
  const tokenBytes = openToken(auth.encryptedToken, auth.keyAttributes.publicKey, secretKey)
  // token 是任意原始字节（非文本），须 base64url 编码后才能作为 X-Auth-Token 使用，
  // 对齐 ente cli 的 model.AccSecretInfo.TokenStr（base64.URLEncoding）
  const token = b64encode(tokenBytes).replace(/\+/g, '-').replace(/\//g, '_')
  return { token, masterKey: b64encode(masterKey), secretKey: b64encode(secretKey) }
}
