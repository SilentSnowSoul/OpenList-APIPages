/**
 * ente museum HTTP client：登录族端点、响应解析、错误映射。浏览器直连，fetch 注入便于测试。
 * 端点与字段见 .scratch/ente-login/research/ente-login.md §3/§5/§6/§8。
 */
import type { KeyAttributes } from './crypto'

export interface FetchResponse {
  status: number
  ok: boolean
  json: () => Promise<unknown>
  text: () => Promise<string>
}

export interface FetchLike {
  (url: string, init: { method: string; headers: Record<string, string>; body?: string }): Promise<FetchResponse>
}

export type EnteErrorKind =
  | 'INVALID_CREDENTIALS' // 401 凭证/验证码错误
  | 'ACCOUNT_NOT_FOUND' // 404 账号不存在
  | 'RATE_LIMITED' // 429 限流
  | 'NETWORK' // endpoint 不可达
  | 'PASSKEY_UNSUPPORTED' // passkey 账号
  | 'SERVER' // 其他服务端错误

export class EnteApiError extends Error {
  readonly kind: EnteErrorKind
  readonly status: number
  readonly serverMessage: string

  constructor(kind: EnteErrorKind, status: number, serverMessage: string) {
    super(serverMessage || kind)
    this.name = 'EnteApiError'
    this.kind = kind
    this.status = status
    this.serverMessage = serverMessage
  }
}

export interface SrpAttributes {
  srpUserID: string
  srpSalt: string
  kekSalt: string
  memLimit: number
  opsLimit: number
  isEmailMFAEnabled: boolean
}

/** attributes 404 = 账号无 SRP verifier，走 email OTP 路径 */
export class SrpNotRegistered extends Error {
  constructor() {
    super('SRP not registered')
    this.name = 'SrpNotRegistered'
  }
}

export interface AuthSuccess {
  status: 'ok'
  keyAttributes: KeyAttributes
  encryptedToken: string
  srpM2: string
}

export interface AuthTwoFactorRequired {
  status: '2fa_required'
  twoFactorSessionID: string
  /**
   * verify-session 的 2FA 分支同样返回 srpM2：srp.go:224 在 onVerificationSuccess 之后无条件赋值，
   * 因此 M2 必须在进入 2FA 之前就验证（/users/two-factor/verify 的响应类型不含 srpM2）。
   */
  srpM2: string
}

export type AuthResult = AuthSuccess | AuthTwoFactorRequired

/** AuthorizationResponse 归一化：2FA/passkey 分支判空（§5：2FA 未完成时 token 为空） */
export function parseAuthResponse(resp: Record<string, unknown>): AuthResult {
  // twoFactorSessionIDV2：passkey 与 TOTP 同时开启时服务端只回 V2（userauth.go:672-673）。
  // 注意 TwoFactorSessionID 的 json tag 没有 omitempty（ente/user.go:58），V2 响应在线上真的
  // 带 "twoFactorSessionID": ""，所以必须用 || 而不是 ??（?? 不会在空串上回退）。
  // V1/V2 都是 two_factor_sessions 里的会话，/users/two-factor/verify 按 sessionID 查库，
  // 两者等价；本页面不支持 passkey，有 V2 即走 TOTP。
  const twoFactorSessionID = resp.twoFactorSessionID || resp.twoFactorSessionIDV2
  if (twoFactorSessionID) {
    return {
      status: '2fa_required',
      twoFactorSessionID: String(twoFactorSessionID),
      srpM2: String(resp.srpM2 ?? ''),
    }
  }
  if (resp.passkeySessionID) {
    throw new EnteApiError('PASSKEY_UNSUPPORTED', 0, String(resp.passkeySessionID))
  }
  if (!resp.keyAttributes || !resp.encryptedToken) {
    throw new EnteApiError('SERVER', 0, 'incomplete authorization response')
  }
  return {
    status: 'ok',
    keyAttributes: resp.keyAttributes as KeyAttributes,
    encryptedToken: String(resp.encryptedToken),
    srpM2: String(resp.srpM2 ?? ''),
  }
}

export const DEFAULT_ENTE_ENDPOINT = 'https://api.ente.com'

export class EnteClient {
  private readonly base: string
  private readonly fetchImpl: FetchLike

  // fetch 必须绑定接收者：浏览器原生 fetch 要求 this=Window，
  // 以 this.fetchImpl(...) 方式调用未绑定的 fetch 会抛 Illegal invocation
  constructor(endpoint = DEFAULT_ENTE_ENDPOINT, fetchImpl: FetchLike = fetch.bind(globalThis) as FetchLike) {
    this.base = endpoint.replace(/\/+$/, '')
    this.fetchImpl = fetchImpl
  }

  private async request(method: string, path: string, body?: unknown): Promise<Record<string, unknown>> {
    let response: FetchResponse
    try {
      response = await this.fetchImpl(`${this.base}/${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Client-Package': 'io.ente.photos',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
    } catch {
      throw new EnteApiError('NETWORK', 0, '')
    }
    if (response.ok) return (await response.json()) as Record<string, unknown>
    let serverMessage = ''
    try {
      const parsed = await response.json()
      if (parsed && typeof parsed === 'object' && 'error' in parsed) {
        serverMessage = String((parsed as { error: unknown }).error ?? '')
      }
    } catch {
      serverMessage = await response.text().catch(() => '')
    }
    const kind: EnteErrorKind =
      response.status === 401
        ? 'INVALID_CREDENTIALS'
        : response.status === 404
          ? 'ACCOUNT_NOT_FOUND'
          : response.status === 429
            ? 'RATE_LIMITED'
            : 'SERVER'
    throw new EnteApiError(kind, response.status, serverMessage)
  }

  async getSrpAttributes(email: string): Promise<SrpAttributes> {
    try {
      const resp = await this.request('GET', `users/srp/attributes?email=${encodeURIComponent(email)}`)
      const attrs = resp.attributes
      if (!attrs || typeof attrs !== 'object') throw new EnteApiError('SERVER', 0, 'malformed srp attributes')
      return attrs as SrpAttributes
    } catch (e) {
      if (e instanceof EnteApiError && e.kind === 'ACCOUNT_NOT_FOUND') throw new SrpNotRegistered()
      throw e
    }
  }

  async createSrpSession(srpUserID: string, srpA: string): Promise<{ sessionID: string; srpB: string }> {
    const resp = await this.request('POST', 'users/srp/create-session', { srpUserID, srpA })
    if (!resp.sessionID || !resp.srpB) throw new EnteApiError('SERVER', 0, 'malformed srp session')
    return { sessionID: String(resp.sessionID), srpB: String(resp.srpB) }
  }

  async verifySrpSession(
    srpUserID: string,
    sessionID: string,
    srpM1: string,
  ): Promise<AuthResult> {
    return parseAuthResponse(await this.request('POST', 'users/srp/verify-session', { srpUserID, sessionID, srpM1 }))
  }

  async sendOtt(email: string): Promise<void> {
    await this.request('POST', 'users/ott', { email, purpose: 'login' })
  }

  async verifyEmail(email: string, ott: string): Promise<AuthResult> {
    return parseAuthResponse(await this.request('POST', 'users/verify-email', { email, ott }))
  }

  async verifyTwoFactor(sessionID: string, code: string): Promise<AuthResult> {
    return parseAuthResponse(
      await this.request('POST', 'users/two-factor/verify', { sessionID, code }),
    )
  }
}
