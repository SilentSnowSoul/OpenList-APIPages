/**
 * ente client 单测：注入假 fetch，断言 URL/payload/分支/错误映射；不 mock crypto。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EnteClient,
  EnteApiError,
  SrpNotRegistered,
  parseAuthResponse,
  type FetchLike,
  type FetchResponse,
} from './client.ts'

function jsonResponse(status: number, body: unknown): FetchResponse {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
    text: async () => JSON.stringify(body),
  }
}

/** 记录请求并按路径返回预设响应 */
function fakeFetch(
  routes: Record<string, (url: string, body: unknown) => FetchResponse | Promise<FetchResponse>>,
  log: Array<{ url: string; method: string; body?: string }> = [],
): FetchLike {
  return async (url, init) => {
    log.push({ url, method: init.method, body: init.body })
    const path = url.replace('https://api.ente.com/', '').split('?')[0]
    const handler = routes[path]
    if (!handler) return jsonResponse(404, { error: 'no route ' + path })
    return handler(url, init.body ? JSON.parse(init.body) : undefined)
  }
}

test('默认 fetchImpl 不依赖调用接收者（浏览器 this.fetchImpl(...) 不抛 Illegal invocation）', async () => {
  // 复现浏览器语义：原生 fetch 要求 this=globalThis，接收者不对即抛 TypeError。
  const realFetch = globalThis.fetch
  const calls: string[] = []
  globalThis.fetch = function (this: unknown, ...a: unknown[]) {
    if (this !== globalThis) throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation")
    calls.push(String(a[0]))
    return Promise.resolve(jsonResponse(404, { error: 'ACCOUNT_NOT_FOUND' }))
  } as typeof fetch
  try {
    const client = new EnteClient('https://api.ente.com')
    // request() 内部正是以方法形式调用：this.fetchImpl(...)
    await assert.rejects(client.getSrpAttributes('a@b.c'), SrpNotRegistered)
    assert.equal(calls.length, 1)
  } finally {
    globalThis.fetch = realFetch
  }
})

test('getSrpAttributes：URL、query、headers', async () => {
  const log: Array<{ url: string; method: string; body?: string }> = []
  const client = new EnteClient(
    'https://api.ente.com/',
    fakeFetch(
      {
        'users/srp/attributes': () =>
          jsonResponse(200, {
            attributes: { srpUserID: '42', srpSalt: 'cw==', kekSalt: 'aw==', memLimit: 268435456, opsLimit: 16, isEmailMFAEnabled: false },
          }),
      },
      log,
    ),
  )
  const attrs = await client.getSrpAttributes('a@b.c')
  assert.equal(attrs.srpUserID, '42')
  assert.equal(attrs.memLimit, 268435456)
  assert.equal(log[0].url, 'https://api.ente.com/users/srp/attributes?email=a%40b.c')
  assert.equal(log[0].method, 'GET')
})

test('getSrpAttributes 404 → SrpNotRegistered（OTP 路径信号）', async () => {
  const client = new EnteClient(
    undefined,
    fakeFetch({ 'users/srp/attributes': () => jsonResponse(404, { error: 'no account' }) }),
  )
  await assert.rejects(() => client.getSrpAttributes('a@b.c'), SrpNotRegistered)
})

test('createSrpSession/verifySrpSession：payload 与成功解析', async () => {
  const log: Array<{ url: string; method: string; body?: string }> = []
  const keyAttributes = {
    kekSalt: 'aw==', encryptedKey: 'eA==', keyDecryptionNonce: 'n==',
    publicKey: 'pQ==', encryptedSecretKey: 'es==', secretKeyDecryptionNonce: 'n2==',
    memLimit: 1, opsLimit: 1,
  }
  const client = new EnteClient(
    undefined,
    fakeFetch(
      {
        'users/srp/create-session': () => jsonResponse(200, { sessionID: 'sid', srpB: 'Qg==' }),
        'users/srp/verify-session': () =>
          jsonResponse(200, { keyAttributes, encryptedToken: 'dG9rZW4=', srpM2: 'bTI=' }),
      },
      log,
    ),
  )
  const { sessionID, srpB } = await client.createSrpSession('42', 'QUFB')
  assert.deepEqual({ sessionID, srpB }, { sessionID: 'sid', srpB: 'Qg==' })
  assert.equal(log[0].body, JSON.stringify({ srpUserID: '42', srpA: 'QUFB' }))
  const result = await client.verifySrpSession('42', 'sid', 'bTE=')
  assert.equal(result.status, 'ok')
  if (result.status === 'ok') assert.equal(result.encryptedToken, 'dG9rZW4=')
})

test('SRP 401 → INVALID_CREDENTIALS', async () => {
  const client = new EnteClient(
    undefined,
    fakeFetch({ 'users/srp/verify-session': () => jsonResponse(401, { error: 'Invalid session' }) }),
  )
  await assert.rejects(
    () => client.verifySrpSession('42', 'sid', 'bTE='),
    (e: unknown) => e instanceof EnteApiError && e.kind === 'INVALID_CREDENTIALS' && e.serverMessage === 'Invalid session',
  )
})

test('verifySrpSession 2FA 分支透传 srpM2（进入 2FA 前先验证 M2）', async () => {
  const client = new EnteClient(
    undefined,
    fakeFetch({
      'users/srp/verify-session': () =>
        jsonResponse(200, { twoFactorSessionID: 'tf-sid', srpM2: 'bTI=', accountsUrl: 'https://accounts.ente.io' }),
    }),
  )
  const result = await client.verifySrpSession('42', 'sid', 'bTE=')
  assert.deepEqual(result, { status: '2fa_required', twoFactorSessionID: 'tf-sid', srpM2: 'bTI=' })
})

test('verifyTwoFactor 响应不含 srpM2（已由 verify-session 校验）', async () => {
  const client = new EnteClient(
    undefined,
    fakeFetch({
      'users/two-factor/verify': () =>
        jsonResponse(200, { keyAttributes: {}, encryptedToken: 'dA==', id: 1 }),
    }),
  )
  const result = await client.verifyTwoFactor('tf-sid', '654321')
  assert.equal(result.status, 'ok')
  assert.equal(result.srpM2, '')
})

test('429 → RATE_LIMITED', async () => {
  const client = new EnteClient(
    undefined,
    fakeFetch({ 'users/ott': () => jsonResponse(429, { error: 'Rate limit breached, try later' }) }),
  )
  await assert.rejects(
    () => client.sendOtt('a@b.c'),
    (e: unknown) => e instanceof EnteApiError && e.kind === 'RATE_LIMITED',
  )
})

test('fetch 抛异常 → NETWORK（endpoint 不可达）', async () => {
  const client = new EnteClient(undefined, (async () => { throw new TypeError('failed') }) as FetchLike)
  await assert.rejects(
    () => client.getSrpAttributes('a@b.c'),
    (e: unknown) => e instanceof EnteApiError && e.kind === 'NETWORK',
  )
})

test('verify-email / two-factor：payload 与成功解析', async () => {
  const log: Array<{ url: string; method: string; body?: string }> = []
  const client = new EnteClient(
    undefined,
    fakeFetch(
      {
        'users/verify-email': () => jsonResponse(200, { keyAttributes: {}, encryptedToken: 'dA==', srpM2: '' }),
        'users/two-factor/verify': () => jsonResponse(200, { keyAttributes: {}, encryptedToken: 'dA==' }),
      },
      log,
    ),
  )
  await client.verifyEmail('a@b.c', '123456')
  await client.verifyTwoFactor('tf-sid', '654321')
  assert.equal(log[0].body, JSON.stringify({ email: 'a@b.c', ott: '123456' }))
  assert.equal(log[1].body, JSON.stringify({ sessionID: 'tf-sid', code: '654321' }))
})

test('parseAuthResponse：TOTP 分支保留 srpM2 与 passkey 拒绝', () => {
  // srp.go:224 在 2FA 分支同样返回 srpM2，必须透传以便进入 2FA 前验证
  const twoFactor = parseAuthResponse({ twoFactorSessionID: 'tf', srpM2: 'bTI=', ID: 1 })
  assert.deepEqual(twoFactor, { status: '2fa_required', twoFactorSessionID: 'tf', srpM2: 'bTI=' })
  // 服务端未返回 srpM2 时归一化为空串，由调用方判定为校验失败
  assert.equal(parseAuthResponse({ twoFactorSessionID: 'tf' }).srpM2, '')
  assert.throws(
    () => parseAuthResponse({ passkeySessionID: 'pk' }),
    (e: unknown) => e instanceof EnteApiError && e.kind === 'PASSKEY_UNSUPPORTED',
  )
  // 空 token + passkey（服务端 v1 形状）同样拒绝
  assert.throws(
    () => parseAuthResponse({ passkeySessionID: 'pk', token: '' }),
    /PASSKEY_UNSUPPORTED|^EnteApiError/,
  )
})

test('parseAuthResponse：twoFactorSessionIDV2 走 TOTP（passkey+TOTP 账号）', () => {
  // userauth.go:672-673：passkey 与 TOTP 同时开启时只回 V2 字段；
  // V2 与 V1 同为 two_factor_sessions 会话，two-factor/verify 按 sessionID 查库，两者等价。
  // 注意 TwoFactorSessionID 无 omitempty（ente/user.go:58），线上 V2 响应真的带 "twoFactorSessionID": ""，
  // 所以这里必须带上空串 V1 才能复现真实报文（用 ?? 会漏掉这个分支）。
  const v2 = parseAuthResponse({
    passkeySessionID: 'pk',
    twoFactorSessionID: '',
    twoFactorSessionIDV2: 'tf-v2',
    accountsUrl: 'https://accounts.ente.io',
  })
  assert.deepEqual(v2, { status: '2fa_required', twoFactorSessionID: 'tf-v2', srpM2: '' })
  // 仅 passkey（V1/V2 都为空）仍拒绝
  assert.throws(
    () => parseAuthResponse({ passkeySessionID: 'pk', accountsUrl: 'https://accounts.ente.io' }),
    (e: unknown) => e instanceof EnteApiError && e.kind === 'PASSKEY_UNSUPPORTED',
  )
})
