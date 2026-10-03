/**
 * 登录组合层测试：凭证输出格式（spec: Output formats）与 srpM2 强制校验。
 * 这两个行为此前只存在于 UI 组件里、没有测试，且被冒烟脚本复制了一份。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { blake2b } from '@noble/hashes/blake2b'
import nacl from 'tweetnacl'
import { SrpSession, b64decode, b64encode, type KeyAttributes } from './crypto.ts'
import { openCredentials, verifySrpM2 } from './login.ts'
import type { AuthResult, AuthSuccess } from './client.ts'

const hex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'))
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex')

function concat(...xs: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(xs.reduce((n, x) => n + x.length, 0))
  let o = 0
  for (const x of xs) { out.set(x, o); o += x.length }
  return out
}

/** libsodium crypto_box_seal：ephPk || box(msg, blake2b24(ephPk||recipientPk)) */
function sealBox(msg: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const eph = nacl.box.keyPair()
  const nonce = blake2b(concat(eph.publicKey, publicKey), { dkLen: 24 })
  return concat(eph.publicKey, nacl.box(msg, nonce, publicKey, eph.secretKey))
}

// crypto.test.ts 同源 PyNaCl 向量：KEK → masterKey 0x41.. / secretKey 0x61..
const KEK = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
const ATTRS: KeyAttributes = {
  kekSalt: '',
  encryptedKey: '3FtrR2K2oUVk17iIwwKIq20Qr39N1f9DzHxd2DbAx3wJEr04oesq0mS9r9kh2put',
  keyDecryptionNonce: 'DbrJhTP9j51Yes3LgWE0jOeh8vPAe7dG',
  publicKey: '',
  encryptedSecretKey: 'u7JM4ADzcgWCL48xVPt3XMRi3gTjzqhOrnRYEjxKcg5i66heFKTWqSMA75LLP9Tj',
  secretKeyDecryptionNonce: '/3ZGgyUNkQHnxIEZvhh7ZX3D2snrCNjW',
  memLimit: 0,
  opsLimit: 0,
}

test('openCredentials：token 为 base64url、master_key/secret_key 为 base64 std', () => {
  const secretKey = hex('6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80')
  const publicKey = nacl.box.keyPair.fromSecretKey(secretKey).publicKey
  // 覆盖 0/255 边界：解密出的 token 是原始字节，须按 ente cli 编码为 base64url
  const tokenPlain = crypto.getRandomValues(new Uint8Array(32))
  const attrs: KeyAttributes = { ...ATTRS, publicKey: b64encode(publicKey) }

  const creds = openCredentials(
    { status: 'ok', keyAttributes: attrs, encryptedToken: b64encode(sealBox(tokenPlain, publicKey)), srpM2: '' },
    KEK,
  )

  assert.equal(
    creds.token,
    Buffer.from(tokenPlain).toString('base64').replaceAll('+', '-').replaceAll('/', '_'),
  )
  assert.equal(creds.masterKey, b64encode(hex('4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60')))
  assert.equal(creds.secretKey, b64encode(secretKey))
  // base64 std（含 +/ 与 = 填充），不是 base64url
  assert.match(creds.masterKey, /^[A-Za-z0-9+/]+={0,2}$/)
})

test('openCredentials：错误 KEK 抛可读错误', () => {
  const auth = { status: 'ok', keyAttributes: ATTRS, encryptedToken: 'AAAA', srpM2: '' } as AuthSuccess
  assert.throws(() => openCredentials(auth, hex('00'.repeat(32))), /key decryption failed/)
})

// go-srp golden（crypto.test.ts 同源）
const SECRET1 = hex('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f')
const SRP_B = hex(
  'a8deec0c3842aeca2a5a575b981bbd28be8ca86e3cb7422433a0527bb530b911' +
    '5f46d88e8d0e5b9604e7aa17d43100345dc1f23b631a700d432aa088e202865b' +
    'c7b3b753a56124a85bd22a9f507ff92f6520371805a51c255d8a504f3cc910b5' +
    '68db01d15d367e31b84f33f71df7cb33dc3032d29e0fd278578411e1e8ddbab9' +
    '5a69cfe3c2dfc5a63373b90df412232136588530371c14fb32493ed48cf015a7' +
    '6be67cc1e77c19ef5a430e8ec6403996014d7b184d08cf0fad0274f6aa148793' +
    '1bb73d9a58357f866b3b021b56d22f1dfebb288bb631503e1f404bbca632bc72' +
    '389ef611b47fbc40960a917b65b5920d5a74871f02bd43a9c52a8316791cb77f' +
    '8233af3fe9f28f6456012bde4d3a5d15f65626f164f385271b7b18bb306ba657' +
    'a76f9dfd366eaa4afdfb82812e2ead0668d29d3f0125104460a18cf5c62ab5d3' +
    '38f0bc667b5a43c69034ab42d12df22d70bc5b218953babdebb318400b185866' +
    'c4658b30dfb7ce8059205c4163d325bbefd6d07db0f93252444fbb26b609114b' +
    'cf281335a25bdfc67a33f808ff49f81ffc410ce1a841b141ba2d823bd36a3b21' +
    'c3b5f3d9f6a3c8cf7993c530991de15d38bc4d6e0842648bfb6b710a7f7bb9ab' +
    '4f1e07c9dade1c789317f73f9c7e03ad795dd358addac44df9e1c498143577fe' +
    'a756c2da67ff0e18b2bffe4605e20056de155db2d1a428264c8a3d284ab1f3fb',
)
const SRP_M2 = '8584abf320a90a81b780b5b1bedf575829363a6d09365826862b25fb8111e32f'

function srpSession(): SrpSession {
  const session = new SrpSession(
    new TextEncoder().encode('alice'),
    new TextEncoder().encode('salty'),
    new TextEncoder().encode('password123'),
    SECRET1,
  )
  session.computeM1(SRP_B) // 缓存 M2
  return session
}

test('verifySrpM2：正确的 M2 通过（2FA 分支同样适用）', () => {
  const session = srpSession()
  const ok: AuthResult = { status: 'ok', keyAttributes: ATTRS, encryptedToken: 'x', srpM2: b64encode(hex(SRP_M2)) }
  assert.doesNotThrow(() => verifySrpM2(ok, session))
  const twoFactor: AuthResult = { status: '2fa_required', twoFactorSessionID: 'tf', srpM2: b64encode(hex(SRP_M2)) }
  assert.doesNotThrow(() => verifySrpM2(twoFactor, session))
})

test('verifySrpM2：错误或缺失的 M2 必须拒绝', () => {
  const bad = hex(SRP_M2)
  bad[0] ^= 1
  assert.throws(() => verifySrpM2({ status: '2fa_required', twoFactorSessionID: 'tf', srpM2: b64encode(bad) }, srpSession()), /srpM2 verification failed/)
  // 服务端不返回 srpM2 时必须拒绝，而不是跳过校验
  assert.throws(() => verifySrpM2({ status: '2fa_required', twoFactorSessionID: 'tf', srpM2: '' }, srpSession()), /did not return srpM2/)
})

test('openCredentials 往返：token 解码后与 sealed box 明文一致', () => {
  const secretKey = hex('6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80')
  const publicKey = nacl.box.keyPair.fromSecretKey(secretKey).publicKey
  const plain = crypto.getRandomValues(new Uint8Array(32))
  const creds = openCredentials(
    {
      status: 'ok',
      keyAttributes: { ...ATTRS, publicKey: b64encode(publicKey) },
      encryptedToken: b64encode(sealBox(plain, publicKey)),
      srpM2: '',
    },
    KEK,
  )
  assert.equal(Buffer.from(creds.token, 'base64').toString('hex'), toHex(plain))
  assert.equal(toHex(b64decode(creds.secretKey)), toHex(secretKey))
})
