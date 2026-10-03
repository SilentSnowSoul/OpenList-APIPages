/**
 * Ente 浏览器端 crypto 层：argon2id KEK、blake2b loginKey、SRP-6a 4096、keyAttributes 解密链。
 * 语义对齐 ente server 实际运行的 `github.com/ente/go-srp`（MIT；与 kong/go-srp 在哈希填充上不同，见 SrpSession.computeM1 注释）。
 * 无 DOM 依赖，Node 可导入；WASM 加载由 hash-wasm 自身处理。
 */
import { argon2id } from 'hash-wasm'
import { blake2b } from '@noble/hashes/blake2b'
import nacl from 'tweetnacl'
import { sha256 } from '@noble/hashes/sha256'

const encoder = new TextEncoder()

function b64decode(s: string): Uint8Array {
  const bin = atob(s)
  return Uint8Array.from(bin, (c: string) => c.charCodeAt(0))
}

function b64encode(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

/** KEK = argon2id(password, kekSalt, time=opsLimit, memory=memLimit/1024 KiB, p=1, 32B) */
export async function deriveKEK(
  password: string,
  kekSaltB64: string,
  opsLimit: number,
  memLimit: number,
): Promise<Uint8Array> {
  if (memLimit < 1024 || opsLimit < 1) throw new Error('invalid KDF limits')
  return argon2id({
    password,
    salt: b64decode(kekSaltB64),
    parallelism: 1,
    iterations: opsLimit,
    memorySize: Math.floor(memLimit / 1024),
    hashLength: 32,
    outputType: 'binary',
  })
}

/** loginKey = blake2b(key=KEK, salt=LE64(1) 零填充 16B, personal="loginctx" 零填充 16B) 前 16 字节 */
export function deriveLoginKey(kek: Uint8Array): Uint8Array {
  const salt = new Uint8Array(16)
  new DataView(salt.buffer).setBigUint64(0, 1n, true)
  const personal = new Uint8Array(16)
  personal.set(encoder.encode('loginctx'))
  const subkey = blake2b(new Uint8Array(0), { dkLen: 32, key: kek, salt, personalization: personal })
  return subkey.slice(0, 16)
}

// ---- SRP-6a / group 4096 / SHA-256，语义对齐 ente/go-srp ----

// RFC 3526 MODP group 4096
const N_HEX =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
  '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
  '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
  '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
  '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
  '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' +
  'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
  'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' +
  'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' +
  '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7' +
  '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8' +
  'DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
  '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9' +
  '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF'

const N = BigInt('0x' + N_HEX)
const G = 5n
const KEY_SIZE = 512 // 4096-bit group

function concat(...inputs: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(inputs.reduce((n, i) => n + i.length, 0))
  let offset = 0
  for (const input of inputs) {
    out.set(input, offset)
    offset += input.length
  }
  return out
}

function sha256Bytes(...inputs: Uint8Array[]): Uint8Array {
  return sha256(concat(...inputs))
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

function bigIntToBytes(n: bigint): Uint8Array {
  const h = n.toString(16)
  return hexToBytes(h.length % 2 ? '0' + h : h)
}

function padToN(n: bigint): Uint8Array {
  const bytes = bigIntToBytes(n)
  if (bytes.length > KEY_SIZE) throw new Error('value exceeds group size')
  return concat(new Uint8Array(KEY_SIZE - bytes.length), bytes)
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  const hex = bytesToHex(bytes)
  return BigInt('0x' + (hex === '' ? '0' : hex))
}

// JS BigInt 幂：base 可能为负，先归一化到 [0, mod)
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let b = ((base % mod) + mod) % mod
  let result = 1n
  let e = exp
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod
    b = (b * b) % mod
    e >>= 1n
  }
  return result
}

// k = H(pad(N) || pad(g))，对齐 go-srp getMultiplier
const MULTIPLIER = BigInt('0x' + bytesToHex(sha256Bytes(padToN(N), padToN(G))))

export interface KeyAttributes {
  kekSalt: string
  encryptedKey: string
  keyDecryptionNonce: string
  publicKey: string
  encryptedSecretKey: string
  secretKeyDecryptionNonce: string
  memLimit: number
  opsLimit: number
}

/** x = H(salt || H(identity || ':' || password)) */
function computeX(salt: Uint8Array, identity: Uint8Array, password: Uint8Array): bigint {
  return bytesToBigInt(sha256Bytes(salt, sha256Bytes(identity, encoder.encode(':'), password)))
}

/** SRP-6a 4096 客户端会话。identity=srpUserID 字节、salt=b64dec(srpSalt)、password 输入=loginKey */
export class SrpSession {
  private readonly a: bigint
  private readonly x: bigint
  private readonly A: bigint
  private M1: Uint8Array | null = null
  private M2: Uint8Array | null = null

  constructor(identity: Uint8Array, salt: Uint8Array, password: Uint8Array, secret1?: Uint8Array) {
    this.a = bytesToBigInt(secret1 ?? crypto.getRandomValues(new Uint8Array(32)))
    this.x = computeX(salt, identity, password)
    this.A = modPow(G, this.a, N)
  }

  /** 512 字节 srpA，服务端强制校验长度 */
  computeA(): Uint8Array {
    return padToN(this.A)
  }

  /**
   * 由服务端 srpB 计算 M1（并缓存 M2 供 verifyM2）。
   *
   * 哈希输入全部使用按 group 大小（512 字节）填充的表示，与 ente/go-srp
   *（ente server 实际运行的 fork）的 getu/getM1/getM2 语义一致：
   *   u  = H(pad(A) || pad(B))
   *   M1 = H(pad(A) || pad(B) || pad(S))
   *   M2 = H(pad(A) || M1 || K)
   * 注意 kong/go-srp 哈希最小字节表示，A 有前导零字节（约 1/256 登录）时
   * 与服务端分歧 → verify-session 401。
   */
  computeM1(srpB: Uint8Array): Uint8Array {
    const B = bytesToBigInt(srpB)
    if (B <= 0n || B >= N) throw new Error('invalid server-supplied B')
    // 与发送的 srpA 完全一致（ente server 强制 512 字节）
    const ABytes = padToN(this.A)
    const BBytes = padToN(B)
    const u = bytesToBigInt(sha256Bytes(ABytes, BBytes))
    // S = (B - k*g^x)^(a + u*x) mod N
    const gx = modPow(G, this.x, N)
    const base = B - (MULTIPLIER * gx) % N
    const S = modPow(base, this.a + u * this.x, N)
    const SBytes = padToN(S)
    const K = sha256Bytes(SBytes)
    this.M1 = sha256Bytes(ABytes, BBytes, SBytes)
    this.M2 = sha256Bytes(ABytes, this.M1, K)
    return this.M1
  }

  /** 校验服务端返回的 srpM2（常数时间比较） */
  verifyM2(srpM2: Uint8Array): boolean {
    if (!this.M2) throw new Error('computeM1 first')
    if (srpM2.length !== this.M2.length) return false
    let diff = 0
    for (let i = 0; i < srpM2.length; i++) diff |= this.M2[i] ^ srpM2[i]
    return diff === 0
  }
}

/** masterKey/secretKey 解密链（密码错误时抛可读错误） */
export function openKeyAttributes(
  keyAttributes: KeyAttributes,
  kek: Uint8Array,
): { masterKey: Uint8Array; secretKey: Uint8Array } {
  const masterKey = nacl.secretbox.open(
    b64decode(keyAttributes.encryptedKey),
    b64decode(keyAttributes.keyDecryptionNonce),
    kek,
  )
  if (!masterKey) throw new Error('key decryption failed (wrong password?)')
  const secretKey = nacl.secretbox.open(
    b64decode(keyAttributes.encryptedSecretKey),
    b64decode(keyAttributes.secretKeyDecryptionNonce),
    masterKey,
  )
  if (!secretKey) throw new Error('secret key decryption failed')
  return { masterKey, secretKey }
}

/** token = sealedbox_open(encryptedToken, publicKey, secretKey) */
export function openToken(
  encryptedTokenB64: string,
  publicKeyB64: string,
  secretKey: Uint8Array,
): Uint8Array {
  const ciphertext = b64decode(encryptedTokenB64)
  if (ciphertext.length < 48) throw new Error('invalid sealed token')
  const ephemeralPk = ciphertext.slice(0, 32)
  const sealed = ciphertext.slice(32)
  const nonce = blake2b(concat(ephemeralPk, b64decode(publicKeyB64)), { dkLen: 24 })
  const token = nacl.box.open(sealed, nonce, ephemeralPk, secretKey)
  if (!token) throw new Error('token unsealing failed')
  return token
}

export { b64decode, b64encode }
