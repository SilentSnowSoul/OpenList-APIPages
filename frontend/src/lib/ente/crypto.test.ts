/**
 * ente crypto 固定向量测试（node:test，零测试依赖）。
 * 向量由独立实现交叉生成：
 * - SRP/verifier：Go + github.com/ente/go-srp（ente server 实际运行的 fork，MIT）
 * - loginKey：Python hashlib blake2b
 * - KEK：OpenSSL ARGON2ID KDF
 * - secretbox：Python PyNaCl；sealed box：ente 官方公开测试向量
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  deriveKEK,
  deriveLoginKey,
  SrpSession,
  openKeyAttributes,
  openToken,
  b64decode,
  b64encode,
  type KeyAttributes,
} from './crypto.ts'

const hex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'))
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex')

// go-srp srp_test.go 同源参数：salt=salty identity=alice password=password123
const SRP_SALT = new TextEncoder().encode('salty')
const SRP_IDENTITY = new TextEncoder().encode('alice')
const SRP_PASSWORD = new TextEncoder().encode('password123')

// 固定客户端/服务端私钥（Go golden 生成器：0x10..0x2f / 0x80..0x61）
const SECRET1 = hex('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f')
const SRP_A =
  '059ebcbb8018d62831cdd54bf9440ac6025076238620752d50df950ddcaaca92' +
  '92644f7ad247d344037e25830f1ce3cf28c09d3c78bf7b9257fadc88a012aa85' +
  '6836cd73e4b7483a92cc1fb21e041742921faba84c63164c101a13e4a9fe2fdf' +
  '7db133ab494d33df43b16239d1cb312a6b3ecb03dc8bee748b499d8bcd04acf2' +
  '75e1adb85a7c0adb24b1b1624d6e47d3eaa7bc9afff6166e2e836f106894a5cc' +
  'd801370ea666d3bcacbf2e08db9bacb79becf32688b60e00d81cbc310f6b2cea' +
  '181271ad560752130142dc1bbee31a154ace0d4b7e67f1a7d83bb8b8fdaa0a10' +
  'a54a912199ad4b5ee36ffc88def8f2200e0dbd49379e5ac7f009c09599585c00' +
  '2b1775258266c849813e94d698a1c1457088afadfee80f4e3beb61a00c2e5c6c' +
  '6713e7ea958c2827d74a50d58dfec1cd7541a9cc1125e147ee59de350e2a3d34' +
  '269ef214871079c7adaaac5aa8044e8166e5d4031530338bddeaab7e62aa08df' +
  '08db2c3ff0ffc1b1e1e26df799c7bb20a826923faa509dd83a3bae98805ec6e3' +
  '56b9d1baed0e00a29da672c3bced8e519023daad80eec82dd6b870ce7081df84' +
  '9fc4e2da86ced283ba960a81b0bc2556d8ef417625530e43750f172f9ecde4f0' +
  '73e5026e98b52a49e61b56669c2c63834d5dd5eb66d0e000a7e74d1a957bd6ee' +
  '5df5c4f2e62c6527a661fc96fb08a9fd71061689657bbec1725ea1e35d1b358f'
const SRP_B =
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
  'a756c2da67ff0e18b2bffe4605e20056de155db2d1a428264c8a3d284ab1f3fb'
const SRP_M1 = '92ff25c8e4994ce464dac1cc461fbb6bf8e5f961c676263440cb175c98b5d32a'
const SRP_M2 = '8584abf320a90a81b780b5b1bedf575829363a6d09365826862b25fb8111e32f'

// A 有前导零字节（A < 2^4088，约 1/256 登录）的向量，由 Go + github.com/ente/go-srp
//（ente server 实际运行的 fork）生成。fork 的 getu/M1/M2 均哈希按 group 大小填充的
// A 与 B；若客户端哈希 bigIntToBytes(A)（最小字节表示，511 字节）而非发送的 512 字节
// srpA，u/M1/M2 全部与服务端分歧 → verify-session 401。
const SECRET1_LZ = hex('301930d0d7090d7d6512ef74644bf81bd7a699bd1ef1d30f5324ada022f24990')
const SRP_A_LZ =
  '00171444fe37c4aee97c567d1da27df71731522dd71644717f051b8899a8b747' +
  '071ee56f67c3c21a7db0176c1a476bbb176a5a86caf8b1f6c28ea7ab97762686' +
  'e62755efcfc362145fcae7eac5eaa824bf180b66adfda106b0661989696e5014' +
  '94b4a6dd6b2e30003241cef3322bb3db8ebbcb89ba16d54a321033d81cdb9dab' +
  '3fef4407a9e6384ded743f843164fd107a9bba9e9094ec176ed1d77b2724e53a' +
  '20e453a5f248186e4db0e880d3a46c4a494aaa10dde7ba245519e9d219455e62' +
  '69bc3bd34cb57ab03f63800496422a5d9bc7b8c40ad87467ab0441cdfd35247b' +
  '10b748cc72c144219ecf5b28211466b29be299ec69cfaa91c61875162328dfa4' +
  'e03beb3b6d8544b74224932ef854352efb70a122169ceb4c84c6a2c9968399e7' +
  'd5ed9c499cf9546b1a4001fc36a3d0c20371f3d145f84b3cbfe09e0f0a1c5f34' +
  'b5cd7cd57008eaa2589eb34e25d9064f9ae6610cc5b51b543d36a58b30eb687b' +
  '7ebf06d362fd684922379054793bbf2111c74a0a9f0a472d5040f33d0c6b65da' +
  '89139d7f6786521ba9e8f590b270fa83eadf4f2615cbaf3e3d06940507f7f238' +
  'de55f1a41fd288dfe529ef45833c549dfbcb9f75c85851745612f4e4045ab972' +
  '7c73476067cfb1f8e33f7dcdfb0432bf1539a83dbe4e0a25d3802b91234c501a' +
  'c3af5d38d5bb84b01e73018a6333c27ca7a6cf6e8d7327f2223b220eb6a0d95d'
const SRP_B_LZ =
  'f21b62cda459be546112648a94d745adb1f5309e1a0edd5c142b0e70c8887c16' +
  'd8ae27d762ff1955690b5f4dc28012d882a48672520dbec10796fdcb0899baa9' +
  '42cde8067d0147b4cf8fdd88fe2b1b119a82f479d26cd2eb9e5633588f283c5a' +
  '48196b7eaf815d77beb2a19543b46e3f6f0535f684b3d9c4bf5e1cdd7bc891b0' +
  'af4f2ea6d2804164d6c689cab0d78f74380a139b1646ced2e7199f8de280080f' +
  '8e53dac66d8da636dad3d428c870f8d56d8b078340b0d2a5f32defd2ccba03a7' +
  'd6d762733a836470dd759dd93832162dc0d680f093442d97364723331d59bc20' +
  '4bc98f4d3d224c46be23fe0a50bece095eabc8f602c2a9173a6ecff18d609fc5' +
  '5357b1780e92354eec9e77d3c3aeb5b4708bc9c35898b8f7967e00665eeab99e' +
  '8a1cc6956a2766730395df66dca128c3d49c66f1514031d6172b7897b5d93680' +
  'a54e73f7e6c0d807da86dc4f1e79f5aded9d57f02b55af44dbc18a46c368bb1c' +
  '87bf091e84db491023f94008b154a083f5a4ee79a92a0b5a6a13012f75a7648b' +
  'fba63fc8cbc02e2955f975701059bf2e21fe4efffb0e963aa39c2374e017f23a' +
  'd6313f9baf8cb5df67e38ffbcad5dc6e80bae17c88ff78398e5b87d942e1c1b8' +
  '874fe4b560b7ac62d30350d8157f695373f190ebb0d20a94279d0c52a1725ffb' +
  '6e6c375d235f4c5ded14addac2867a2833e6a434e1703e74298a33f7256da2a4'
const SRP_M1_LZ = '5e47f99a0ad71acfafb69178619918d45da53242ea84b6687bcfb94633bcc728'
const SRP_M2_LZ = '496fc84bcbaf2adb0de311f20f74279a8c0606a4fc9824e44f36751c7d531c1d'

test('SrpSession 4096/SHA-256 与 go-srp golden 一致', () => {
  const session = new SrpSession(SRP_IDENTITY, SRP_SALT, SRP_PASSWORD, SECRET1)
  const srpA = session.computeA()
  assert.equal(srpA.length, 512, 'srpA 必须为 512 字节')
  assert.equal(toHex(srpA), SRP_A)
  const srpM1 = session.computeM1(hex(SRP_B))
  assert.equal(toHex(srpM1), SRP_M1)
  assert.equal(session.verifyM2(hex(SRP_M2)), true)
  // 错误 M2 必须被拒绝
  const bad = hex(SRP_M2)
  bad[0] ^= 1
  assert.equal(session.verifyM2(bad), false)
})

test('computeM1 哈希发送的 512 字节 srpA（A 有前导零字节时与 ente/go-srp 一致）', () => {
  const session = new SrpSession(SRP_IDENTITY, SRP_SALT, SRP_PASSWORD, SECRET1_LZ)
  const srpA = session.computeA()
  assert.equal(srpA.length, 512, 'srpA 必须为 512 字节')
  assert.equal(srpA[0], 0, '本向量要求 A 有前导零字节')
  assert.equal(toHex(srpA), SRP_A_LZ)
  const srpM1 = session.computeM1(hex(SRP_B_LZ))
  assert.equal(toHex(srpM1), SRP_M1_LZ)
  assert.equal(session.verifyM2(hex(SRP_M2_LZ)), true)
})

test('M1 长度与非法 srpB', () => {
  const session = new SrpSession(SRP_IDENTITY, SRP_SALT, SRP_PASSWORD, SECRET1)
  assert.throws(() => session.verifyM2(hex(SRP_M2)), /computeM1 first/)
  assert.throws(() => session.computeM1(new Uint8Array(512)), /invalid server-supplied B/)
})

test('deriveLoginKey 与 libsodium crypto_kdf 语义一致', () => {
  // kek = 01..20，Python blake2b(key, salt=LE64(1)||pad, person="loginctx"||pad) 前 16 字节
  const kek = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
  assert.equal(toHex(deriveLoginKey(kek)), '01c04280401affefd32debd8ab9fc978')
})

test('deriveKEK 与 OpenSSL ARGON2ID golden 一致', async () => {
  // OpenSSL ARGON2ID: pass=correct_horse salt="0123456789abcdef" m=64KiB t=3 p=1 len=32
  const kek = await deriveKEK('correct_horse', b64encode(hex('30313233343536373839616263646566')), 3, 64 * 1024)
  assert.equal(toHex(kek), '90768a15b02ec5dcf7a279d77e3753f6aff69fd5ddfe103afd305d4b5ea1ad1a')
})

test('openKeyAttributes 解密链（PyNaCl golden）', () => {
  // 三层向量：KEK→masterKey→secretKey（PyNaCl 生成）
  const attrs: KeyAttributes = {
    kekSalt: '',
    encryptedKey: '3FtrR2K2oUVk17iIwwKIq20Qr39N1f9DzHxd2DbAx3wJEr04oesq0mS9r9kh2put',
    keyDecryptionNonce: 'DbrJhTP9j51Yes3LgWE0jOeh8vPAe7dG',
    publicKey: '',
    encryptedSecretKey: 'u7JM4ADzcgWCL48xVPt3XMRi3gTjzqhOrnRYEjxKcg5i66heFKTWqSMA75LLP9Tj',
    secretKeyDecryptionNonce: '/3ZGgyUNkQHnxIEZvhh7ZX3D2snrCNjW',
    memLimit: 0,
    opsLimit: 0,
  }
  const kek = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
  const { masterKey, secretKey } = openKeyAttributes(attrs, kek)
  assert.equal(toHex(masterKey), '4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60')
  assert.equal(toHex(secretKey), '6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80')
  // 错误 KEK 抛可读错误
  assert.throws(() => openKeyAttributes(attrs, hex('00'.repeat(32))), /key decryption failed/)
})

test('openToken 解 ente 官方 sealed box 向量', () => {
  const token = openToken(
    'jVHae52Eixf5JkF0B0jZYR0U/KQ8ckCM631dw253O0bPMmpGHRPieCG/KRKk075x4STFEptJDw==',
    'W/Vcc7guviK+gPNDBmevVw+uJVamQV5rMNQGUwCqlH0=',
    b64decode('UEatwduoOIZ7K7v90MNCPli1eXC1JnqQ9XlgkkqH8ZY='),
  )
  assert.deepEqual(Array.from(token), [0, 1, 127, 128, 254, 255, 16])
})

test('b64 往返', () => {
  const bytes = crypto.getRandomValues(new Uint8Array(48))
  assert.deepEqual(Array.from(b64decode(b64encode(bytes))), Array.from(bytes))
})
