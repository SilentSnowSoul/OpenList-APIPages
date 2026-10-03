#!/usr/bin/env node
/**
 * Ente 登录真实冒烟脚本（env-gated 手动运行，不进 CI）。
 *
 * 与 frontend/src/components/EnteLoginForm.tsx 走同一条协议路径：
 *   attributes → SRP（或 email OTP）→ 可选 TOTP → 解密 → 打印 Worker ente 驱动凭证。
 * 直接复用前端 crypto / client / login 模块（含凭证解密与 srpM2 校验），
 * 保证冒烟覆盖的就是真正上线的那份实现。
 *
 * 用法：
 *   ENTE_EMAIL=you@example.com ENTE_PASSWORD='...' \
 *     node --experimental-strip-types scripts/test-ente-login.mjs
 *
 * 环境变量：
 *   ENTE_EMAIL     必填，ente 账号邮箱
 *   ENTE_PASSWORD  必填，ente 账号密码
 *   ENTE_API       选填，museum endpoint，默认 https://api.ente.com（自托管填自己的地址）
 *   ENTE_OTP       选填，email-MFA / 无 SRP verifier 账号的邮箱验证码（缺省时交互输入）
 *   ENTE_TOTP      选填，已开 TOTP 账号的 6 位验证码（缺省时交互输入）
 *
 * 凭证仅经环境变量注入，不写入磁盘、不硬编码；打印结果含密钥，注意终端回滚缓冲。
 */
import { createInterface } from 'node:readline/promises'
import { stdin, stdout } from 'node:process'
import {
  DEFAULT_ENTE_ENDPOINT,
  EnteApiError,
  EnteClient,
  SrpNotRegistered,
} from '../frontend/src/lib/ente/client.ts'
import {
  SrpSession,
  b64decode,
  b64encode,
  deriveKEK,
  deriveLoginKey,
} from '../frontend/src/lib/ente/crypto.ts'
import { openCredentials, verifySrpM2 } from '../frontend/src/lib/ente/login.ts'

const endpoint = (process.env.ENTE_API || DEFAULT_ENTE_ENDPOINT).replace(/\/+$/, '')
const email = process.env.ENTE_EMAIL
const password = process.env.ENTE_PASSWORD

if (!email || !password) {
  console.error('跳过：未提供 ENTE_EMAIL / ENTE_PASSWORD（本脚本为手动冒烟，不进入 CI）。')
  console.error('用法：ENTE_EMAIL=you@example.com ENTE_PASSWORD=... node --experimental-strip-types scripts/test-ente-login.mjs')
  process.exit(0)
}

const rl = createInterface({ input: stdin, output: stdout })

/** 验证码优先取 env，缺省时交互输入 */
async function promptCode(envValue, label) {
  if (envValue) return envValue
  return (await rl.question(`${label}：`)).trim()
}

/** 与 UI 一致：argon2id KEK + blake2b loginKey */
async function derive(password, kekSalt, opsLimit, memLimit) {
  console.log(`  argon2id KDF（opsLimit=${opsLimit}, memLimit=${memLimit} bytes）…`)
  const kek = await deriveKEK(password, kekSalt, opsLimit, memLimit)
  return { kek, loginKey: deriveLoginKey(kek) }
}

/** 与 UI 共用 openCredentials / verifySrpM2，冒烟覆盖的就是上线的那份实现 */
function decrypt(auth, kek) {
  return openCredentials(auth, kek)
}

/** SRP 响应必须携带并可验证 srpM2（2FA 分支同样返回；two-factor/verify 不返回） */
function verifyM2(auth, session) {
  verifySrpM2(auth, session)
  console.log('  srpM2 校验通过')
}

async function main() {
  console.log(`endpoint: ${endpoint}`)
  const client = new EnteClient(endpoint)

  console.log('1/4 拉取 SRP attributes…')
  let attributes = null
  try {
    attributes = await client.getSrpAttributes(email)
  } catch (error) {
    if (!(error instanceof SrpNotRegistered)) throw error
    console.log('  404：账号无 SRP verifier，走 email OTP 路径')
  }

  // ---- email OTP 路径 ----
  if (!attributes || attributes.isEmailMFAEnabled) {
    if (attributes?.isEmailMFAEnabled) console.log('  账号启用了 email MFA，走 email OTP 路径')
    console.log('2/4 发送邮箱验证码…')
    await client.sendOtt(email)
    const ott = await promptCode(process.env.ENTE_OTP, '邮箱验证码')
    let auth = await client.verifyEmail(email, ott)
    // email-MFA + TOTP 账号：verify-email 返回 twoFactorSessionID(V2)，还需再过一道 TOTP
    if (auth.status === '2fa_required') {
      console.log('  账号同时开启两步验证，需要 TOTP…')
      const totp = await promptCode(process.env.ENTE_TOTP, 'TOTP 验证码')
      auth = await client.verifyTwoFactor(auth.twoFactorSessionID, totp)
    }
    if (auth.status !== 'ok') throw new Error(`验证未返回凭证：${auth.status}`)
    console.log('3/4 派生 KEK…')
    const { kek } = await derive(
      password,
      auth.keyAttributes.kekSalt,
      auth.keyAttributes.opsLimit,
      auth.keyAttributes.memLimit,
    )
    console.log('4/4 解密凭证…')
    return decrypt(auth, kek)
  }

  // ---- SRP 路径 ----
  console.log('2/4 派生 KEK 并执行 SRP-4096…')
  const { kek, loginKey } = await derive(password, attributes.kekSalt, attributes.opsLimit, attributes.memLimit)
  const session = new SrpSession(
    new TextEncoder().encode(attributes.srpUserID),
    b64decode(attributes.srpSalt),
    loginKey,
  )
  const { sessionID, srpB } = await client.createSrpSession(
    attributes.srpUserID,
    b64encode(session.computeA()),
  )
  let auth = await client.verifySrpSession(
    attributes.srpUserID,
    sessionID,
    b64encode(session.computeM1(b64decode(srpB))),
  )
  verifyM2(auth, session)

  // ---- 可选 TOTP ----
  if (auth.status === '2fa_required') {
    console.log('3/4 账号已开两步验证，需要 TOTP…')
    const totp = await promptCode(process.env.ENTE_TOTP, 'TOTP 验证码')
    auth = await client.verifyTwoFactor(auth.twoFactorSessionID, totp)
    if (auth.status !== 'ok') throw new Error(`two-factor/verify 未返回凭证：${auth.status}`)
  } else {
    console.log('3/4 无需两步验证')
  }

  console.log('4/4 解密凭证…')
  return decrypt(auth, kek)
}

try {
  const { token, masterKey, secretKey } = await main()
  console.log('\n=== OpenList-Worker ente 驱动配置 ===')
  console.log(`endpoint    : ${endpoint}`)
  console.log(`token       : ${token}`)
  console.log(`master_key  : ${masterKey}`)
  console.log(`secret_key  : ${secretKey}`)
  console.log('show_hidden : false（按需改为 true）')
  console.log('\n冒烟通过：请将以上字段填入 Worker ente 驱动并确认可挂载。')
} catch (error) {
  if (error instanceof EnteApiError) {
    console.error(`\n失败（${error.kind}${error.status ? ` HTTP ${error.status}` : ''}）：${error.serverMessage || error.message}`)
  } else {
    console.error(`\n失败：${error instanceof Error ? error.message : String(error)}`)
  }
  process.exitCode = 1
} finally {
  rl.close()
}
