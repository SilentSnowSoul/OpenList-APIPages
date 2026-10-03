/**
 * Ente 密码登录表单：SRP/OTP/TOTP 全流程 + 凭证导出。
 * 密码与派生密钥只存组件内存，流程结束或出错即清空（spec: Credentials never leave the browser）。
 */
import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { App, Button, Divider, Input, Space, Typography } from 'antd'
import { LockOutlined, MailOutlined, SendOutlined } from '@ant-design/icons'
import CopyableField from './CopyableField'
import KdfWorker from '../lib/ente/kdf.worker?worker'
import {
  DEFAULT_ENTE_ENDPOINT,
  EnteApiError,
  EnteClient,
  SrpNotRegistered,
  type AuthSuccess,
  type SrpAttributes,
} from '../lib/ente/client'
import {
  SrpSession,
  b64decode,
  b64encode,
} from '../lib/ente/crypto'
import { openCredentials, verifySrpM2, type EnteCredentials } from '../lib/ente/login'

type Step = 'credentials' | 'ott' | 'totp' | 'done'

/**
 * 待完成登录的上下文，按 kind 区分三条路径：
 * - srp：SRP 成功、待 TOTP（kek 已派生，M2 已校验）
 * - ott：email OTP 路径，verify-email 前（kek 待响应后派生）
 * - ott-totp：email OTP 路径进入 2FA（kek 待 2FA 完成后派生）
 */
type PendingContext =
  | { kind: 'srp'; client: EnteClient; kek: Uint8Array; twoFactorSessionID: string }
  | { kind: 'ott'; client: EnteClient; email: string }
  | { kind: 'ott-totp'; client: EnteClient; email: string; twoFactorSessionID: string }

interface KdfWorkerResult {
  kek?: string
  loginKey?: string
  error?: string
}

/** KDF 放 Web Worker（1GiB memLimit 会卡死主线程） */
function deriveKekInWorker(
  password: string,
  kekSalt: string,
  opsLimit: number,
  memLimit: number,
): Promise<{ kek: Uint8Array; loginKey: Uint8Array }> {
  return new Promise((resolve, reject) => {
    const worker = new KdfWorker()
    const cleanup = () => worker.terminate()
    worker.onmessage = (event: MessageEvent<KdfWorkerResult>) => {
      cleanup()
      const data = event.data
      if (data.error || !data.kek || !data.loginKey) {
        reject(new Error(`KDF failed: ${data.error || 'worker returned no key material'}`))
      } else {
        resolve({ kek: b64decode(data.kek), loginKey: b64decode(data.loginKey) })
      }
    }
    worker.onerror = () => {
      cleanup()
      reject(new Error('KDF failed: worker could not be loaded'))
    }
    worker.postMessage({ password, kekSalt, opsLimit, memLimit })
  })
}

/** 从 keyAttributes 派生 KEK；SRP 路径在 2FA 前、OTP 路径在 2FA 完成后调用 */
async function deriveKekFromAttributes(
  password: string,
  attrs: { kekSalt: string; opsLimit: number; memLimit: number },
): Promise<Uint8Array> {
  const { kek } = await deriveKekInWorker(password, attrs.kekSalt, attrs.opsLimit, attrs.memLimit)
  return kek
}

export default function EnteLoginForm() {
  const { t } = useTranslation()
  const { message } = App.useApp()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [endpoint, setEndpoint] = useState(DEFAULT_ENTE_ENDPOINT)
  const [ott, setOtt] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [step, setStep] = useState<Step>('credentials')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<EnteCredentials | null>(null)

  const pendingRef = useRef<PendingContext | null>(null)

  const showError = (error: unknown) => {
    if (error instanceof EnteApiError) {
      const keyByKind: Record<string, string> = {
        INVALID_CREDENTIALS: 'ente.errInvalidCredentials',
        ACCOUNT_NOT_FOUND: 'ente.errAccountNotFound',
        RATE_LIMITED: 'ente.errRateLimited',
        NETWORK: 'ente.errNetwork',
        PASSKEY_UNSUPPORTED: 'ente.errPasskey',
        SERVER: 'ente.errServer',
      }
      message.error(t(keyByKind[error.kind] ?? 'ente.errServer'))
    } else if (error instanceof Error && /srpM2|M2 verification/i.test(error.message)) {
      // 服务端无法证明持有 verifier：中止而非继续，避免把凭证交给中间人
      message.error(t('ente.errSrpVerify'))
    } else if (error instanceof Error && /KDF failed|memory|allocat/i.test(error.message)) {
      // argon2id 大 memLimit 在低内存浏览器/设备上会分配失败，Web Worker 也可能加载不起来
      message.error(t('ente.errKdf'))
    } else if (error instanceof Error && /decryption|unseal/i.test(error.message)) {
      message.error(t('ente.errDecrypt'))
    } else if (error instanceof Error) {
      message.error(`${t('ente.errServer')}: ${error.message}`)
    } else {
      message.error(t('ente.errNetwork'))
    }
  }

  /** 密码/密钥即用即清 */
  const clearSecrets = () => {
    setPassword('')
    pendingRef.current = null
  }

  const finish = (auth: AuthSuccess, kek: Uint8Array) => {
    setResult(openCredentials(auth, kek))
    clearSecrets()
    setOtt('')
    setTotpCode('')
    setStep('done')
    message.success(t('ente.loginSuccess'))
  }

  const handleLogin = async () => {
    if (!email || !password) {
      message.error(t('ente.errFillForm'))
      return
    }
    setLoading(true)
    try {
      const client = new EnteClient(endpoint || DEFAULT_ENTE_ENDPOINT)
      let attributes: SrpAttributes
      try {
        attributes = await client.getSrpAttributes(email)
      } catch (error) {
        if (!(error instanceof SrpNotRegistered)) throw error
        // 无 SRP verifier（或 email-MFA）：OTP 路径
        await client.sendOtt(email)
        pendingRef.current = { kind: 'ott', client, email }
        setStep('ott')
        message.info(t('ente.ottSent'))
        return
      }
      if (attributes.isEmailMFAEnabled) {
        await client.sendOtt(email)
        pendingRef.current = { kind: 'ott', client, email }
        setStep('ott')
        message.info(t('ente.ottSent'))
        return
      }
      await runSrp(client, attributes)
    } catch (error) {
      showError(error)
      clearSecrets()
    } finally {
      setLoading(false)
    }
  }

  const runSrp = async (client: EnteClient, attributes: SrpAttributes) => {
    const { kek, loginKey } = await deriveKekInWorker(
      password,
      attributes.kekSalt,
      attributes.opsLimit,
      attributes.memLimit,
    )
    const identity = new TextEncoder().encode(attributes.srpUserID)
    const session = new SrpSession(identity, b64decode(attributes.srpSalt), loginKey)
    const { sessionID, srpB } = await client.createSrpSession(
      attributes.srpUserID,
      b64encode(session.computeA()),
    )
    const auth = await client.verifySrpSession(
      attributes.srpUserID,
      sessionID,
      b64encode(session.computeM1(b64decode(srpB))),
    )
    // verify-session 必须携带并可验证 srpM2（2FA 分支同样返回，见 client.ts）；
    // /users/two-factor/verify 的响应不含 srpM2，所以必须在此处校验，不能推迟到 finish。
    verifySrpM2(auth, session)

    if (auth.status === '2fa_required') {
      pendingRef.current = { kind: 'srp', client, kek, twoFactorSessionID: auth.twoFactorSessionID }
      setStep('totp')
      message.info(t('ente.totpNeeded'))
      return
    }
    finish(auth, kek)
  }

  const handleOttVerify = async () => {
    const pending = pendingRef.current
    if (pending?.kind !== 'ott' || !ott) {
      message.error(t('ente.errFillOtt'))
      return
    }
    setLoading(true)
    try {
      // OTP 验证后仍需密码派生 KEK 解 keyAttributes（无 SRP，故无 M2 可校验）
      const auth = await pending.client.verifyEmail(pending.email, ott)
      if (auth.status === '2fa_required') {
        // email-MFA 账号同时开了 TOTP：回到 totp 步，kek 在 2FA 完成后再派生
        pendingRef.current = { kind: 'ott-totp', client: pending.client, email: pending.email, twoFactorSessionID: auth.twoFactorSessionID }
        setStep('totp')
        message.info(t('ente.totpNeeded'))
        return
      }
      if (auth.status !== 'ok') {
        message.error(t('ente.errServer'))
        return
      }
      const kek = await deriveKekFromAttributes(password, auth.keyAttributes)
      finish(auth, kek)
    } catch (error) {
      showError(error)
      clearSecrets()
    } finally {
      setLoading(false)
    }
  }

  const handleTotpVerify = async () => {
    const pending = pendingRef.current
    if ((pending?.kind !== 'srp' && pending?.kind !== 'ott-totp') || !totpCode) {
      message.error(t('ente.errFillTotp'))
      return
    }
    setLoading(true)
    try {
      const auth = await pending.client.verifyTwoFactor(pending.twoFactorSessionID, totpCode)
      if (auth.status !== 'ok') {
        message.error(t('ente.errServer'))
        return
      }
      // SRP 路径的 kek 在进入 2FA 前已派生；OTP 路径此时才能从 keyAttributes 派生
      const kek = pending.kind === 'srp'
        ? pending.kek
        : await deriveKekFromAttributes(password, auth.keyAttributes)
      finish(auth, kek)
    } catch (error) {
      // 验证码错误允许重试，不清 pending
      if (error instanceof EnteApiError && error.kind === 'INVALID_CREDENTIALS') {
        message.error(t('ente.errInvalidTotp'))
        return
      }
      showError(error)
      clearSecrets()
    } finally {
      setLoading(false)
    }
  }

  const restart = () => {
    clearSecrets()
    setResult(null)
    setStep('credentials')
  }

  return (
    <div className="ente-login">
      {step === 'credentials' && (
        <>
          <div className="field">
            <label className="field-label">{t('ente.email')}</label>
            <Input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@example.com"
              prefix={<MailOutlined />}
              className="mono-input"
              size="large"
              autoComplete="off"
            />
          </div>
          <div className="field">
            <label className="field-label">{t('ente.password')}</label>
            <Input.Password
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t('ente.passwordPlaceholder')}
              prefix={<LockOutlined />}
              className="mono-input"
              size="large"
              autoComplete="new-password"
            />
          </div>
          <div className="field">
            <label className="field-label">{t('ente.endpoint')}</label>
            <Input
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder={DEFAULT_ENTE_ENDPOINT}
              className="mono-input"
              size="large"
            />
          </div>
          <Divider />
          <Button
            type="primary"
            size="large"
            icon={<SendOutlined />}
            loading={loading}
            onClick={() => void handleLogin()}
            className="action-btn"
          >
            {t('ente.login')}
          </Button>
          <Typography.Paragraph type="secondary" className="ente-login__privacy" style={{ marginTop: 12 }}>
            {t('ente.privacy')}
          </Typography.Paragraph>
        </>
      )}

      {step === 'ott' && (
        <>
          <Typography.Paragraph>{t('ente.ottSent')}</Typography.Paragraph>
          <div className="field">
            <label className="field-label">{t('ente.ott')}</label>
            <Input
              value={ott}
              onChange={(e) => setOtt(e.target.value)}
              placeholder={t('ente.ottPlaceholder')}
              className="mono-input"
              size="large"
            />
          </div>
          <Space size={12}>
            <Button type="primary" size="large" loading={loading} onClick={() => void handleOttVerify()}>
              {t('ente.ottSubmit')}
            </Button>
            <Button size="large" onClick={restart}>
              {t('common.cancel')}
            </Button>
          </Space>
        </>
      )}

      {step === 'totp' && (
        <>
          <Typography.Paragraph>{t('ente.totpNeeded')}</Typography.Paragraph>
          <div className="field">
            <label className="field-label">{t('ente.totp')}</label>
            <Input
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
              placeholder="123456"
              maxLength={6}
              className="mono-input"
              size="large"
            />
          </div>
          <Space size={12}>
            <Button type="primary" size="large" loading={loading} onClick={() => void handleTotpVerify()}>
              {t('ente.totpSubmit')}
            </Button>
            <Button size="large" onClick={restart}>
              {t('common.cancel')}
            </Button>
          </Space>
        </>
      )}

      {step === 'done' && result && (
        <>
          <div className="field">
            <label className="field-label">{t('ente.token')}</label>
            <CopyableField value={result.token} placeholder="—" rows={2} size="large" />
          </div>
          <div className="field">
            <label className="field-label">{t('ente.masterKey')}</label>
            <CopyableField value={result.masterKey} placeholder="—" rows={2} size="large" />
          </div>
          <div className="field">
            <label className="field-label">{t('ente.secretKey')}</label>
            <CopyableField value={result.secretKey} placeholder="—" rows={2} size="large" />
          </div>
          <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>
            {t('ente.hint', { endpoint: endpoint || DEFAULT_ENTE_ENDPOINT })}
          </Typography.Paragraph>
          <Button size="large" onClick={restart}>
            {t('ente.relogin')}
          </Button>
        </>
      )}
    </div>
  )
}
