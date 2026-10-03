/**
 * argon2id KEK 派生 Web Worker：大 memLimit（1GiB/4 或 256MiB/16）会阻塞主线程，放后台执行。
 */
import { deriveKEK, deriveLoginKey, b64encode } from './crypto'

interface KdfRequest {
  password: string
  kekSalt: string
  opsLimit: number
  memLimit: number
}

self.onmessage = async (event: MessageEvent<KdfRequest>) => {
  const { password, kekSalt, opsLimit, memLimit } = event.data
  try {
    const kek = await deriveKEK(password, kekSalt, opsLimit, memLimit)
    self.postMessage({ kek: b64encode(kek), loginKey: b64encode(deriveLoginKey(kek)) })
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : String(error) })
  }
}
