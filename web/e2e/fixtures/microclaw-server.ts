import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const E2E_PASSWORD = 'e2e-smoke-password-123'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

export interface MicroclawServer {
  baseURL: string
  /** Everything the process wrote to stdout/stderr so far (for failure diagnostics). */
  readonly log: string
  stop(): Promise<void>
}

export function resolveBinary(): string {
  const fromEnv = process.env.MICROCLAW_BIN
  const candidates = fromEnv
    ? [path.resolve(fromEnv)]
    : [
        path.join(repoRoot, 'target', 'debug', 'microclaw'),
        path.join(repoRoot, 'target', 'release', 'microclaw'),
      ].map((p) => (process.platform === 'win32' ? `${p}.exe` : p))
  const found = candidates.find((p) => existsSync(p))
  if (!found) {
    throw new Error(
      `microclaw binary not found (looked at ${candidates.join(', ')}). ` +
        'Run `cargo build` first or point MICROCLAW_BIN at the binary.',
    )
  }
  return found
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer()
    srv.unref()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const address = srv.address()
      if (!address || typeof address === 'string') {
        reject(new Error('could not determine a free port'))
        return
      }
      srv.close(() => resolve(address.port))
    })
  })
}

async function waitForHttp200(url: string, timeoutMs: number, isAlive: () => boolean, logs: () => string) {
  const deadline = Date.now() + timeoutMs
  let lastError = ''
  while (Date.now() < deadline) {
    if (!isAlive()) {
      throw new Error(`microclaw exited before serving ${url}\n--- server log ---\n${logs()}`)
    }
    try {
      const res = await fetch(url, { redirect: 'manual' })
      if (res.status === 200) return
      lastError = `HTTP ${res.status}`
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err)
    }
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error(`timed out waiting for ${url} (${lastError})\n--- server log ---\n${logs()}`)
}

/**
 * Boot a throwaway `microclaw start` with only the web channel enabled.
 *
 * The LLM credentials are placeholders: sending a message will fail at the
 * provider, which is fine because the smoke test asserts on the UI, not the
 * reply. Everything lives in a scratch data_dir that is removed on stop().
 */
export async function startMicroclaw(): Promise<MicroclawServer> {
  const binary = resolveBinary()
  const scratch = mkdtempSync(path.join(tmpdir(), 'microclaw-e2e-'))
  const dataDir = path.join(scratch, 'data')
  const workingDir = path.join(scratch, 'work')
  const configPath = path.join(scratch, 'microclaw.config.yaml')
  const port = await freePort()

  const yamlString = (value: string) => JSON.stringify(value)
  writeFileSync(
    configPath,
    [
      'llm_provider: "anthropic"',
      'api_key: "sk-ant-e2e-placeholder-key"',
      'model: "claude-sonnet-4-5"',
      `data_dir: ${yamlString(dataDir)}`,
      `working_dir: ${yamlString(workingDir)}`,
      'web_host: "127.0.0.1"',
      `web_port: ${port}`,
      'channels:',
      '  web:',
      '    enabled: true',
      '',
    ].join('\n'),
  )

  const env = { ...process.env, MICROCLAW_CONFIG: configPath, RUST_LOG: process.env.RUST_LOG ?? 'info' }

  const setPassword = spawnSync(binary, ['web', 'password', E2E_PASSWORD], { env, encoding: 'utf8' })
  if (setPassword.status !== 0) {
    rmSync(scratch, { recursive: true, force: true })
    throw new Error(
      `\`microclaw web password\` failed (exit ${setPassword.status}):\n${setPassword.stdout}\n${setPassword.stderr}`,
    )
  }

  let log = ''
  const child: ChildProcess = spawn(binary, ['start'], { env, stdio: ['ignore', 'pipe', 'pipe'] })
  const append = (chunk: Buffer) => {
    log += chunk.toString()
    if (log.length > 200_000) log = log.slice(-200_000)
  }
  child.stdout?.on('data', append)
  child.stderr?.on('data', append)
  let exited = false
  child.on('exit', () => {
    exited = true
  })

  const baseURL = `http://127.0.0.1:${port}`
  try {
    await waitForHttp200(`${baseURL}/`, 60_000, () => !exited, () => log)
  } catch (err) {
    child.kill('SIGKILL')
    rmSync(scratch, { recursive: true, force: true })
    throw err
  }

  return {
    baseURL,
    get log() {
      return log
    },
    async stop() {
      if (!exited) {
        child.kill('SIGTERM')
        await Promise.race([
          new Promise<void>((resolve) => child.once('exit', () => resolve())),
          new Promise<void>((resolve) => setTimeout(resolve, 5_000)),
        ])
        if (!exited) child.kill('SIGKILL')
      }
      rmSync(scratch, { recursive: true, force: true })
    },
  }
}
