// Settings-panel config model: provider profiles, multi-account channel
// drafts, soul-path helpers, and input parsers shared by the config forms.
import type { A2APeerDraft, ConfigPayload, ProviderProfileDraft } from './backend-types'
import { DYNAMIC_CHANNELS } from './channels'

export const PROVIDER_SUGGESTIONS = [
  'openai',
  'openai-codex',
  'ollama',
  'openrouter',
  'anthropic',
  'google',
  'aliyun-bailian',
  'alibaba',
  'deepseek',
  'moonshot',
  'mistral',
  'azure',
  'bedrock',
  'zhipu',
  'minimax',
  'cohere',
  'tencent',
  'xai',
  'nvidia',
  'huggingface',
  'together',
  'custom',
]

export const MODEL_OPTIONS: Record<string, string[]> = {
  anthropic: ['claude-sonnet-4-5-20250929', 'claude-opus-4-1-20250805', 'claude-3-7-sonnet-latest'],
  openai: ['gpt-5.2'],
  'openai-codex': ['gpt-5.3-codex'],
  ollama: ['llama3.2', 'qwen2.5', 'deepseek-r1'],
  openrouter: ['openai/gpt-5', 'anthropic/claude-sonnet-4-5', 'google/gemini-2.5-pro'],
  deepseek: ['deepseek-chat', 'deepseek-reasoner'],
  google: ['gemini-2.5-pro', 'gemini-2.5-flash'],
  'aliyun-bailian': ['qwen3.5-plus', 'qwen3-max', 'qwen-plus-latest'],
  nvidia: ['meta/llama-3.3-70b-instruct', 'meta/llama-3.1-70b-instruct'],
}

export const DEFAULT_CONFIG_VALUES = {
  llm_provider: 'anthropic',
  working_dir_isolation: 'chat',
  high_risk_tool_user_confirmation_required: true,
  max_tokens: 8192,
  max_tool_iterations: 100,
  max_document_size_mb: 100,
  memory_token_budget: 1500,
  show_thinking: false,
  web_enabled: true,
  web_host: '127.0.0.1',
  web_port: 10961,
  reflector_enabled: true,
  reflector_interval_mins: 15,
  embedding_provider: '',
  embedding_api_key: '',
  embedding_base_url: '',
  embedding_model: '',
  embedding_dim: '',
  a2a_enabled: false,
  a2a_public_base_url: '',
  a2a_agent_name: '',
  a2a_agent_description: '',
  a2a_shared_tokens: '',
  a2a_peers: [] as A2APeerDraft[],
  souls_dir: '',
}

export const BOT_SLOT_MAX = 10
export const MAIN_PROFILE_VALUE = '__main__'

export function nextProviderProfileId(entries: ProviderProfileDraft[]): string {
  const used = new Set(entries.map((entry) => String(entry.id || '').trim().toLowerCase()).filter(Boolean))
  for (let idx = 1; idx < 10_000; idx += 1) {
    const candidate = `provider${idx}`
    if (!used.has(candidate)) return candidate
  }
  return 'provider1'
}

export function nextClonedProviderProfileId(entries: ProviderProfileDraft[], sourceId: string): string {
  const base = String(sourceId || '').trim().toLowerCase()
  if (!base) return nextProviderProfileId(entries)
  const used = new Set(entries.map((entry) => String(entry.id || '').trim().toLowerCase()).filter(Boolean))
  for (let idx = 2; idx < 10_000; idx += 1) {
    const candidate = `${base}-${idx}`
    if (!used.has(candidate)) return candidate
  }
  return `${base}-2`
}

export function emptyProviderProfileDraft(entries: ProviderProfileDraft[]): ProviderProfileDraft {
  return {
    id: nextProviderProfileId(entries),
    provider: 'anthropic',
    api_key: '',
    llm_base_url: '',
    llm_user_agent: '',
    default_model: defaultModelForProvider('anthropic'),
    show_thinking: false,
  }
}

export function normalizeProviderProfileDraft(raw: unknown, fallbackId = ''): ProviderProfileDraft {
  const draft = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  return {
    id: String(draft.id || fallbackId || '').trim(),
    provider: String(draft.provider || '').trim(),
    api_key: typeof draft.api_key === 'string' && draft.api_key.trim() === '***' ? '' : String(draft.api_key || ''),
    llm_base_url: String(draft.llm_base_url || ''),
    llm_user_agent: String(draft.llm_user_agent || ''),
    default_model: String(draft.default_model || ''),
    show_thinking: Boolean(draft.show_thinking),
  }
}

export function providerProfilesFromConfig(config: ConfigPayload | null): ProviderProfileDraft[] {
  const presetsRaw =
    (config?.provider_presets as Record<string, unknown> | undefined) ||
    (config?.llm_providers as Record<string, unknown> | undefined) ||
    {}
  return Object.entries(presetsRaw)
    .filter(([id]) => id.trim() && id.trim().toLowerCase() !== 'main')
    .map(([id, value]) => normalizeProviderProfileDraft(value, id))
    .sort((a, b) => a.id.localeCompare(b.id))
}

export function serializeProviderProfiles(entries: ProviderProfileDraft[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const raw of entries) {
    const entry = normalizeProviderProfileDraft(raw)
    const id = entry.id.trim().toLowerCase()
    if (!id || id === 'main') continue
    out[id] = {
      ...(entry.provider.trim() ? { provider: entry.provider.trim().toLowerCase() } : {}),
      ...(entry.api_key.trim() ? { api_key: entry.api_key.trim() } : {}),
      ...(entry.llm_base_url.trim() ? { llm_base_url: entry.llm_base_url.trim() } : {}),
      ...(entry.llm_user_agent.trim() ? { llm_user_agent: entry.llm_user_agent.trim() } : {}),
      ...(entry.default_model.trim() ? { default_model: entry.default_model.trim() } : {}),
      show_thinking: Boolean(entry.show_thinking),
    }
  }
  return out
}

export function providerPresetFromConfigValue(raw: unknown): string {
  if (!raw || typeof raw !== 'object') return ''
  const cfg = raw as Record<string, unknown>
  return String(cfg.provider_preset || cfg.llm_provider || '').trim()
}

export function providerProfileOptions(entries: ProviderProfileDraft[], currentRaw: unknown): Array<{ value: string; label: string }> {
  const current = String(currentRaw || '').trim()
  const options = [{ value: MAIN_PROFILE_VALUE, label: 'main (global default)' }]
  const seen = new Set<string>([MAIN_PROFILE_VALUE])
  for (const entry of entries) {
    const id = String(entry.id || '').trim()
    if (!id || seen.has(id)) continue
    options.push({
      value: id,
      label: `${id} · ${String(entry.provider || 'custom').trim() || 'custom'} / ${String(entry.default_model || '').trim() || '(no model)'}`,
    })
    seen.add(id)
  }
  if (current && !seen.has(current)) {
    options.push({ value: current, label: `${current} · custom/current` })
  }
  return options
}

export function providerProfileReferences(configDraft: Record<string, unknown>, profileIdRaw: unknown): string[] {
  const profileId = String(profileIdRaw || '').trim()
  if (!profileId) return []
  const refs: string[] = []

  if (String(configDraft.telegram_provider_preset || '').trim().toLowerCase() === profileId.toLowerCase()) {
    refs.push('telegram channel')
  }
  if (String(configDraft.discord_provider_preset || '').trim().toLowerCase() === profileId.toLowerCase()) {
    refs.push('discord channel')
  }

  for (let slot = 1; slot <= normalizeBotCount(configDraft.telegram_bot_count || 1); slot += 1) {
    if (String(configDraft[`telegram_bot_${slot}_provider_preset`] || '').trim().toLowerCase() === profileId.toLowerCase()) {
      const accountId = normalizeAccountId(configDraft[`telegram_bot_${slot}_account_id`] || defaultTelegramAccountIdForSlot(slot))
      refs.push(`telegram.${accountId}`)
    }
  }

  for (let slot = 1; slot <= normalizeBotCount(configDraft.discord_bot_count || 1); slot += 1) {
    if (String(configDraft[`discord_bot_${slot}_provider_preset`] || '').trim().toLowerCase() === profileId.toLowerCase()) {
      const accountId = normalizeAccountId(configDraft[`discord_bot_${slot}_account_id`] || defaultAccountIdForSlot(slot))
      refs.push(`discord.${accountId}`)
    }
  }

  if (String(configDraft.irc_provider_preset || '').trim().toLowerCase() === profileId.toLowerCase()) {
    refs.push('irc channel')
  }

  for (const ch of DYNAMIC_CHANNELS) {
    for (let slot = 1; slot <= normalizeBotCount(configDraft[`${ch.name}__bot_count`] || 1); slot += 1) {
      const stateKey = `${ch.name}__bot_${slot}__provider_preset`
      if (String(configDraft[stateKey] || '').trim().toLowerCase() === profileId.toLowerCase()) {
        const accountId = normalizeAccountId(configDraft[`${ch.name}__bot_${slot}__account_id`] || defaultAccountIdForSlot(slot))
        refs.push(`${ch.name}.${accountId}`)
      }
    }
  }

  return Array.from(new Set(refs)).sort((a, b) => a.localeCompare(b))
}

export function renameProviderProfileReferences(
  configDraft: Record<string, unknown>,
  oldIdRaw: unknown,
  newIdRaw: unknown,
): Record<string, unknown> {
  const oldId = String(oldIdRaw || '').trim()
  const newId = String(newIdRaw || '').trim()
  if (!oldId || oldId.toLowerCase() === newId.toLowerCase()) return configDraft

  const next: Record<string, unknown> = { ...configDraft }
  const maybeReplace = (key: string): void => {
    if (String(next[key] || '').trim().toLowerCase() === oldId.toLowerCase()) {
      next[key] = newId
    }
  }

  maybeReplace('telegram_provider_preset')
  maybeReplace('discord_provider_preset')
  for (let slot = 1; slot <= BOT_SLOT_MAX; slot += 1) {
    maybeReplace(`telegram_bot_${slot}_provider_preset`)
    maybeReplace(`discord_bot_${slot}_provider_preset`)
  }
  maybeReplace('irc_provider_preset')
  for (const ch of DYNAMIC_CHANNELS) {
    for (let slot = 1; slot <= BOT_SLOT_MAX; slot += 1) {
      maybeReplace(`${ch.name}__bot_${slot}__provider_preset`)
    }
  }
  return next
}

export function resetProviderProfileReferencesToMain(
  configDraft: Record<string, unknown>,
  profileIdRaw: unknown,
): { nextDraft: Record<string, unknown>; resetRefs: string[] } {
  const profileId = String(profileIdRaw || '').trim()
  if (!profileId) return { nextDraft: configDraft, resetRefs: [] }

  const refs = providerProfileReferences(configDraft, profileId)
  if (refs.length === 0) return { nextDraft: configDraft, resetRefs: [] }

  const next = renameProviderProfileReferences(configDraft, profileId, '')
  return { nextDraft: next, resetRefs: refs }
}

export function defaultModelForProvider(providerRaw: string): string {
  const provider = providerRaw.trim().toLowerCase()
  if (provider === 'anthropic') return 'claude-sonnet-4-5-20250929'
  if (provider === 'openai-codex') return 'gpt-5.3-codex'
  if (provider === 'ollama') return 'llama3.2'
  if (provider === 'google') return 'gemini-2.5-pro'
  if (provider === 'aliyun-bailian') return 'qwen3.5-plus'
  if (provider === 'nvidia') return 'meta/llama-3.3-70b-instruct'
  return 'gpt-5.2'
}

export function normalizeAccountId(raw: unknown): string {
  const text = String(raw || '').trim()
  return text || 'main'
}

export function defaultAccountIdFromChannelConfig(channelCfg: unknown): string {
  if (!channelCfg || typeof channelCfg !== 'object') return 'main'
  const cfg = channelCfg as Record<string, unknown>
  const explicit = String(cfg.default_account || '').trim()
  if (explicit) return explicit
  const accounts = cfg.accounts
  if (accounts && typeof accounts === 'object') {
    const keys = Object.keys(accounts as Record<string, unknown>).sort()
    if (keys.includes('default')) return 'default'
    if (keys.length > 0) return keys[0] || 'main'
  }
  return 'main'
}

export function defaultAccountConfig(channelCfg: unknown): Record<string, unknown> {
  if (!channelCfg || typeof channelCfg !== 'object') return {}
  const cfg = channelCfg as Record<string, unknown>
  const accountId = defaultAccountIdFromChannelConfig(cfg)
  const accounts = cfg.accounts
  if (!accounts || typeof accounts !== 'object') return {}
  const account = (accounts as Record<string, unknown>)[accountId]
  return account && typeof account === 'object' ? (account as Record<string, unknown>) : {}
}

export function defaultTelegramAccountIdForSlot(slot: number): string {
  return slot <= 1 ? 'main' : `bot${slot}`
}

export function defaultAccountIdForSlot(slot: number): string {
  return slot <= 1 ? 'main' : `bot${slot}`
}

export function normalizeBotCount(raw: unknown): number {
  const n = Number(raw)
  if (!Number.isFinite(n)) return 1
  return Math.min(BOT_SLOT_MAX, Math.max(1, Math.floor(n)))
}

export function normalizeSoulPathInput(raw: unknown, soulsDir?: unknown): string {
  const trimmed = String(raw || '').trim()
  if (!trimmed) return ''
  if (trimmed.includes('/') || trimmed.includes('\\')) return trimmed
  const base = String(soulsDir || '').trim().replace(/[\\/]+$/, '') || 'souls'
  if (trimmed.toLowerCase().endsWith('.md')) return `${base}/${trimmed}`
  return `${base}/${trimmed}.md`
}

export function soulFileNameFromPath(raw: unknown): string {
  const text = String(raw || '').trim()
  if (!text) return ''
  const normalized = text.replace(/\\/g, '/')
  const parts = normalized.split('/')
  return parts[parts.length - 1] || ''
}

export function soulPickerValue(raw: unknown, options: readonly string[], soulsDir?: unknown): string {
  const normalized = normalizeSoulPathInput(raw, soulsDir)
  if (!normalized) return '__none__'
  const fileName = soulFileNameFromPath(normalized)
  return options.includes(fileName) ? fileName : '__custom__'
}

export function orderedAccountsFromChannelConfig(channelCfg: unknown): Array<[string, Record<string, unknown>]> {
  if (!channelCfg || typeof channelCfg !== 'object') return []
  const cfg = channelCfg as Record<string, unknown>
  const accountsRaw = cfg.accounts
  if (!accountsRaw || typeof accountsRaw !== 'object') return []
  const accountsObj = accountsRaw as Record<string, unknown>
  const entries: Array<[string, Record<string, unknown>]> = Object.entries(accountsObj)
    .filter(([, v]) => v && typeof v === 'object' && !Array.isArray(v))
    .map(([id, v]) => [id, v as Record<string, unknown>])
  if (entries.length === 0) return []

  const defaultId = defaultAccountIdFromChannelConfig(cfg)
  entries.sort(([a], [b]) => a.localeCompare(b))
  const defaultIdx = entries.findIndex(([id]) => id === defaultId)
  if (defaultIdx > 0) {
    const [defaultEntry] = entries.splice(defaultIdx, 1)
    entries.unshift(defaultEntry)
  }
  return entries.slice(0, BOT_SLOT_MAX)
}

export function orderedTelegramAccountsFromChannelConfig(channelCfg: unknown): Array<[string, Record<string, unknown>]> {
  return orderedAccountsFromChannelConfig(channelCfg)
}

export function parseDiscordChannelCsv(input: string): number[] {
  const out: number[] = []
  for (const part of input.split(',')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const n = Number(trimmed)
    if (Number.isInteger(n) && n > 0) {
      out.push(n)
    }
  }
  return Array.from(new Set(out))
}

export function parseI64ListCsvOrJsonArray(input: string, fieldName: string): number[] {
  const trimmed = input.trim()
  if (!trimmed) return []

  const parsedAsCsv = (): number[] => {
    const out: number[] = []
    for (const part of trimmed.split(',')) {
      const token = part.trim()
      if (!token) continue
      if (!/^-?\d+$/.test(token)) {
        throw new Error(`${fieldName} must be a CSV of integers or a JSON integer array`)
      }
      const n = Number(token)
      if (!Number.isSafeInteger(n)) {
        throw new Error(`${fieldName} contains an out-of-range integer`)
      }
      out.push(n)
    }
    return Array.from(new Set(out))
  }

  if (trimmed.startsWith('[')) {
    let parsed: unknown
    try {
      parsed = JSON.parse(trimmed)
    } catch (e) {
      throw new Error(`${fieldName} must be valid JSON array: ${e instanceof Error ? e.message : String(e)}`)
    }
    if (!Array.isArray(parsed)) {
      throw new Error(`${fieldName} must be a JSON array when using JSON format`)
    }
    const out: number[] = []
    for (const item of parsed) {
      if (typeof item !== 'number' || !Number.isSafeInteger(item)) {
        throw new Error(`${fieldName} JSON array must contain integers only`)
      }
      out.push(item)
    }
    return Array.from(new Set(out))
  }

  return parsedAsCsv()
}

export function parseStringListInput(input: string): string[] {
  const trimmed = input.trim()
  if (!trimmed) return []
  if (trimmed.startsWith('[')) {
    let parsed: unknown
    try {
      parsed = JSON.parse(trimmed)
    } catch (e) {
      throw new Error(`a2a_shared_tokens must be valid JSON array: ${e instanceof Error ? e.message : String(e)}`)
    }
    if (!Array.isArray(parsed)) {
      throw new Error('a2a_shared_tokens must be a JSON array when using JSON format')
    }
    return Array.from(
      new Set(
        parsed
          .map((item) => String(item || '').trim())
          .filter(Boolean),
      ),
    )
  }
  return Array.from(new Set(trimmed.split(',').map((item) => item.trim()).filter(Boolean)))
}

export function peersFromConfigValue(value: unknown): A2APeerDraft[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  return Object.entries(value as Record<string, unknown>)
    .map(([name, raw]) => {
      const peer = (raw && typeof raw === 'object' && !Array.isArray(raw))
        ? (raw as Record<string, unknown>)
        : {}
      const bearer = String(peer.bearer_token || '').trim()
      return {
        name,
        enabled: peer.enabled !== false,
        base_url: String(peer.base_url || ''),
        bearer_token: '',
        has_bearer_token: Boolean(bearer),
        description: String(peer.description || ''),
        default_session_key: String(peer.default_session_key || ''),
      }
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

export function emptyA2APeer(): A2APeerDraft {
  return {
    name: '',
    enabled: true,
    base_url: '',
    bearer_token: '',
    has_bearer_token: false,
    description: '',
    default_session_key: '',
  }
}

export function parseOptionalBoolString(input: string, fieldName: string): boolean | null {
  const trimmed = input.trim().toLowerCase()
  if (!trimmed) return null
  if (trimmed === 'true' || trimmed === '1' || trimmed === 'yes') return true
  if (trimmed === 'false' || trimmed === '0' || trimmed === 'no') return false
  throw new Error(`${fieldName} must be true/false (or 1/0)`)
}

export function parseOptionalU64String(input: string, fieldName: string): number | null {
  const trimmed = input.trim()
  if (!trimmed) return null
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`${fieldName} must be a non-negative integer`)
  }
  const parsed = Number(trimmed)
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${fieldName} must be a safe integer`)
  }
  return parsed
}

export function dynamicFieldDraftValue(raw: unknown, valueType: 'string' | 'bool' | 'number' = 'string'): string {
  if (valueType === 'bool') {
    if (typeof raw === 'boolean') return raw ? 'true' : 'false'
    const text = String(raw || '').trim().toLowerCase()
    if (!text) return ''
    if (text === 'true' || text === '1' || text === 'yes') return 'true'
    if (text === 'false' || text === '0' || text === 'no') return 'false'
    return String(raw || '')
  }
  if (valueType === 'number') {
    if (typeof raw === 'number' && Number.isFinite(raw)) return String(Math.trunc(raw))
    const text = String(raw || '').trim()
    if (!text) return ''
    return text
  }
  return String(raw || '')
}

export function normalizeWorkingDirIsolation(value: unknown): 'chat' | 'shared' {
  const normalized = String(value || '').trim().toLowerCase()
  return normalized === 'shared' ? 'shared' : 'chat'
}
