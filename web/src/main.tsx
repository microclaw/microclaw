import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import type { ReadonlyJSONObject, ReadonlyJSONValue } from 'assistant-stream/utils'
import {
  AssistantRuntimeProvider,
  MessagePrimitive,
  useMessage,
  useLocalRuntime,
  type ChatModelAdapter,
  type ChatModelRunOptions,
  type ChatModelRunResult,
  type ThreadMessageLike,
  type ToolCallMessagePartProps,
} from '@assistant-ui/react'
import {
  AssistantActionBar,
  AssistantMessage,
  BranchPicker,
  Thread,
  UserActionBar,
  UserMessage,
  makeMarkdownText,
} from '@assistant-ui/react-ui'
import {
  Button,
  Badge,
  Callout,
  Card,
  Dialog,
  Flex,
  Heading,
  Separator,
  Select,
  Switch,
  Tabs,
  Text,
  TextField,
  Theme,
} from '@radix-ui/themes'
import '@radix-ui/themes/styles.css'
import '@assistant-ui/react-ui/styles/index.css'
import './styles.css'
import { SessionSidebar } from './components/session-sidebar'
import { UsagePanel, type InjectionLogPoint, type MemoryObservability, type ReflectorRunPoint } from './components/usage-panel'
import type { SessionItem } from './types'

type ThinkExtraction = {
  visibleText: string
  thinkSegments: string[]
}

function extractThinkSegments(text: string): ThinkExtraction {
  if (!text) return { visibleText: '', thinkSegments: [] }

  const thinkSegments: string[] = []
  let visibleText = ''
  let index = 0

  while (index < text.length) {
    const start = text.indexOf('<think>', index)
    if (start < 0) {
      visibleText += text.slice(index)
      break
    }

    visibleText += text.slice(index, start)
    const contentStart = start + '<think>'.length
    const end = text.indexOf('</think>', contentStart)

    if (end < 0) {
      const tail = text.slice(contentStart).trim()
      if (tail) thinkSegments.push(tail)
      break
    }

    const segment = text.slice(contentStart, end).trim()
    if (segment) thinkSegments.push(segment)
    index = end + '</think>'.length
  }

  return { visibleText, thinkSegments }
}

function collectThinkText(parts: readonly { type: string; text?: string }[] | undefined): string {
  if (!Array.isArray(parts)) return ''
  const segments: string[] = []
  for (const part of parts) {
    if (part.type !== 'text' || typeof part.text !== 'string') continue
    const extracted = extractThinkSegments(part.text)
    if (extracted.thinkSegments.length > 0) segments.push(...extracted.thinkSegments)
  }
  return segments.join('\n\n')
}

type ConfigPayload = Record<string, unknown>

type StreamEvent = {
  event: string
  payload: Record<string, unknown>
}

type AuthStatusResponse = {
  ok?: boolean
  authenticated?: boolean
  has_password?: boolean
  using_default_password?: boolean
}

type HealthResponse = {
  version?: string
}

type BackendMessage = {
  id?: string
  sender_name?: string
  content?: string
  is_from_bot?: boolean
  timestamp?: string
}

type ConfigWarning = {
  code?: string
  severity?: string
  message?: string
}

type ExecutionPolicyItem = {
  tool?: string
  risk?: string
  policy?: string
}

type MountAllowlistStatus = {
  path?: string
  exists?: boolean
  has_entries?: boolean
}

type SecurityPosture = {
  sandbox_mode?: 'off' | 'all' | string
  sandbox_runtime_available?: boolean
  sandbox_backend?: string
  sandbox_require_runtime?: boolean
  execution_policies?: ExecutionPolicyItem[]
  mount_allowlist?: MountAllowlistStatus | null
}

type ConfigSelfCheck = {
  ok?: boolean
  risk_level?: 'none' | 'medium' | 'high' | string
  warning_count?: number
  warnings?: ConfigWarning[]
  security_posture?: SecurityPosture
}

const DOCS_BASE = 'https://microclaw.ai/docs'

function warningDocUrl(code?: string): string {
  switch (code) {
    case 'sandbox_disabled':
    case 'sandbox_runtime_unavailable':
    case 'sandbox_mount_allowlist_missing':
      return `${DOCS_BASE}/configuration#sandbox`
    case 'auth_password_not_configured':
    case 'legacy_auth_token_enabled':
    case 'web_host_not_loopback':
      return `${DOCS_BASE}/permissions`
    case 'web_rate_limit_too_high':
    case 'web_inflight_limit_too_high':
    case 'web_rate_window_too_small_for_limit':
    case 'web_session_idle_ttl_too_low':
      return `${DOCS_BASE}/configuration#web`
    case 'hooks_max_input_bytes_too_high':
    case 'hooks_max_output_bytes_too_high':
      return `${DOCS_BASE}/hooks`
    case 'otlp_enabled_without_endpoint':
    case 'otlp_queue_capacity_low':
    case 'otlp_retry_attempts_too_low':
      return `${DOCS_BASE}/observability`
    default:
      return `${DOCS_BASE}/configuration`
  }
}

type ToolStartPayload = {
  tool_use_id: string
  name: string
  input?: unknown
}

type ToolResultPayload = {
  tool_use_id: string
  name: string
  is_error?: boolean
  output?: unknown
  duration_ms?: number
  bytes?: number
  status_code?: number
  error_type?: string
}

type Appearance = 'dark' | 'light'
type UiTheme =
  | 'green'
  | 'blue'
  | 'slate'
  | 'amber'
  | 'violet'
  | 'rose'
  | 'cyan'
  | 'teal'
  | 'orange'
  | 'indigo'

const PROVIDER_SUGGESTIONS = [
  'openai',
  'openai-codex',
  'ollama',
  'openrouter',
  'anthropic',
  'google',
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
  'huggingface',
  'together',
  'custom',
]

const MODEL_OPTIONS: Record<string, string[]> = {
  anthropic: ['claude-sonnet-4-5-20250929', 'claude-opus-4-1-20250805', 'claude-3-7-sonnet-latest'],
  openai: ['gpt-5.2'],
  'openai-codex': ['gpt-5.3-codex'],
  ollama: ['llama3.2', 'qwen2.5', 'deepseek-r1'],
  openrouter: ['openai/gpt-5', 'anthropic/claude-sonnet-4-5', 'google/gemini-2.5-pro'],
  deepseek: ['deepseek-chat', 'deepseek-reasoner'],
  google: ['gemini-2.5-pro', 'gemini-2.5-flash'],
}

const DEFAULT_CONFIG_VALUES = {
  llm_provider: 'anthropic',
  working_dir_isolation: 'chat',
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
}

// ---------------------------------------------------------------------------
// Declarative dynamic-channel definitions for the Settings panel.
// To add a new channel, just append an entry here — no other UI code changes.
// ---------------------------------------------------------------------------
interface DynChannelField {
  /** YAML key inside channels.<name>, e.g. "bot_token" */
  yamlKey: string
  /** Label shown in the settings panel */
  label: string
  /** Input placeholder */
  placeholder: string
  /** Description shown in ConfigFieldCard */
  description: string
  /** If true, field value is a secret (not pre-filled from server config) */
  secret: boolean
}
interface DynChannelDef {
  /** Channel name, e.g. "slack" */
  name: string
  /** Display title for the tab header */
  title: string
  /** Emoji icon for the tab trigger */
  icon: string
  /** Setup steps shown in ConfigStepsCard */
  steps: string[]
  /** Hint text below the steps */
  hint: string
  /** Config fields */
  fields: DynChannelField[]
}

const DYNAMIC_CHANNELS: DynChannelDef[] = [
  {
    name: 'slack',
    title: 'Slack',
    icon: '🔗',
    steps: [
      'Go to api.slack.com/apps and create a new app.',
      'Enable Socket Mode and create an app-level token (xapp-).',
      'Add bot token scopes: chat:write, channels:history, groups:history, im:history, mpim:history, app_mentions:read.',
      'Install to workspace and copy the Bot User OAuth Token (xoxb-).',
      'Enable Event Subscriptions and subscribe to: message.channels, message.groups, message.im, message.mpim, app_mention.',
    ],
    hint: 'Required: bot token and app token. Leave tokens blank to keep current secrets unchanged.',
    fields: [
      { yamlKey: 'bot_token', label: 'slack_bot_token', placeholder: 'xoxb-...', description: 'Bot User OAuth Token (xoxb-) for sending messages. Leave blank to keep current secret unchanged.', secret: true },
      { yamlKey: 'app_token', label: 'slack_app_token', placeholder: 'xapp-...', description: 'App-level token (xapp-) for Socket Mode connection. Leave blank to keep current secret unchanged.', secret: true },
      { yamlKey: 'bot_username', label: 'slack_bot_username', placeholder: 'slack_bot_name', description: 'Optional Slack-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'slack_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional Slack bot model override for this account.', secret: false },
    ],
  },
  {
    name: 'feishu',
    title: 'Feishu / Lark',
    icon: '🐦',
    steps: [
      'Go to Feishu Open Platform (or Lark Developer for international) and create a custom app.',
      'Copy the App ID and App Secret from Credentials.',
      'Add permissions: im:message, im:message:send_as_bot, im:resource.',
      'Enable Long Connection mode (recommended) or configure a webhook URL.',
      'Subscribe to event: im.message.receive_v1.',
    ],
    hint: 'Required: App ID and App Secret. Domain defaults to "feishu" (China); use "lark" for international.',
    fields: [
      { yamlKey: 'app_id', label: 'feishu_app_id', placeholder: 'cli_xxx', description: 'App ID from Feishu Open Platform credentials.', secret: false },
      { yamlKey: 'app_secret', label: 'feishu_app_secret', placeholder: 'xxx', description: 'App Secret from Feishu Open Platform. Leave blank to keep current secret unchanged.', secret: true },
      { yamlKey: 'domain', label: 'feishu_domain', placeholder: 'feishu', description: 'Use "feishu" for China, "lark" for international, or a custom base URL.', secret: false },
      { yamlKey: 'bot_username', label: 'feishu_bot_username', placeholder: 'feishu_bot_name', description: 'Optional Feishu-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'feishu_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional Feishu bot model override for this account.', secret: false },
    ],
  },
  {
    name: 'matrix',
    title: 'Matrix',
    icon: '🧩',
    steps: [
      'Prepare a Matrix bot account on your homeserver.',
      'Get homeserver URL, bot user ID, and access token.',
      'Invite the bot to target rooms/chats.',
    ],
    hint: 'Required: homeserver_url, access_token, bot_user_id.',
    fields: [
      { yamlKey: 'homeserver_url', label: 'matrix_homeserver_url', placeholder: 'https://matrix.org', description: 'Matrix homeserver URL.', secret: false },
      { yamlKey: 'access_token', label: 'matrix_access_token', placeholder: 'syt_xxx', description: 'Matrix access token for the bot account.', secret: true },
      { yamlKey: 'bot_user_id', label: 'matrix_bot_user_id', placeholder: '@bot:example.org', description: 'Matrix bot user ID.', secret: false },
      { yamlKey: 'bot_username', label: 'matrix_bot_username', placeholder: 'matrix_bot_name', description: 'Optional Matrix-specific bot username override.', secret: false },
    ],
  },
  {
    name: 'whatsapp',
    title: 'WhatsApp',
    icon: '🟢',
    steps: [
      'Create WhatsApp Cloud API app in Meta Developer dashboard.',
      'Copy access token and phone number ID.',
      'Configure webhook and verify token if needed.',
    ],
    hint: 'Required: access_token and phone_number_id.',
    fields: [
      { yamlKey: 'access_token', label: 'whatsapp_access_token', placeholder: 'EAAG...', description: 'WhatsApp Cloud API access token.', secret: true },
      { yamlKey: 'phone_number_id', label: 'whatsapp_phone_number_id', placeholder: '1234567890', description: 'WhatsApp phone number ID.', secret: false },
      { yamlKey: 'webhook_verify_token', label: 'whatsapp_webhook_verify_token', placeholder: 'verify-token', description: 'Optional webhook verify token.', secret: true },
      { yamlKey: 'api_version', label: 'whatsapp_api_version', placeholder: 'v21.0', description: 'Graph API version.', secret: false },
      { yamlKey: 'webhook_path', label: 'whatsapp_webhook_path', placeholder: '/whatsapp/webhook', description: 'Webhook path.', secret: false },
      { yamlKey: 'allowed_user_ids', label: 'whatsapp_allowed_user_ids', placeholder: 'user1,user2', description: 'Optional allowed user IDs csv.', secret: false },
      { yamlKey: 'bot_username', label: 'whatsapp_bot_username', placeholder: 'whatsapp_bot_name', description: 'Optional WhatsApp-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'whatsapp_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional WhatsApp bot model override for this account.', secret: false },
    ],
  },
  {
    name: 'imessage',
    title: 'iMessage',
    icon: '💬',
    steps: [
      'Run on macOS with osascript support.',
      'Choose service type and connect sender workflow.',
    ],
    hint: 'Default service is iMessage.',
    fields: [
      { yamlKey: 'service', label: 'imessage_service', placeholder: 'iMessage', description: 'Service type (iMessage/SMS relay setup dependent).', secret: false },
      { yamlKey: 'bot_username', label: 'imessage_bot_username', placeholder: 'imessage_bot_name', description: 'Optional iMessage-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'imessage_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional iMessage bot model override for this account.', secret: false },
    ],
  },
  {
    name: 'email',
    title: 'Email',
    icon: '✉️',
    steps: [
      'Set sender address and sendmail path.',
      'Expose webhook endpoint if receiving inbound events.',
      'Optionally restrict allowed senders.',
    ],
    hint: 'Required: from_address.',
    fields: [
      { yamlKey: 'from_address', label: 'email_from_address', placeholder: 'bot@example.com', description: 'Email sender address.', secret: false },
      { yamlKey: 'sendmail_path', label: 'email_sendmail_path', placeholder: '/usr/sbin/sendmail', description: 'sendmail binary path.', secret: false },
      { yamlKey: 'webhook_path', label: 'email_webhook_path', placeholder: '/email/webhook', description: 'Inbound webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'email_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_senders', label: 'email_allowed_senders', placeholder: 'a@example.com,b@example.com', description: 'Optional allowed sender list csv.', secret: false },
      { yamlKey: 'bot_username', label: 'email_bot_username', placeholder: 'email_bot_name', description: 'Optional Email-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'email_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional Email bot model override for this account.', secret: false },
    ],
  },
  {
    name: 'nostr',
    title: 'Nostr',
    icon: '🟣',
    steps: [
      'Configure publish command used to send outgoing replies.',
      'Configure webhook endpoint for incoming events.',
    ],
    hint: 'Recommended: set publish_command and webhook token.',
    fields: [
      { yamlKey: 'publish_command', label: 'nostr_publish_command', placeholder: 'nostril publish ...', description: 'Command used to publish messages.', secret: false },
      { yamlKey: 'webhook_path', label: 'nostr_webhook_path', placeholder: '/nostr/events', description: 'Webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'nostr_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_pubkeys', label: 'nostr_allowed_pubkeys', placeholder: 'npub1...,npub1...', description: 'Optional allowed pubkeys csv.', secret: false },
      { yamlKey: 'bot_username', label: 'nostr_bot_username', placeholder: 'nostr_bot_name', description: 'Optional Nostr-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'nostr_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional Nostr bot model override for this account.', secret: false },
    ],
  },
  {
    name: 'signal',
    title: 'Signal',
    icon: '🔐',
    steps: [
      'Configure send command used to send outgoing replies.',
      'Configure webhook endpoint for incoming messages.',
    ],
    hint: 'Recommended: set send_command and webhook token.',
    fields: [
      { yamlKey: 'send_command', label: 'signal_send_command', placeholder: 'signal-cli send ...', description: 'Command used to send Signal messages.', secret: false },
      { yamlKey: 'webhook_path', label: 'signal_webhook_path', placeholder: '/signal/messages', description: 'Webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'signal_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_numbers', label: 'signal_allowed_numbers', placeholder: '+15551234567,+15559876543', description: 'Optional allowed numbers csv.', secret: false },
      { yamlKey: 'bot_username', label: 'signal_bot_username', placeholder: 'signal_bot_name', description: 'Optional Signal-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'signal_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional Signal bot model override for this account.', secret: false },
    ],
  },
  {
    name: 'dingtalk',
    title: 'DingTalk',
    icon: '🟡',
    steps: [
      'Create DingTalk robot integration.',
      'Set robot webhook URL and inbound webhook route.',
    ],
    hint: 'Recommended: set robot_webhook_url and webhook token.',
    fields: [
      { yamlKey: 'robot_webhook_url', label: 'dingtalk_robot_webhook_url', placeholder: 'https://oapi.dingtalk.com/robot/send?...', description: 'DingTalk robot webhook URL.', secret: true },
      { yamlKey: 'webhook_path', label: 'dingtalk_webhook_path', placeholder: '/dingtalk/events', description: 'Webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'dingtalk_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_chat_ids', label: 'dingtalk_allowed_chat_ids', placeholder: 'chat1,chat2', description: 'Optional allowed chat IDs csv.', secret: false },
      { yamlKey: 'bot_username', label: 'dingtalk_bot_username', placeholder: 'dingtalk_bot_name', description: 'Optional DingTalk-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'dingtalk_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional DingTalk bot model override for this account.', secret: false },
    ],
  },
  {
    name: 'qq',
    title: 'QQ',
    icon: '🐧',
    steps: [
      'Configure send command used to send outgoing replies.',
      'Configure webhook endpoint for incoming messages.',
    ],
    hint: 'Recommended: set send_command and webhook token.',
    fields: [
      { yamlKey: 'send_command', label: 'qq_send_command', placeholder: 'qq-send ...', description: 'Command used to send QQ messages.', secret: false },
      { yamlKey: 'webhook_path', label: 'qq_webhook_path', placeholder: '/qq/events', description: 'Webhook path.', secret: false },
      { yamlKey: 'webhook_token', label: 'qq_webhook_token', placeholder: 'token', description: 'Optional webhook token.', secret: true },
      { yamlKey: 'allowed_user_ids', label: 'qq_allowed_user_ids', placeholder: '10001,10002', description: 'Optional allowed user IDs csv.', secret: false },
      { yamlKey: 'bot_username', label: 'qq_bot_username', placeholder: 'qq_bot_name', description: 'Optional QQ-specific bot username override.', secret: false },
      { yamlKey: 'model', label: 'qq_model', placeholder: 'claude-sonnet-4-5-20250929', description: 'Optional QQ bot model override for this account.', secret: false },
    ],
  },
]

const UI_THEME_OPTIONS: { key: UiTheme; label: string; color: string }[] = [
  { key: 'green', label: 'Green', color: '#34d399' },
  { key: 'blue', label: 'Blue', color: '#60a5fa' },
  { key: 'slate', label: 'Slate', color: '#94a3b8' },
  { key: 'amber', label: 'Amber', color: '#fbbf24' },
  { key: 'violet', label: 'Violet', color: '#a78bfa' },
  { key: 'rose', label: 'Rose', color: '#fb7185' },
  { key: 'cyan', label: 'Cyan', color: '#22d3ee' },
  { key: 'teal', label: 'Teal', color: '#2dd4bf' },
  { key: 'orange', label: 'Orange', color: '#fb923c' },
  { key: 'indigo', label: 'Indigo', color: '#818cf8' },
]

const RADIX_ACCENT_BY_THEME: Record<UiTheme, string> = {
  green: 'green',
  blue: 'blue',
  slate: 'gray',
  amber: 'amber',
  violet: 'violet',
  rose: 'ruby',
  cyan: 'cyan',
  teal: 'teal',
  orange: 'orange',
  indigo: 'indigo',
}
const BOT_SLOT_MAX = 10

function defaultModelForProvider(providerRaw: string): string {
  const provider = providerRaw.trim().toLowerCase()
  if (provider === 'anthropic') return 'claude-sonnet-4-5-20250929'
  if (provider === 'openai-codex') return 'gpt-5.3-codex'
  if (provider === 'ollama') return 'llama3.2'
  return 'gpt-5.2'
}

function normalizeAccountId(raw: unknown): string {
  const text = String(raw || '').trim()
  return text || 'main'
}

function defaultAccountIdFromChannelConfig(channelCfg: unknown): string {
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

function defaultAccountConfig(channelCfg: unknown): Record<string, unknown> {
  if (!channelCfg || typeof channelCfg !== 'object') return {}
  const cfg = channelCfg as Record<string, unknown>
  const accountId = defaultAccountIdFromChannelConfig(cfg)
  const accounts = cfg.accounts
  if (!accounts || typeof accounts !== 'object') return {}
  const account = (accounts as Record<string, unknown>)[accountId]
  return account && typeof account === 'object' ? (account as Record<string, unknown>) : {}
}

function defaultTelegramAccountIdForSlot(slot: number): string {
  return slot <= 1 ? 'main' : `bot${slot}`
}

function defaultAccountIdForSlot(slot: number): string {
  return slot <= 1 ? 'main' : `bot${slot}`
}

function normalizeBotCount(raw: unknown): number {
  const n = Number(raw)
  if (!Number.isFinite(n)) return 1
  return Math.min(BOT_SLOT_MAX, Math.max(1, Math.floor(n)))
}

function orderedAccountsFromChannelConfig(channelCfg: unknown): Array<[string, Record<string, unknown>]> {
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

function orderedTelegramAccountsFromChannelConfig(channelCfg: unknown): Array<[string, Record<string, unknown>]> {
  return orderedAccountsFromChannelConfig(channelCfg)
}

function readAppearance(): Appearance {
  const saved = localStorage.getItem('microclaw_appearance')
  return saved === 'light' ? 'light' : 'dark'
}

function saveAppearance(value: Appearance): void {
  localStorage.setItem('microclaw_appearance', value)
}

function readUiTheme(): UiTheme {
  const saved = localStorage.getItem('microclaw_ui_theme') as UiTheme | null
  return UI_THEME_OPTIONS.some((t) => t.key === saved) ? (saved as UiTheme) : 'green'
}

function saveUiTheme(value: UiTheme): void {
  localStorage.setItem('microclaw_ui_theme', value)
}

function writeSessionToUrl(sessionKey: string): void {
  if (typeof window === 'undefined') return
  const url = new URL(window.location.href)
  url.searchParams.set('session', sessionKey)
  window.history.replaceState(null, '', url.toString())
}

function readSessionFromUrl(): string {
  if (typeof window === 'undefined') return ''
  const url = new URL(window.location.href)
  return url.searchParams.get('session')?.trim() || ''
}

function pickLatestSessionKey(items: SessionItem[]): string {
  if (items.length === 0) return makeSessionKey()

  const parsed = items
    .map((item) => ({ item, ts: Date.parse(item.last_message_time || '') }))
    .filter((v) => Number.isFinite(v.ts))

  if (parsed.length > 0) {
    parsed.sort((a, b) => b.ts - a.ts)
    return parsed[0]?.item.session_key || makeSessionKey()
  }

  return items[0]?.session_key || makeSessionKey()
}

if (typeof document !== 'undefined') {
  document.documentElement.classList.toggle('dark', readAppearance() === 'dark')
  document.documentElement.setAttribute('data-ui-theme', readUiTheme())
}

function makeHeaders(options: RequestInit = {}): HeadersInit {
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> | undefined),
  }
  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }
  // Backend currently validates CSRF by scope (including some GET admin endpoints),
  // so attach token whenever present to avoid false 403 for authenticated browser sessions.
  const csrf = readCookie('mc_csrf')
  if (csrf && !hasHeader(headers, 'x-csrf-token')) {
    headers['x-csrf-token'] = csrf
  }
  return headers
}

class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function hasHeader(headers: Record<string, string>, key: string): boolean {
  const needle = key.toLowerCase()
  return Object.keys(headers).some((k) => k.toLowerCase() === needle)
}

function readCookie(name: string): string {
  if (typeof document === 'undefined') return ''
  const encodedName = `${encodeURIComponent(name)}=`
  const items = document.cookie ? document.cookie.split('; ') : []
  for (const item of items) {
    if (!item.startsWith(encodedName)) continue
    return decodeURIComponent(item.slice(encodedName.length))
  }
  return ''
}

function readBootstrapTokenFromHash(): string {
  if (typeof window === 'undefined') return ''
  const raw = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash
  const params = new URLSearchParams(raw)
  return params.get('bootstrap')?.trim() || ''
}

function clearBootstrapTokenFromHash(): void {
  if (typeof window === 'undefined') return
  const raw = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash
  const params = new URLSearchParams(raw)
  if (!params.has('bootstrap')) return
  params.delete('bootstrap')
  const next = params.toString()
  window.location.hash = next ? `#${next}` : ''
}

function generatePassword(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    const raw = crypto.randomUUID().replace(/-/g, '')
    return `mc-${raw.slice(0, 6)}-${raw.slice(6, 12)}!`
  }
  const fallback = Math.random().toString(36).slice(2, 14)
  return `mc-${fallback.slice(0, 6)}-${fallback.slice(6, 12)}!`
}

async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(path, { ...options, headers: makeHeaders(options), credentials: 'same-origin' })
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    throw new ApiError(String(data.error || data.message || `HTTP ${res.status}`), res.status)
  }
  return data as T
}

async function* parseSseFrames(
  response: Response,
  signal: AbortSignal,
): AsyncGenerator<StreamEvent, void> {
  if (!response.body) {
    throw new Error('empty stream body')
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let pending = ''
  let eventName = 'message'
  let dataLines: string[] = []

  const flush = (): StreamEvent | null => {
    if (dataLines.length === 0) return null
    const raw = dataLines.join('\n')
    dataLines = []

    let payload: Record<string, unknown> = {}
    try {
      payload = JSON.parse(raw) as Record<string, unknown>
    } catch {
      payload = { raw }
    }

    const event: StreamEvent = { event: eventName, payload }
    eventName = 'message'
    return event
  }

  const handleLine = (line: string): StreamEvent | null => {
    if (line === '') return flush()
    if (line.startsWith(':')) return null

    const sep = line.indexOf(':')
    const field = sep >= 0 ? line.slice(0, sep) : line
    let value = sep >= 0 ? line.slice(sep + 1) : ''
    if (value.startsWith(' ')) value = value.slice(1)

    if (field === 'event') eventName = value
    if (field === 'data') dataLines.push(value)

    return null
  }

  while (true) {
    if (signal.aborted) return

    const { done, value } = await reader.read()
    pending += decoder.decode(value || new Uint8Array(), { stream: !done })

    while (true) {
      const idx = pending.indexOf('\n')
      if (idx < 0) break
      let line = pending.slice(0, idx)
      pending = pending.slice(idx + 1)
      if (line.endsWith('\r')) line = line.slice(0, -1)
      const event = handleLine(line)
      if (event) yield event
    }

    if (done) {
      if (pending.length > 0) {
        let line = pending
        if (line.endsWith('\r')) line = line.slice(0, -1)
        const event = handleLine(line)
        if (event) yield event
      }
      const event = flush()
      if (event) yield event
      return
    }
  }
}

function extractLatestUserText(messages: readonly ChatModelRunOptions['messages'][number][]): string {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i]
    if (message.role !== 'user') continue

    const text = message.content
      .map((part) => {
        if (part.type === 'text') return part.text
        return ''
      })
      .join('\n')
      .trim()

    if (text.length > 0) return text
  }
  return ''
}

function mapBackendHistory(messages: BackendMessage[]): ThreadMessageLike[] {
  return messages.map((item, index) => ({
    id: item.id || `history-${index}`,
    role: item.is_from_bot ? 'assistant' : 'user',
    content: item.content || '',
    createdAt: item.timestamp ? new Date(item.timestamp) : new Date(),
  }))
}

function makeSessionKey(): string {
  return `session-${new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)}`
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return {}
}

function toJsonValue(value: unknown): ReadonlyJSONValue {
  try {
    return JSON.parse(JSON.stringify(value)) as ReadonlyJSONValue
  } catch {
    return String(value)
  }
}

function toJsonObject(value: unknown): ReadonlyJSONObject {
  const normalized = toJsonValue(value)
  if (typeof normalized === 'object' && normalized !== null && !Array.isArray(normalized)) {
    return normalized as ReadonlyJSONObject
  }
  return {}
}

function formatUnknown(value: unknown): string {
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function ToolCallCard(props: ToolCallMessagePartProps) {
  const result = asObject(props.result)
  const hasResult = Object.keys(result).length > 0
  const output = result.output
  const duration = result.duration_ms
  const bytes = result.bytes
  const statusCode = result.status_code
  const errorType = result.error_type

  return (
    <div className="tool-card">
      <div className="tool-card-head">
        <span className="tool-card-name">{props.toolName}</span>
        <span className={`tool-card-state ${hasResult ? (props.isError ? 'error' : 'ok') : 'running'}`}>
          {hasResult ? (props.isError ? 'error' : 'done') : 'running'}
        </span>
      </div>
      {Object.keys(props.args || {}).length > 0 ? (
        <pre className="tool-card-pre">{JSON.stringify(props.args, null, 2)}</pre>
      ) : null}
      {hasResult ? (
        <div className="tool-card-meta">
          {typeof duration === 'number' ? <span>{duration}ms</span> : null}
          {typeof bytes === 'number' ? <span>{bytes}b</span> : null}
          {typeof statusCode === 'number' ? <span>HTTP {statusCode}</span> : null}
          {typeof errorType === 'string' && errorType ? <span>{errorType}</span> : null}
        </div>
      ) : null}
      {output !== undefined ? <pre className="tool-card-pre">{formatUnknown(output)}</pre> : null}
    </div>
  )
}

function MessageTimestamp({ align }: { align: 'left' | 'right' }) {
  const createdAt = useMessage((m) => m.createdAt)
  const formatted = createdAt ? createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
  return (
    <div className={align === 'right' ? 'mc-msg-time mc-msg-time-right' : 'mc-msg-time'}>
      {formatted}
    </div>
  )
}

function CustomAssistantMessage() {
  const thinkText = useMessage((m) => collectThinkText(m.content as readonly { type: string; text?: string }[] | undefined))

  const hasRenderableContent = useMessage((m) =>
    Array.isArray(m.content)
      ? m.content.some((part) => {
          if (part.type === 'text') return Boolean(extractThinkSegments(part.text ?? '').visibleText.trim())
          return part.type === 'tool-call'
        })
      : false,
  )

  return (
    <AssistantMessage.Root>
      <AssistantMessage.Avatar />
      {hasRenderableContent ? (
        <AssistantMessage.Content />
      ) : (
        <div className="mc-assistant-placeholder" aria-live="polite">
          <span className="mc-assistant-placeholder-dot" />
          <span className="mc-assistant-placeholder-dot" />
          <span className="mc-assistant-placeholder-dot" />
          <span className="mc-assistant-placeholder-text">Thinking</span>
        </div>
      )}
      {thinkText.trim() ? (
        <details className="mc-think-details">
          <summary>View thinking</summary>
          <pre className="mc-think-content">{thinkText}</pre>
        </details>
      ) : null}
      <BranchPicker />
      <AssistantActionBar />
      <MessageTimestamp align="left" />
    </AssistantMessage.Root>
  )
}

function CustomUserMessage() {
  return (
    <UserMessage.Root>
      <UserMessage.Attachments />
      <MessagePrimitive.If hasContent>
        <UserActionBar />
        <div className="mc-user-content-wrap">
          <UserMessage.Content />
          <MessageTimestamp align="right" />
        </div>
      </MessagePrimitive.If>
      <BranchPicker />
    </UserMessage.Root>
  )
}

type ThreadPaneProps = {
  adapter: ChatModelAdapter
  initialMessages: ThreadMessageLike[]
  runtimeKey: string
}

function ThreadPane({ adapter, initialMessages, runtimeKey }: ThreadPaneProps) {
  const MarkdownText = makeMarkdownText({
    preprocess: (text) => extractThinkSegments(text).visibleText,
  })
  const runtime = useLocalRuntime(adapter, {
    initialMessages,
    maxSteps: 100,
  })

  return (
    <AssistantRuntimeProvider key={runtimeKey} runtime={runtime}>
      <div className="aui-root h-full min-h-0">
        <Thread
          assistantMessage={{
            allowCopy: true,
            allowReload: false,
            allowSpeak: false,
            allowFeedbackNegative: false,
            allowFeedbackPositive: false,
            components: {
              Text: MarkdownText,
              ToolFallback: ToolCallCard,
            },
          }}
          userMessage={{ allowEdit: false }}
          composer={{ allowAttachments: false }}
          components={{
            AssistantMessage: CustomAssistantMessage,
            UserMessage: CustomUserMessage,
          }}
          strings={{
            composer: {
              input: { placeholder: 'Message MicroClaw...' },
            },
          }}
          assistantAvatar={{ fallback: 'M' }}
        />
      </div>
    </AssistantRuntimeProvider>
  )
}

function parseDiscordChannelCsv(input: string): number[] {
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

function parseI64ListCsvOrJsonArray(input: string, fieldName: string): number[] {
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

function normalizeWorkingDirIsolation(value: unknown): 'chat' | 'shared' {
  const normalized = String(value || '').trim().toLowerCase()
  return normalized === 'shared' ? 'shared' : 'chat'
}

type ConfigFieldCardProps = {
  label: string
  description: React.ReactNode
  children: React.ReactNode
}

function ConfigFieldCard({ label, description, children }: ConfigFieldCardProps) {
  return (
    <Card className="p-3">
      <Text size="2" weight="medium">{label}</Text>
      <Text size="1" color="gray" className="mt-1 block">{description}</Text>
      <div className="mt-2">{children}</div>
    </Card>
  )
}

type ConfigToggleCardProps = {
  label: string
  description?: React.ReactNode
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  className: string
  style?: React.CSSProperties
}

function ConfigToggleCard({ label, description, checked, onCheckedChange, className, style }: ConfigToggleCardProps) {
  return (
    <div className={className} style={style}>
      <Flex justify="between" align="center">
        <div>
          <Text size="2">{label}</Text>
          {description ? (
            <Text size="1" color="gray" className="mt-1 block">
              {description}
            </Text>
          ) : null}
        </div>
        <Switch checked={checked} onCheckedChange={onCheckedChange} />
      </Flex>
    </div>
  )
}

type ConfigStepsCardProps = {
  title?: string
  steps: React.ReactNode[]
}

function ConfigStepsCard({ title = 'Setup Steps', steps }: ConfigStepsCardProps) {
  return (
    <Card className="mt-3 p-3">
      <Text size="2" weight="bold">{title}</Text>
      <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-slate-400">
        {steps.map((step, index) => (
          <li key={index}>{step}</li>
        ))}
      </ol>
    </Card>
  )
}

function App() {
  const [appearance, setAppearance] = useState<Appearance>(readAppearance())
  const [uiTheme, setUiTheme] = useState<UiTheme>(readUiTheme())
  const [sessions, setSessions] = useState<SessionItem[]>([])
  const [extraSessions, setExtraSessions] = useState<SessionItem[]>([])
  const [sessionKey, setSessionKey] = useState<string>(() => makeSessionKey())
  const [historySeed, setHistorySeed] = useState<ThreadMessageLike[]>([])
  const [historyCountBySession, setHistoryCountBySession] = useState<Record<string, number>>({})
  const [runtimeNonce, setRuntimeNonce] = useState<number>(0)
  const [error, setError] = useState<string>('')
  const [statusText, setStatusText] = useState<string>('Idle')
  const [replayNotice, setReplayNotice] = useState<string>('')
  const [sending, setSending] = useState<boolean>(false)
  const [configOpen, setConfigOpen] = useState<boolean>(false)
  const [config, setConfig] = useState<ConfigPayload | null>(null)
  const [configDraft, setConfigDraft] = useState<Record<string, unknown>>({})
  const [configSelfCheck, setConfigSelfCheck] = useState<ConfigSelfCheck | null>(null)
  const [configSelfCheckLoading, setConfigSelfCheckLoading] = useState<boolean>(false)
  const [configSelfCheckError, setConfigSelfCheckError] = useState<string>('')
  const [saveStatus, setSaveStatus] = useState<string>('')
  const [usageOpen, setUsageOpen] = useState<boolean>(false)
  const [usageLoading, setUsageLoading] = useState<boolean>(false)
  const [usageReport, setUsageReport] = useState<string>('')
  const [usageMemory, setUsageMemory] = useState<MemoryObservability | null>(null)
  const [usageReflectorRuns, setUsageReflectorRuns] = useState<ReflectorRunPoint[]>([])
  const [usageInjectionLogs, setUsageInjectionLogs] = useState<InjectionLogPoint[]>([])
  const [usageError, setUsageError] = useState<string>('')
  const [usageSession, setUsageSession] = useState<string>('')
  const [authReady, setAuthReady] = useState<boolean>(false)
  const [authHasPassword, setAuthHasPassword] = useState<boolean>(false)
  const [authAuthenticated, setAuthAuthenticated] = useState<boolean>(false)
  const [authUsingDefaultPassword, setAuthUsingDefaultPassword] = useState<boolean>(false)
  const [authMessage, setAuthMessage] = useState<string>('')
  const [loginPassword, setLoginPassword] = useState<string>('')
  const [bootstrapToken, setBootstrapToken] = useState<string>(() => readBootstrapTokenFromHash())
  const [bootstrapPassword, setBootstrapPassword] = useState<string>('')
  const [bootstrapConfirm, setBootstrapConfirm] = useState<string>('')
  const [generatedPasswordPreview, setGeneratedPasswordPreview] = useState<string>('')
  const [authBusy, setAuthBusy] = useState<boolean>(false)
  const [passwordPromptOpen, setPasswordPromptOpen] = useState<boolean>(false)
  const [passwordPromptMessage, setPasswordPromptMessage] = useState<string>('')
  const [passwordPromptBusy, setPasswordPromptBusy] = useState<boolean>(false)
  const [newPassword, setNewPassword] = useState<string>('')
  const [newPasswordConfirm, setNewPasswordConfirm] = useState<string>('')
  const [appVersion, setAppVersion] = useState<string>('')

  const sessionItems = useMemo(() => {
    const map = new Map<string, SessionItem>()

    for (const item of [...extraSessions, ...sessions]) {
      if (!map.has(item.session_key)) {
        map.set(item.session_key, item)
      }
    }

    const selectedMissingFromStoredList = !map.has(sessionKey)
    if (selectedMissingFromStoredList && !sessionKey.startsWith('chat:')) {
      map.set(sessionKey, {
        session_key: sessionKey,
        label: sessionKey,
        chat_id: 0,
        chat_type: 'web',
      })
    }

    if (map.size === 0) {
      const key = makeSessionKey()
      map.set(key, {
        session_key: key,
        label: key,
        chat_id: 0,
        chat_type: 'web',
      })
    }

    const items = Array.from(map.values())
    const selectedSynthetic = selectedMissingFromStoredList && !sessionKey.startsWith('chat:')
    items.sort((a, b) => {
      if (selectedSynthetic) {
        if (a.session_key === sessionKey) return -1
        if (b.session_key === sessionKey) return 1
      }

      const ta = Date.parse(a.last_message_time || '')
      const tb = Date.parse(b.last_message_time || '')
      const aOk = Number.isFinite(ta)
      const bOk = Number.isFinite(tb)
      if (aOk && bOk) {
        if (tb !== ta) return tb - ta
      } else if (aOk !== bOk) {
        return aOk ? -1 : 1
      }

      return a.label.localeCompare(b.label)
    })
    return items
  }, [extraSessions, sessions, sessionKey])

  const selectedSession = useMemo(
    () => sessionItems.find((item) => item.session_key === sessionKey),
    [sessionItems, sessionKey],
  )

  const selectedSessionLabel = selectedSession?.label || sessionKey
  const selectedSessionReadOnly = Boolean(selectedSession && selectedSession.chat_type !== 'web')

  function isUnauthorizedError(err: unknown): boolean {
    return err instanceof ApiError && err.status === 401
  }

  function isForbiddenError(err: unknown): boolean {
    return err instanceof ApiError && err.status === 403
  }

  function lockForAuth(message = 'Authentication required. Please sign in.'): void {
    setAuthAuthenticated(false)
    setAuthMessage(message)
    setError(message)
  }

  async function refreshAuthStatus(): Promise<AuthStatusResponse> {
    try {
      const data = await api<AuthStatusResponse>('/api/auth/status')
      const hasPassword = Boolean(data.has_password)
      const authenticated = Boolean(data.authenticated)
      const usingDefaultPassword = Boolean(data.using_default_password)
      setAuthHasPassword(hasPassword)
      setAuthAuthenticated(authenticated)
      setAuthUsingDefaultPassword(usingDefaultPassword)
      setAuthReady(true)
      if (authenticated) {
        setAuthMessage('')
        setError('')
      }
      if (authenticated && usingDefaultPassword) {
        setPasswordPromptOpen(true)
      }
      if (!usingDefaultPassword) {
        setPasswordPromptOpen(false)
      }
      return data
    } catch (e) {
      setAuthReady(true)
      throw e
    }
  }

  async function loadAppVersion(): Promise<void> {
    try {
      const data = await api<HealthResponse>('/api/health')
      setAppVersion(String(data.version || '').trim())
    } catch {
      // `/api/health` requires read scope; keep placeholder when unavailable.
    }
  }

  async function loadInitialConversation(): Promise<void> {
    setError('')
    const data = await api<{ sessions?: SessionItem[] }>('/api/sessions')
    const loaded = Array.isArray(data.sessions) ? data.sessions : []
    setSessions(loaded)

    const latestSession = pickLatestSessionKey(loaded)
    const preferredSession = readSessionFromUrl()
    const preferredExists = preferredSession
      ? loaded.some((item) => item.session_key === preferredSession)
      : false
    const initialSession = preferredExists
      ? preferredSession
      : latestSession

    setSessionKey(initialSession)
    writeSessionToUrl(initialSession)
    const initialExists = loaded.some((item) => item.session_key === initialSession)
    if (initialExists) {
      await loadHistory(initialSession)
    } else {
      setHistorySeed([])
      setHistoryCountBySession((prev) => ({ ...prev, [initialSession]: 0 }))
      setRuntimeNonce((x) => x + 1)
      setError('')
    }
  }

  async function loadSessions(): Promise<void> {
    try {
      const data = await api<{ sessions?: SessionItem[] }>('/api/sessions')
      setSessions(Array.isArray(data.sessions) ? data.sessions : [])
    } catch (e) {
      if (isUnauthorizedError(e)) {
        lockForAuth()
        return
      }
      throw e
    }
  }

  async function loadHistory(target = sessionKey): Promise<void> {
    try {
      const query = new URLSearchParams({ session_key: target, limit: '200' })
      const data = await api<{ messages?: BackendMessage[] }>(`/api/history?${query.toString()}`)
      const rawMessages = Array.isArray(data.messages) ? data.messages : []
      const mapped = mapBackendHistory(rawMessages)
      setHistorySeed(mapped)
      setHistoryCountBySession((prev) => ({ ...prev, [target]: rawMessages.length }))
      setRuntimeNonce((x) => x + 1)
      setError('')
    } catch (e) {
      if (isUnauthorizedError(e)) {
        lockForAuth()
        return
      }
      if (e instanceof ApiError && e.status === 404) {
        setHistorySeed([])
        setHistoryCountBySession((prev) => ({ ...prev, [target]: 0 }))
        setRuntimeNonce((x) => x + 1)
        setError('')
        return
      }
      throw e
    }
  }

  async function submitLogin(password: string): Promise<void> {
    const normalized = password.trim()
    if (!normalized) {
      setAuthMessage('Please enter your password.')
      return
    }
    setAuthBusy(true)
    setAuthMessage('')
    try {
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ password: normalized }),
      })
      setLoginPassword('')
      await refreshAuthStatus()
      await loadInitialConversation()
      setStatusText('Authenticated')
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.status === 401) {
          setAuthMessage('Password is incorrect. Please try again or reset with `microclaw web password-generate`.')
          return
        }
        if (e.status === 429) {
          setAuthMessage('Too many login attempts. Please wait and retry.')
          return
        }
      }
      setAuthMessage(e instanceof Error ? e.message : String(e))
    } finally {
      setAuthBusy(false)
    }
  }

  async function submitBootstrapPassword(): Promise<void> {
    const token = bootstrapToken.trim()
    const password = bootstrapPassword.trim()
    const confirm = bootstrapConfirm.trim()

    if (!token) {
      setAuthMessage('Bootstrap token is required.')
      return
    }
    if (password.length < 8) {
      setAuthMessage('Password must be at least 8 characters.')
      return
    }
    if (password !== confirm) {
      setAuthMessage('Passwords do not match.')
      return
    }

    setAuthBusy(true)
    setAuthMessage('')
    try {
      await api('/api/auth/password', {
        method: 'POST',
        headers: { 'x-bootstrap-token': token },
        body: JSON.stringify({ password }),
      })
      clearBootstrapTokenFromHash()
      await submitLogin(password)
      setBootstrapPassword('')
      setBootstrapConfirm('')
      setGeneratedPasswordPreview('')
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setAuthMessage('Bootstrap token is invalid or expired. Please copy the latest token from startup logs.')
        return
      }
      setAuthMessage(e instanceof Error ? e.message : String(e))
    } finally {
      setAuthBusy(false)
    }
  }

  async function submitPasswordUpdate(): Promise<void> {
    const password = newPassword.trim()
    const confirm = newPasswordConfirm.trim()
    if (password.length < 8) {
      setPasswordPromptMessage('Password must be at least 8 characters.')
      return
    }
    if (password !== confirm) {
      setPasswordPromptMessage('Passwords do not match.')
      return
    }
    setPasswordPromptBusy(true)
    setPasswordPromptMessage('')
    try {
      await api('/api/auth/password', {
        method: 'POST',
        body: JSON.stringify({ password }),
      })
      setNewPassword('')
      setNewPasswordConfirm('')
      await refreshAuthStatus()
      setPasswordPromptOpen(false)
      setStatusText('Password updated')
    } catch (e) {
      setPasswordPromptMessage(e instanceof Error ? e.message : String(e))
    } finally {
      setPasswordPromptBusy(false)
    }
  }

  async function logout(): Promise<void> {
    setStatusText('Signing out...')
    setError('')
    try {
      await api('/api/auth/logout', { method: 'POST' })
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSessions([])
      setExtraSessions([])
      setHistorySeed([])
      setHistoryCountBySession({})
      setRuntimeNonce((x) => x + 1)
      setAppVersion('')
      setSessionKey(makeSessionKey())
      setUsageOpen(false)
      setConfigOpen(false)
      await refreshAuthStatus().catch(() => {
        setAuthAuthenticated(false)
      })
      setAuthMessage('Signed out. Please sign in again.')
      setStatusText('Signed out')
    }
  }

  const adapter = useMemo<ChatModelAdapter>(
    () => ({
      run: async function* (options): AsyncGenerator<ChatModelRunResult, void> {
        const userText = extractLatestUserText(options.messages)
        if (!userText) return

        setSending(true)
        setStatusText('Sending...')
        setReplayNotice('')
        setError('')

        try {
          if (selectedSessionReadOnly) {
            setStatusText('Read-only channel')
            throw new Error('This channel is read-only in Web UI. Send messages from the original channel.')
          }

          const sendResponse = await api<{ run_id?: string }>('/api/send_stream', {
            method: 'POST',
            body: JSON.stringify({
              session_key: sessionKey,
              sender_name: 'web-user',
              message: userText,
            }),
            signal: options.abortSignal,
          })

          const runId = sendResponse.run_id
          if (!runId) {
            throw new Error('missing run_id')
          }

          const query = new URLSearchParams({ run_id: runId })
          const streamResponse = await fetch(`/api/stream?${query.toString()}`, {
            method: 'GET',
            headers: makeHeaders(),
            credentials: 'same-origin',
            cache: 'no-store',
            signal: options.abortSignal,
          })

          if (!streamResponse.ok) {
            const text = await streamResponse.text().catch(() => '')
            throw new ApiError(text || `HTTP ${streamResponse.status}`, streamResponse.status)
          }

          let assistantText = ''
          const toolState = new Map<
            string,
            {
              name: string
              args: ReadonlyJSONObject
              result?: ReadonlyJSONValue
              isError?: boolean
            }
          >()

          const makeContent = () => {
            const toolParts = Array.from(toolState.entries()).map(([toolCallId, tool]) => ({
              type: 'tool-call' as const,
              toolCallId,
              toolName: tool.name,
              args: tool.args,
              argsText: JSON.stringify(tool.args),
              ...(tool.result ? { result: tool.result } : {}),
              ...(tool.isError !== undefined ? { isError: tool.isError } : {}),
            }))

            return [
              ...(assistantText ? [{ type: 'text' as const, text: assistantText }] : []),
              ...toolParts,
            ]
          }

          for await (const event of parseSseFrames(streamResponse, options.abortSignal)) {
            const data = event.payload

            if (event.event === 'replay_meta') {
              if (data.replay_truncated === true) {
                const oldest = typeof data.oldest_event_id === 'number' ? data.oldest_event_id : null
                const message =
                  oldest !== null
                    ? `Stream history was truncated. Recovery resumed from event #${oldest}.`
                    : 'Stream history was truncated. Recovery resumed from the earliest available event.'
                setReplayNotice(message)
              }
              continue
            }

            if (event.event === 'status') {
              const message = typeof data.message === 'string' ? data.message : ''
              if (message) setStatusText(message)
              continue
            }

            if (event.event === 'tool_start') {
              const payload = data as ToolStartPayload
              if (!payload.tool_use_id || !payload.name) continue
              toolState.set(payload.tool_use_id, {
                name: payload.name,
                args: toJsonObject(payload.input),
              })
              setStatusText(`tool: ${payload.name}...`)
              const content = makeContent()
              if (content.length > 0) yield { content }
              continue
            }

            if (event.event === 'tool_result') {
              const payload = data as ToolResultPayload
              if (!payload.tool_use_id || !payload.name) continue

              const previous = toolState.get(payload.tool_use_id)
              const resultPayload: ReadonlyJSONObject = toJsonObject({
                output: payload.output ?? '',
                duration_ms: payload.duration_ms ?? null,
                bytes: payload.bytes ?? null,
                status_code: payload.status_code ?? null,
                error_type: payload.error_type ?? null,
              })

              toolState.set(payload.tool_use_id, {
                name: payload.name,
                args: previous?.args ?? {},
                result: resultPayload,
                isError: Boolean(payload.is_error),
              })

              const ms = typeof payload.duration_ms === 'number' ? payload.duration_ms : 0
              const bytes = typeof payload.bytes === 'number' ? payload.bytes : 0
              setStatusText(`tool: ${payload.name} ${payload.is_error ? 'error' : 'ok'} ${ms}ms ${bytes}b`)
              const content = makeContent()
              if (content.length > 0) yield { content }
              continue
            }

            if (event.event === 'delta') {
              const delta = typeof data.delta === 'string' ? data.delta : ''
              if (!delta) continue
              assistantText += delta
              const content = makeContent()
              if (content.length > 0) yield { content }
              continue
            }

            if (event.event === 'error') {
              const message = typeof data.error === 'string' ? data.error : 'stream error'
              throw new Error(message)
            }

            if (event.event === 'done') {
              setStatusText('Done')
              break
            }
          }
        } catch (e) {
          if (isUnauthorizedError(e)) {
            lockForAuth('Session expired. Please sign in again.')
            setStatusText('Auth required')
          }
          throw e
        } finally {
          setSending(false)
          void loadSessions()
          void loadHistory(sessionKey)
        }
      },
    }),
    [sessionKey, selectedSessionReadOnly],
  )

  function createSession(): void {
    const currentCount = historyCountBySession[sessionKey] ?? historySeed.length
    if (currentCount === 0) {
      setStatusText('Current session is empty. Reuse this session.')
      return
    }

    const key = makeSessionKey()
    const nowIso = new Date().toISOString()
    const item: SessionItem = {
      session_key: key,
      label: key,
      chat_id: 0,
      chat_type: 'web',
      last_message_time: nowIso,
    }
    setExtraSessions((prev) => (prev.some((v) => v.session_key === key) ? prev : [item, ...prev]))
    setSessionKey(key)
    setHistoryCountBySession((prev) => ({ ...prev, [key]: 0 }))
    setHistorySeed([])
    setRuntimeNonce((x) => x + 1)
    setReplayNotice('')
    setError('')
    setStatusText('Idle')
  }

  function toggleAppearance(): void {
    setAppearance((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }

  async function onResetSessionByKey(targetSession: string): Promise<void> {
    try {
      await api('/api/reset', {
        method: 'POST',
        body: JSON.stringify({ session_key: targetSession }),
      })
      if (targetSession === sessionKey) {
        await loadHistory(targetSession)
      }
      await loadSessions()
      setStatusText('Session reset')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function onRefreshSessionByKey(targetSession: string): Promise<void> {
    try {
      if (targetSession === sessionKey) {
        await loadHistory(targetSession)
      }
      await loadSessions()
      setStatusText('Session refreshed')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function onDeleteSessionByKey(targetSession: string): Promise<void> {
    try {
      const resp = await api<{ deleted?: boolean }>('/api/delete_session', {
        method: 'POST',
        body: JSON.stringify({ session_key: targetSession }),
      })

      if (resp.deleted === false) {
        setStatusText('No session data found to delete.')
      }

      setExtraSessions((prev) => prev.filter((s) => s.session_key !== targetSession))
      setHistoryCountBySession((prev) => {
        const next = { ...prev }
        delete next[targetSession]
        return next
      })

      const fallback =
        sessionItems.find((item) => item.session_key !== targetSession)?.session_key ||
        makeSessionKey()
      if (targetSession === sessionKey) {
        setSessionKey(fallback)
        await loadHistory(fallback)
      }
      await loadSessions()
      if (resp.deleted !== false) {
        setStatusText('Session deleted')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }





  async function openConfig(): Promise<void> {
    setSaveStatus('')
    setConfigSelfCheckError('')
    setConfigSelfCheckLoading(true)
    try {
      const [data, selfCheck] = await Promise.all([
        api<{ config?: ConfigPayload }>('/api/config'),
        api<ConfigSelfCheck>('/api/config/self_check').catch((e) => {
          setConfigSelfCheckError(e instanceof Error ? e.message : String(e))
          return null
        }),
      ])
      setConfig(data.config || null)
      setConfigSelfCheck(selfCheck)
      const channelsCfg = (data.config?.channels as Record<string, Record<string, unknown>> | undefined) || {}
      const telegramCfg = channelsCfg.telegram || {}
      const telegramDefaultAccount = defaultAccountIdFromChannelConfig(telegramCfg)
      const telegramAccountCfg = defaultAccountConfig(telegramCfg)
      const telegramAccounts = orderedTelegramAccountsFromChannelConfig(telegramCfg)
      const telegramBotCount = normalizeBotCount(telegramAccounts.length || 1)
      const telegramBotDraft: Record<string, unknown> = {}
      for (let slot = 1; slot <= BOT_SLOT_MAX; slot += 1) {
        const account = telegramAccounts[slot - 1]
        const accountId = account?.[0] || defaultTelegramAccountIdForSlot(slot)
        const accountCfg = account?.[1] || {}
        telegramBotDraft[`telegram_bot_${slot}_account_id`] = accountId
        telegramBotDraft[`telegram_bot_${slot}_token`] = ''
        telegramBotDraft[`telegram_bot_${slot}_has_token`] = Boolean(
          typeof accountCfg.bot_token === 'string' && String(accountCfg.bot_token || '').trim(),
        )
        telegramBotDraft[`telegram_bot_${slot}_username`] = String(accountCfg.bot_username || '')
        telegramBotDraft[`telegram_bot_${slot}_allowed_user_ids`] = Array.isArray(accountCfg.allowed_user_ids)
          ? (accountCfg.allowed_user_ids as number[]).join(',')
          : ''
      }
      const discordCfg = channelsCfg.discord || {}
      const discordDefaultAccount = defaultAccountIdFromChannelConfig(discordCfg)
      const discordAccounts = orderedAccountsFromChannelConfig(discordCfg)
      const discordBotCount = normalizeBotCount(discordAccounts.length || 1)
      const discordBotDraft: Record<string, unknown> = {}
      for (let slot = 1; slot <= BOT_SLOT_MAX; slot += 1) {
        const account = discordAccounts[slot - 1]
        const accountId = account?.[0] || defaultAccountIdForSlot(slot)
        const accountCfg = account?.[1] || {}
        discordBotDraft[`discord_bot_${slot}_account_id`] = accountId
        discordBotDraft[`discord_bot_${slot}_token`] = ''
        discordBotDraft[`discord_bot_${slot}_has_token`] = Boolean(
          typeof accountCfg.bot_token === 'string' && String(accountCfg.bot_token || '').trim(),
        )
        discordBotDraft[`discord_bot_${slot}_allowed_channels_csv`] = Array.isArray(accountCfg.allowed_channels)
          ? (accountCfg.allowed_channels as number[]).join(',')
          : ''
        discordBotDraft[`discord_bot_${slot}_username`] = String(accountCfg.bot_username || '')
        discordBotDraft[`discord_bot_${slot}_model`] = String(accountCfg.model || '')
      }
      const ircCfg = channelsCfg.irc || {}
      setConfigDraft({
        llm_provider: data.config?.llm_provider || '',
        model: data.config?.model || defaultModelForProvider(String(data.config?.llm_provider || 'anthropic')),
        llm_base_url: String(data.config?.llm_base_url || ''),
        api_key: '',
        bot_username: String(data.config?.bot_username || ''),
        telegram_account_id: telegramDefaultAccount,
        telegram_bot_count: telegramBotCount,
        telegram_model: String(telegramCfg.model || telegramAccountCfg.model || ''),
        telegram_allowed_user_ids: Array.isArray(telegramCfg.allowed_user_ids)
          ? (telegramCfg.allowed_user_ids as number[]).join(',')
          : '',
        ...telegramBotDraft,
        discord_account_id: discordDefaultAccount,
        discord_bot_count: discordBotCount,
        ...discordBotDraft,
        irc_server: String(ircCfg.server || ''),
        irc_port: String(ircCfg.port || ''),
        irc_nick: String(ircCfg.nick || ''),
        irc_username: String(ircCfg.username || ''),
        irc_real_name: String(ircCfg.real_name || ''),
        irc_channels: String(ircCfg.channels || ''),
        irc_password: '',
        irc_mention_required: String(ircCfg.mention_required || ''),
        irc_tls: String(ircCfg.tls || ''),
        irc_tls_server_name: String(ircCfg.tls_server_name || ''),
        irc_tls_danger_accept_invalid_certs: String(ircCfg.tls_danger_accept_invalid_certs || ''),
        irc_model: String(ircCfg.model || ''),
        web_bot_username: String((channelsCfg.web?.bot_username) || ''),
        working_dir_isolation: normalizeWorkingDirIsolation(
          data.config?.working_dir_isolation || DEFAULT_CONFIG_VALUES.working_dir_isolation,
        ),
        max_tokens: Number(data.config?.max_tokens ?? 8192),
        max_tool_iterations: Number(data.config?.max_tool_iterations ?? 100),
        max_document_size_mb: Number(data.config?.max_document_size_mb ?? DEFAULT_CONFIG_VALUES.max_document_size_mb),
        memory_token_budget: Number(data.config?.memory_token_budget ?? DEFAULT_CONFIG_VALUES.memory_token_budget),
        show_thinking: Boolean(data.config?.show_thinking),
        web_enabled: Boolean(data.config?.web_enabled),
        web_host: String(data.config?.web_host || '127.0.0.1'),
        web_port: Number(data.config?.web_port ?? 10961),
        reflector_enabled: data.config?.reflector_enabled !== false,
        reflector_interval_mins: Number(data.config?.reflector_interval_mins ?? DEFAULT_CONFIG_VALUES.reflector_interval_mins),
        embedding_provider: String(data.config?.embedding_provider || ''),
        embedding_api_key: '',
        embedding_base_url: String(data.config?.embedding_base_url || ''),
        embedding_model: String(data.config?.embedding_model || ''),
        embedding_dim: String(data.config?.embedding_dim || ''),
        // Dynamic channel fields — initialize from server config
        ...Object.fromEntries(
          DYNAMIC_CHANNELS.flatMap((ch) => {
            const chCfg = channelsCfg[ch.name] || {}
            const chAccounts = orderedAccountsFromChannelConfig(chCfg)
            const botCount = normalizeBotCount(chAccounts.length || 1)
            const pairs: Array<[string, unknown]> = [[`${ch.name}__account_id`, defaultAccountIdFromChannelConfig(chCfg)], [`${ch.name}__bot_count`, botCount]]
            for (let slot = 1; slot <= BOT_SLOT_MAX; slot += 1) {
              const account = chAccounts[slot - 1]
              const accountId = account?.[0] || defaultAccountIdForSlot(slot)
              const accountCfg = account?.[1] || {}
              pairs.push([`${ch.name}__bot_${slot}__account_id`, accountId])
              for (const f of ch.fields) {
                if (f.secret) {
                  pairs.push([`${ch.name}__bot_${slot}__has__${f.yamlKey}`, Boolean(String(accountCfg[f.yamlKey] || '').trim())])
                  pairs.push([`${ch.name}__bot_${slot}__${f.yamlKey}`, ''])
                } else {
                  pairs.push([`${ch.name}__bot_${slot}__${f.yamlKey}`, String(accountCfg[f.yamlKey] || '')])
                }
              }
            }
            return pairs
          }),
        ),
      })
      setConfigOpen(true)
    } catch (e) {
      if (isUnauthorizedError(e)) {
        lockForAuth('Session expired. Please sign in again.')
        return
      }
      if (isForbiddenError(e)) {
        setError('Forbidden: Runtime Config is not accessible with current credentials.')
        return
      }
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setConfigSelfCheckLoading(false)
    }
  }

  async function openUsage(targetSession = sessionKey): Promise<void> {
    setUsageLoading(true)
    setUsageError('')
    setUsageReport('')
    setUsageMemory(null)
    setUsageReflectorRuns([])
    setUsageInjectionLogs([])
    const hasStoredSession = sessions.some((s) => s.session_key === targetSession)
    const resolvedSession =
      hasStoredSession
        ? targetSession
        : (sessions.length > 0 ? pickLatestSessionKey(sessions) : targetSession)
    setUsageSession(resolvedSession)
    try {
      if (!hasStoredSession && sessions.length === 0) {
        setUsageError('No usage data yet. Send a message in this session first.')
        setUsageOpen(true)
        return
      }
      const query = new URLSearchParams({ session_key: resolvedSession })
      const data = await api<{ report?: string; memory_observability?: MemoryObservability }>(`/api/usage?${query.toString()}`)
      setUsageReport(String(data.report || '').trim())
      setUsageMemory(data.memory_observability ?? null)
      const moQuery = new URLSearchParams({
        session_key: resolvedSession,
        scope: 'chat',
        hours: '168',
        limit: '1000',
        offset: '0',
      })
      const series = await api<{
        reflector_runs?: ReflectorRunPoint[]
        injection_logs?: InjectionLogPoint[]
      }>(`/api/memory_observability?${moQuery.toString()}`)
      setUsageReflectorRuns(Array.isArray(series.reflector_runs) ? series.reflector_runs : [])
      setUsageInjectionLogs(Array.isArray(series.injection_logs) ? series.injection_logs : [])
      setUsageOpen(true)
    } catch (e) {
      if (isUnauthorizedError(e)) {
        lockForAuth('Session expired. Please sign in again.')
        return
      }
      if (isForbiddenError(e)) {
        setUsageError('Forbidden: Usage panel requires permission.')
        setUsageOpen(true)
        return
      }
      setUsageError(e instanceof Error ? e.message : String(e))
      setUsageOpen(true)
    } finally {
      setUsageLoading(false)
    }
  }

  function setConfigField(field: string, value: unknown): void {
    setConfigDraft((prev) => ({ ...prev, [field]: value }))
  }

  function resetConfigField(field: string): void {
    setConfigDraft((prev) => {
      const next = { ...prev }
      switch (field) {
        case 'llm_provider':
          next.llm_provider = DEFAULT_CONFIG_VALUES.llm_provider
          next.model = defaultModelForProvider(DEFAULT_CONFIG_VALUES.llm_provider)
          break
        case 'model':
          next.model = defaultModelForProvider(String(next.llm_provider || DEFAULT_CONFIG_VALUES.llm_provider))
          break
        case 'llm_base_url':
          next.llm_base_url = ''
          break
        case 'max_tokens':
          next.max_tokens = DEFAULT_CONFIG_VALUES.max_tokens
          break
        case 'telegram_account_id':
          next.telegram_account_id = 'main'
          break
        case 'telegram_bot_count':
          next.telegram_bot_count = 1
          for (let slot = 1; slot <= BOT_SLOT_MAX; slot += 1) {
            next[`telegram_bot_${slot}_account_id`] = defaultTelegramAccountIdForSlot(slot)
            next[`telegram_bot_${slot}_token`] = ''
            next[`telegram_bot_${slot}_has_token`] = false
            next[`telegram_bot_${slot}_username`] = ''
            next[`telegram_bot_${slot}_allowed_user_ids`] = ''
          }
          break
        case 'bot_username':
          next.bot_username = ''
          break
        case 'telegram_model':
          next.telegram_model = ''
          break
        case 'telegram_allowed_user_ids':
          next.telegram_allowed_user_ids = ''
          break
        case 'discord_account_id':
          next.discord_account_id = 'main'
          break
        case 'discord_bot_count':
          next.discord_bot_count = 1
          for (let slot = 1; slot <= BOT_SLOT_MAX; slot += 1) {
            next[`discord_bot_${slot}_account_id`] = defaultAccountIdForSlot(slot)
            next[`discord_bot_${slot}_token`] = ''
            next[`discord_bot_${slot}_has_token`] = false
            next[`discord_bot_${slot}_allowed_channels_csv`] = ''
            next[`discord_bot_${slot}_username`] = ''
            next[`discord_bot_${slot}_model`] = ''
          }
          break
        case 'web_bot_username':
          next.web_bot_username = ''
          break
        case 'working_dir_isolation':
          next.working_dir_isolation = DEFAULT_CONFIG_VALUES.working_dir_isolation
          break
        case 'max_tool_iterations':
          next.max_tool_iterations = DEFAULT_CONFIG_VALUES.max_tool_iterations
          break
        case 'max_document_size_mb':
          next.max_document_size_mb = DEFAULT_CONFIG_VALUES.max_document_size_mb
          break
        case 'memory_token_budget':
          next.memory_token_budget = DEFAULT_CONFIG_VALUES.memory_token_budget
          break
        case 'show_thinking':
          next.show_thinking = DEFAULT_CONFIG_VALUES.show_thinking
          break
        case 'web_enabled':
          next.web_enabled = DEFAULT_CONFIG_VALUES.web_enabled
          break
        case 'web_host':
          next.web_host = DEFAULT_CONFIG_VALUES.web_host
          break
        case 'web_port':
          next.web_port = DEFAULT_CONFIG_VALUES.web_port
          break
        case 'reflector_enabled':
          next.reflector_enabled = DEFAULT_CONFIG_VALUES.reflector_enabled
          break
        case 'reflector_interval_mins':
          next.reflector_interval_mins = DEFAULT_CONFIG_VALUES.reflector_interval_mins
          break
        case 'embedding_provider':
          next.embedding_provider = DEFAULT_CONFIG_VALUES.embedding_provider
          break
        case 'embedding_api_key':
          next.embedding_api_key = DEFAULT_CONFIG_VALUES.embedding_api_key
          break
        case 'embedding_base_url':
          next.embedding_base_url = DEFAULT_CONFIG_VALUES.embedding_base_url
          break
        case 'embedding_model':
          next.embedding_model = DEFAULT_CONFIG_VALUES.embedding_model
          break
        case 'embedding_dim':
          next.embedding_dim = DEFAULT_CONFIG_VALUES.embedding_dim
          break
        case 'irc_server':
          next.irc_server = ''
          break
        case 'irc_port':
          next.irc_port = ''
          break
        case 'irc_nick':
          next.irc_nick = ''
          break
        case 'irc_username':
          next.irc_username = ''
          break
        case 'irc_real_name':
          next.irc_real_name = ''
          break
        case 'irc_channels':
          next.irc_channels = ''
          break
        case 'irc_password':
          next.irc_password = ''
          break
        case 'irc_mention_required':
          next.irc_mention_required = ''
          break
        case 'irc_tls':
          next.irc_tls = ''
          break
        case 'irc_tls_server_name':
          next.irc_tls_server_name = ''
          break
        case 'irc_tls_danger_accept_invalid_certs':
          next.irc_tls_danger_accept_invalid_certs = ''
          break
        case 'irc_model':
          next.irc_model = ''
          break
        default:
          // Handle dynamic channel fields
          for (const ch of DYNAMIC_CHANNELS) {
            const accountKey = `${ch.name}__account_id`
            const botCountKey = `${ch.name}__bot_count`
            if (field === accountKey) {
              next[accountKey] = 'main'
            }
            if (field === botCountKey) {
              next[botCountKey] = 1
              for (let slot = 1; slot <= BOT_SLOT_MAX; slot += 1) {
                next[`${ch.name}__bot_${slot}__account_id`] = defaultAccountIdForSlot(slot)
                for (const f of ch.fields) {
                  next[`${ch.name}__bot_${slot}__${f.yamlKey}`] = ''
                  if (f.secret) next[`${ch.name}__bot_${slot}__has__${f.yamlKey}`] = false
                }
              }
            }
            for (const f of ch.fields) {
              const key = `${ch.name}__${f.yamlKey}`
              if (field === key) {
                next[key] = ''
              }
            }
          }
          break
      }
      return next
    })
  }

  async function saveConfigChanges(): Promise<void> {
    try {
      const provider = String(configDraft.llm_provider || '').trim().toLowerCase()
      if (provider === 'openai-codex') {
        const apiKey = String(configDraft.api_key || '').trim()
        const baseUrl = String(configDraft.llm_base_url || '').trim()
        if (apiKey || baseUrl) {
          setSaveStatus('Save failed: openai-codex ignores api_key/llm_base_url in microclaw config. Configure ~/.codex/auth.json and ~/.codex/config.toml.')
          return
        }
      }

      const payload: Record<string, unknown> = {
        llm_provider: String(configDraft.llm_provider || ''),
        model: String(configDraft.model || ''),
        bot_username: String(configDraft.bot_username || '').trim(),
        web_bot_username: String(configDraft.web_bot_username || '').trim() || null,
        working_dir_isolation: normalizeWorkingDirIsolation(
          configDraft.working_dir_isolation || DEFAULT_CONFIG_VALUES.working_dir_isolation,
        ),
        max_tokens: Number(configDraft.max_tokens || 8192),
        max_tool_iterations: Number(configDraft.max_tool_iterations || 100),
        max_document_size_mb: Number(
          configDraft.max_document_size_mb || DEFAULT_CONFIG_VALUES.max_document_size_mb,
        ),
        memory_token_budget: Number(
          configDraft.memory_token_budget || DEFAULT_CONFIG_VALUES.memory_token_budget,
        ),
        show_thinking: Boolean(configDraft.show_thinking),
        web_enabled: Boolean(configDraft.web_enabled),
        web_host: String(configDraft.web_host || '127.0.0.1'),
        web_port: Number(configDraft.web_port || 10961),
        reflector_enabled: configDraft.reflector_enabled !== false,
        reflector_interval_mins: Number(configDraft.reflector_interval_mins || DEFAULT_CONFIG_VALUES.reflector_interval_mins),
        embedding_provider: String(configDraft.embedding_provider || '').trim() || null,
        embedding_base_url: String(configDraft.embedding_base_url || '').trim() || null,
        embedding_model: String(configDraft.embedding_model || '').trim() || null,
        embedding_dim: String(configDraft.embedding_dim || '').trim()
          ? Number(configDraft.embedding_dim)
          : null,
      }
      if (String(configDraft.llm_provider || '').trim().toLowerCase() === 'custom') {
        payload.llm_base_url = String(configDraft.llm_base_url || '').trim() || null
      } else if (provider === 'openai-codex') {
        payload.llm_base_url = null
      }
      const apiKey = String(configDraft.api_key || '').trim()
      if (provider === 'openai-codex') {
        payload.api_key = ''
      } else if (apiKey) {
        payload.api_key = apiKey
      }

      const telegramAccountId = normalizeAccountId(configDraft.telegram_account_id)
      const telegramModel = String(configDraft.telegram_model || '').trim()
      const telegramBotCount = normalizeBotCount(configDraft.telegram_bot_count)
      const telegramAllowedUserIds = parseI64ListCsvOrJsonArray(
        String(configDraft.telegram_allowed_user_ids || ''),
        'telegram_allowed_user_ids',
      )
      const telegramAccounts: Record<string, unknown> = {}
      for (let slot = 1; slot <= telegramBotCount; slot += 1) {
        const accountId = normalizeAccountId(
          configDraft[`telegram_bot_${slot}_account_id`] || defaultTelegramAccountIdForSlot(slot),
        )
        const token = String(configDraft[`telegram_bot_${slot}_token`] || '').trim()
        const hasToken = Boolean(configDraft[`telegram_bot_${slot}_has_token`])
        const username = String(configDraft[`telegram_bot_${slot}_username`] || '').trim()
        const accountAllowedUserIds = parseI64ListCsvOrJsonArray(
          String(configDraft[`telegram_bot_${slot}_allowed_user_ids`] || ''),
          `telegram_bot_${slot}_allowed_user_ids`,
        )
        const hasAny =
          Boolean(token) ||
          hasToken ||
          Boolean(username) ||
          accountAllowedUserIds.length > 0 ||
          accountId === telegramAccountId
        if (!hasAny) continue
        if (Object.prototype.hasOwnProperty.call(telegramAccounts, accountId)) {
          throw new Error(`Duplicate Telegram account id: ${accountId}`)
        }
        telegramAccounts[accountId] = {
          enabled: true,
          ...(token ? { bot_token: token } : {}),
          ...(username ? { bot_username: username } : {}),
          ...(accountAllowedUserIds.length > 0 ? { allowed_user_ids: accountAllowedUserIds } : {}),
        }
      }

      const discordAccountId = normalizeAccountId(configDraft.discord_account_id)
      const discordBotCount = normalizeBotCount(configDraft.discord_bot_count)
      const discordAccounts: Record<string, unknown> = {}
      for (let slot = 1; slot <= discordBotCount; slot += 1) {
        const accountId = normalizeAccountId(
          configDraft[`discord_bot_${slot}_account_id`] || defaultAccountIdForSlot(slot),
        )
        const token = String(configDraft[`discord_bot_${slot}_token`] || '').trim()
        const hasToken = Boolean(configDraft[`discord_bot_${slot}_has_token`])
        const allowedChannels = parseDiscordChannelCsv(
          String(configDraft[`discord_bot_${slot}_allowed_channels_csv`] || ''),
        )
        const username = String(configDraft[`discord_bot_${slot}_username`] || '').trim()
        const model = String(configDraft[`discord_bot_${slot}_model`] || '').trim()
        const hasAny =
          Boolean(token) ||
          hasToken ||
          allowedChannels.length > 0 ||
          Boolean(username) ||
          Boolean(model) ||
          accountId === discordAccountId
        if (!hasAny) continue
        if (Object.prototype.hasOwnProperty.call(discordAccounts, accountId)) {
          throw new Error(`Duplicate Discord account id: ${accountId}`)
        }
        discordAccounts[accountId] = {
          enabled: true,
          ...(token ? { bot_token: token } : {}),
          ...(allowedChannels.length > 0 ? { allowed_channels: allowedChannels } : {}),
          ...(username ? { bot_username: username } : {}),
          ...(model ? { model } : {}),
        }
      }
      const ircServer = String(configDraft.irc_server || '').trim()
      const ircPort = String(configDraft.irc_port || '').trim()
      const ircNick = String(configDraft.irc_nick || '').trim()
      const ircUsername = String(configDraft.irc_username || '').trim()
      const ircRealName = String(configDraft.irc_real_name || '').trim()
      const ircChannels = String(configDraft.irc_channels || '').trim()
      const ircPassword = String(configDraft.irc_password || '').trim()
      const ircMentionRequired = String(configDraft.irc_mention_required || '').trim()
      const ircTls = String(configDraft.irc_tls || '').trim()
      const ircTlsServerName = String(configDraft.irc_tls_server_name || '').trim()
      const ircTlsDangerAcceptInvalidCerts = String(configDraft.irc_tls_danger_accept_invalid_certs || '').trim()
      const ircModel = String(configDraft.irc_model || '').trim()

      const embeddingApiKey = String(configDraft.embedding_api_key || '').trim()
      if (embeddingApiKey) payload.embedding_api_key = embeddingApiKey

      // Build generic channel_configs from dynamic channel definitions
      const channelConfigs: Record<string, Record<string, unknown>> = {}
      if (
        Object.keys(telegramAccounts).length > 0 ||
        telegramAllowedUserIds.length > 0 ||
        telegramModel
      ) {
        channelConfigs.telegram = {
          default_account: telegramAccountId,
          ...(telegramModel ? { model: telegramModel } : {}),
          ...(telegramAllowedUserIds.length > 0 ? { allowed_user_ids: telegramAllowedUserIds } : {}),
          accounts: telegramAccounts,
        }
      }
      if (Object.keys(discordAccounts).length > 0) {
        channelConfigs.discord = {
          default_account: discordAccountId,
          accounts: discordAccounts,
        }
      }
      if (
        ircServer ||
        ircPort ||
        ircNick ||
        ircUsername ||
        ircRealName ||
        ircChannels ||
        ircPassword ||
        ircMentionRequired ||
        ircTls ||
        ircTlsServerName ||
        ircTlsDangerAcceptInvalidCerts ||
        ircModel
      ) {
        channelConfigs.irc = {
          ...(ircServer ? { server: ircServer } : {}),
          ...(ircPort ? { port: ircPort } : {}),
          ...(ircNick ? { nick: ircNick } : {}),
          ...(ircUsername ? { username: ircUsername } : {}),
          ...(ircRealName ? { real_name: ircRealName } : {}),
          ...(ircChannels ? { channels: ircChannels } : {}),
          ...(ircPassword ? { password: ircPassword } : {}),
          ...(ircMentionRequired ? { mention_required: ircMentionRequired } : {}),
          ...(ircTls ? { tls: ircTls } : {}),
          ...(ircTlsServerName ? { tls_server_name: ircTlsServerName } : {}),
          ...(ircTlsDangerAcceptInvalidCerts
            ? { tls_danger_accept_invalid_certs: ircTlsDangerAcceptInvalidCerts }
            : {}),
          ...(ircModel ? { model: ircModel } : {}),
        }
      }
      for (const ch of DYNAMIC_CHANNELS) {
        const accountId = normalizeAccountId(configDraft[`${ch.name}__account_id`])
        const botCount = normalizeBotCount(configDraft[`${ch.name}__bot_count`])
        const accounts: Record<string, unknown> = {}
        for (let slot = 1; slot <= botCount; slot += 1) {
          const slotAccountId = normalizeAccountId(
            configDraft[`${ch.name}__bot_${slot}__account_id`] || defaultAccountIdForSlot(slot),
          )
          const fields: Record<string, unknown> = {}
          let hasAny = slotAccountId === accountId
          for (const f of ch.fields) {
            const key = `${ch.name}__bot_${slot}__${f.yamlKey}`
            const val = String(configDraft[key] || '').trim()
            const hasSecret = f.secret
              ? Boolean(configDraft[`${ch.name}__bot_${slot}__has__${f.yamlKey}`])
              : false
            if (val) {
              fields[f.yamlKey] = val
              hasAny = true
            } else if (hasSecret) {
              hasAny = true
            }
          }
          if (!hasAny) continue
          if (Object.prototype.hasOwnProperty.call(accounts, slotAccountId)) {
            throw new Error(`Duplicate ${ch.name} account id: ${slotAccountId}`)
          }
          accounts[slotAccountId] = {
            enabled: true,
            ...fields,
          }
        }
        if (Object.keys(accounts).length > 0) {
          channelConfigs[ch.name] = {
            default_account: accountId,
            accounts: {
              ...accounts,
            },
          }
        }
      }
      if (Object.keys(channelConfigs).length > 0) {
        payload.channel_configs = channelConfigs
      }

      await api('/api/config', { method: 'PUT', body: JSON.stringify(payload) })
      setConfigSelfCheckLoading(true)
      setConfigSelfCheckError('')
      const selfCheck = await api<ConfigSelfCheck>('/api/config/self_check').catch((e) => {
        setConfigSelfCheckError(e instanceof Error ? e.message : String(e))
        return null
      })
      setConfigSelfCheck(selfCheck)
      setConfigSelfCheckLoading(false)
      setSaveStatus('Saved. Restart microclaw to apply changes.')
    } catch (e) {
      setSaveStatus(`Save failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }


  useEffect(() => {
    saveAppearance(appearance)
    document.documentElement.classList.toggle('dark', appearance === 'dark')
  }, [appearance])

  useEffect(() => {
    saveUiTheme(uiTheme)
    document.documentElement.setAttribute('data-ui-theme', uiTheme)
  }, [uiTheme])


  useEffect(() => {
    ;(async () => {
      try {
        const auth = await refreshAuthStatus()
        if (auth.authenticated) {
          await loadAppVersion()
        }
        if (!auth.has_password || !auth.authenticated) return
        await loadInitialConversation()
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e))
      }
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!authAuthenticated) return
    loadHistory(sessionKey).catch((e) => setError(e instanceof Error ? e.message : String(e)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionKey, authAuthenticated])

  useEffect(() => {
    if (!authAuthenticated) return
    loadAppVersion().catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authAuthenticated])

  useEffect(() => {
    writeSessionToUrl(sessionKey)
  }, [sessionKey])

  const runtimeKey = `${sessionKey}-${runtimeNonce}`
  const radixAccent = RADIX_ACCENT_BY_THEME[uiTheme] ?? 'green'
  const currentProvider = String(configDraft.llm_provider || DEFAULT_CONFIG_VALUES.llm_provider).trim().toLowerCase()
  const providerOptions = Array.from(
    new Set([currentProvider, ...PROVIDER_SUGGESTIONS.map((p) => p.toLowerCase())].filter(Boolean)),
  )
  const modelOptions = MODEL_OPTIONS[currentProvider] || []
  const sectionCardClass = appearance === 'dark'
    ? 'rounded-xl border p-5'
    : 'rounded-xl border border-slate-200/80 p-5'
  const sectionCardStyle = appearance === 'dark'
    ? { borderColor: 'color-mix(in srgb, var(--mc-border-soft) 68%, transparent)' }
    : undefined
  const toggleCardClass = appearance === 'dark'
    ? 'rounded-lg border p-3'
    : 'rounded-lg border border-slate-200/80 p-3'
  const toggleCardStyle = appearance === 'dark'
    ? { borderColor: 'color-mix(in srgb, var(--mc-border-soft) 60%, transparent)' }
    : undefined

  return (
    <Theme appearance={appearance} accentColor={radixAccent as never} grayColor="slate" radius="medium" scaling="100%">
      <div
        className={
          appearance === 'dark'
            ? 'h-screen w-screen bg-[var(--mc-bg-main)]'
            : 'h-screen w-screen bg-[radial-gradient(1200px_560px_at_-8%_-10%,#d1fae5_0%,transparent_58%),radial-gradient(1200px_560px_at_108%_-12%,#e0f2fe_0%,transparent_58%),#f8fafc]'
        }
      >
        <div className="grid h-full min-h-0 grid-cols-[320px_minmax(0,1fr)]">
          <SessionSidebar
            appearance={appearance}
            onToggleAppearance={toggleAppearance}
            uiTheme={uiTheme}
            onUiThemeChange={(theme) => setUiTheme(theme as UiTheme)}
            uiThemeOptions={UI_THEME_OPTIONS}
            sessionItems={sessionItems}
            selectedSessionKey={sessionKey}
            onSessionSelect={(key) => setSessionKey(key)}
            onRefreshSession={(key) => void onRefreshSessionByKey(key)}
            onResetSession={(key) => void onResetSessionByKey(key)}
            onDeleteSession={(key) => void onDeleteSessionByKey(key)}
            onOpenConfig={openConfig}
            onOpenUsage={() => openUsage(sessionKey)}
            onNewSession={createSession}
            appVersion={appVersion}
          />

          <main
            className={
              appearance === 'dark'
                ? 'flex h-full min-h-0 min-w-0 flex-col overflow-hidden bg-[var(--mc-bg-panel)]'
                : 'flex h-full min-h-0 min-w-0 flex-col overflow-hidden bg-white/95'
            }
          >
            <header
              className={
                appearance === 'dark'
                  ? 'sticky top-0 z-10 border-b border-[color:var(--mc-border-soft)] bg-[color:var(--mc-bg-panel)]/95 px-4 py-3 backdrop-blur-sm'
                  : 'sticky top-0 z-10 border-b border-slate-200 bg-white/92 px-4 py-3 backdrop-blur-sm'
              }
            >
              <Heading size="6">
                {selectedSessionLabel}
              </Heading>
            </header>

            <div
              className={
                appearance === 'dark'
                  ? 'flex min-h-0 flex-1 flex-col bg-[linear-gradient(to_bottom,var(--mc-bg-panel),var(--mc-bg-main)_28%)]'
                  : 'flex min-h-0 flex-1 flex-col bg-[linear-gradient(to_bottom,#f8fafc,white_20%)]'
              }
            >
              <div className="mx-auto w-full max-w-5xl px-3 pt-3">
                {replayNotice ? (
                  <Callout.Root color="orange" size="1" variant="soft">
                    <Callout.Text>{replayNotice}</Callout.Text>
                  </Callout.Root>
                ) : null}
                {error ? (
                  <Callout.Root color="red" size="1" variant="soft" className={replayNotice ? 'mt-2' : ''}>
                    <Callout.Text>{error}</Callout.Text>
                  </Callout.Root>
                ) : null}
              </div>

              <div className="min-h-0 flex-1 px-1 pb-1">
                <ThreadPane key={runtimeKey} adapter={adapter} initialMessages={historySeed} runtimeKey={runtimeKey} />
              </div>
            </div>
          </main>
        </div>
        <Dialog.Root open={authReady && !authHasPassword}>
          <Dialog.Content maxWidth="520px">
            <Dialog.Title>Set Operator Password</Dialog.Title>
            <Dialog.Description size="2">
              First-time setup: set an admin password using the bootstrap token from server logs.
            </Dialog.Description>
            <div className="mt-4 space-y-3">
              <ConfigFieldCard
                label="Bootstrap Token"
                description={<>Copy <code>x-bootstrap-token</code> from MicroClaw startup logs.</>}
              >
                <TextField.Root
                  className="mt-2"
                  value={bootstrapToken}
                  onChange={(e) => setBootstrapToken(e.target.value)}
                  placeholder="902439dd-a93b-4c66-81bb-7ffba0057936"
                />
              </ConfigFieldCard>
              <ConfigFieldCard
                label="Password"
                description={<>At least 8 characters.</>}
              >
                <TextField.Root
                  className="mt-2"
                  type="password"
                  value={bootstrapPassword}
                  onChange={(e) => setBootstrapPassword(e.target.value)}
                  placeholder="********"
                />
                <div className="mt-2 flex items-center justify-end">
                  <Button
                    size="1"
                    variant="soft"
                    onClick={() => {
                      const next = generatePassword()
                      setBootstrapPassword(next)
                      setBootstrapConfirm(next)
                      setGeneratedPasswordPreview(next)
                    }}
                    disabled={authBusy}
                  >
                    Generate Password
                  </Button>
                </div>
              </ConfigFieldCard>
              <ConfigFieldCard label="Confirm Password" description={<>Re-enter the same password.</>}>
                <TextField.Root
                  className="mt-2"
                  type="password"
                  value={bootstrapConfirm}
                  onChange={(e) => setBootstrapConfirm(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void submitBootstrapPassword()
                  }}
                  placeholder="********"
                />
              </ConfigFieldCard>
            </div>
            {authMessage ? (
              <Callout.Root color="red" size="1" variant="soft" className="mt-3">
                <Callout.Text>{authMessage}</Callout.Text>
              </Callout.Root>
            ) : null}
            {generatedPasswordPreview ? (
              <Callout.Root color="green" size="1" variant="soft" className="mt-3">
                <Callout.Text>Generated password: <code>{generatedPasswordPreview}</code></Callout.Text>
              </Callout.Root>
            ) : null}
            <div className="mt-4 flex justify-end">
              <Button onClick={() => void submitBootstrapPassword()} disabled={authBusy}>
                {authBusy ? 'Applying...' : 'Set Password'}
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Root>
        <Dialog.Root open={authReady && authHasPassword && !authAuthenticated}>
          <Dialog.Content maxWidth="460px">
            <Dialog.Title>Sign In</Dialog.Title>
            <Dialog.Description size="2">
              Enter your operator password to access sessions and history.
            </Dialog.Description>
            {authUsingDefaultPassword ? (
              <Callout.Root color="orange" size="1" variant="soft" className="mt-2">
                <Callout.Text>
                  No custom password is set yet. Temporary default password: <code>helloworld</code>
                </Callout.Text>
              </Callout.Root>
            ) : null}
            <ConfigFieldCard label="Password" description={<>Use the password configured for this Web UI.</>}>
              <TextField.Root
                className="mt-2"
                type="password"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void submitLogin(loginPassword)
                }}
                placeholder="********"
              />
            </ConfigFieldCard>
            {authMessage ? (
              <Callout.Root color="red" size="1" variant="soft" className="mt-3">
                <Callout.Text>{authMessage}</Callout.Text>
              </Callout.Root>
            ) : null}
            <div className="mt-4 flex justify-end">
              <Button onClick={() => void submitLogin(loginPassword)} disabled={authBusy}>
                {authBusy ? 'Signing in...' : 'Sign In'}
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Root>
        <Dialog.Root open={authReady && authAuthenticated && authUsingDefaultPassword && passwordPromptOpen}>
          <Dialog.Content maxWidth="520px">
            <Dialog.Title>Change Default Password</Dialog.Title>
            <Dialog.Description size="2">
              You are using the default password <code>helloworld</code>. Set a new password now, or skip for now.
            </Dialog.Description>
            <div className="mt-4 space-y-3">
              <ConfigFieldCard label="New Password" description={<>At least 8 characters.</>}>
                <TextField.Root
                  className="mt-2"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="********"
                />
              </ConfigFieldCard>
              <ConfigFieldCard label="Confirm Password" description={<>Re-enter the new password.</>}>
                <TextField.Root
                  className="mt-2"
                  type="password"
                  value={newPasswordConfirm}
                  onChange={(e) => setNewPasswordConfirm(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void submitPasswordUpdate()
                  }}
                  placeholder="********"
                />
              </ConfigFieldCard>
            </div>
            {passwordPromptMessage ? (
              <Callout.Root color="red" size="1" variant="soft" className="mt-3">
                <Callout.Text>{passwordPromptMessage}</Callout.Text>
              </Callout.Root>
            ) : null}
            <div className="mt-4 flex justify-end gap-2">
              <Button
                variant="soft"
                onClick={() => setPasswordPromptOpen(false)}
                disabled={passwordPromptBusy}
              >
                Skip for now
              </Button>
              <Button onClick={() => void submitPasswordUpdate()} disabled={passwordPromptBusy}>
                {passwordPromptBusy ? 'Updating...' : 'Update Password'}
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Root>
        <Dialog.Root open={configOpen} onOpenChange={setConfigOpen}>
          <Dialog.Content maxWidth="1120px" className="overflow-hidden flex flex-col" style={{ width: "1120px", height: "760px", maxWidth: "1120px", maxHeight: "760px" }}>
            <Dialog.Title>Settings</Dialog.Title>
            <Dialog.Description size="2" mb="3">
              Channel-first configuration. Save writes to microclaw.config.yaml. Restart is required.
            </Dialog.Description>
            {configSelfCheck ? (
              <Callout.Root
                color={
                  configSelfCheck.risk_level === 'high'
                    ? 'red'
                    : configSelfCheck.risk_level === 'medium'
                      ? 'orange'
                      : 'green'
                }
                size="1"
                variant="soft"
                className="mb-2"
              >
                <Callout.Text>
                  Config self-check: risk={String(configSelfCheck.risk_level || 'none')}, warnings={Number(configSelfCheck.warning_count || 0)}.
                  {' '}
                  <a href={`${DOCS_BASE}/configuration`} target="_blank" rel="noreferrer" className="underline">
                    Docs
                  </a>
                </Callout.Text>
              </Callout.Root>
            ) : null}
            {configSelfCheck?.security_posture ? (
              <details className="mb-2">
                <summary className="cursor-pointer text-sm text-[color:var(--gray-11)]">
                  Security posture details
                </summary>
                <Card className="mt-2 p-3">
                  <Text size="2" weight="bold">
                    Security posture{' '}
                    <a href={`${DOCS_BASE}/permissions`} target="_blank" rel="noreferrer" className="underline text-[color:var(--mc-accent)]">
                      Rules
                    </a>
                  </Text>
                  <Text size="1" color="gray" className="mt-1 block">
                    sandbox={String(configSelfCheck.security_posture.sandbox_mode || 'off')} | runtime={String(Boolean(configSelfCheck.security_posture.sandbox_runtime_available))} | backend={String(configSelfCheck.security_posture.sandbox_backend || 'auto')}
                  </Text>
                  <Text size="1" color="gray" className="mt-1 block">
                    mount allowlist: {String(configSelfCheck.security_posture.mount_allowlist?.path || '(default)')} | exists={String(Boolean(configSelfCheck.security_posture.mount_allowlist?.exists))} | has_entries={String(Boolean(configSelfCheck.security_posture.mount_allowlist?.has_entries))}
                  </Text>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {(configSelfCheck.security_posture.execution_policies || []).map((p, idx) => (
                      <Badge key={`${String(p.tool)}-${idx}`} color={p.risk === 'high' ? 'red' : p.risk === 'medium' ? 'orange' : 'gray'} variant="soft">
                        {String(p.tool)}: {String(p.policy)}
                      </Badge>
                    ))}
                  </div>
                </Card>
              </details>
            ) : null}
            {configSelfCheckLoading ? (
              <Text size="1" color="gray" className="mb-2 block">Checking critical config risks...</Text>
            ) : null}
            {configSelfCheckError ? (
              <Callout.Root color="red" size="1" variant="soft" className="mb-2">
                <Callout.Text>Self-check failed: {configSelfCheckError}</Callout.Text>
              </Callout.Root>
            ) : null}
            <div className="mt-2 min-h-0 flex-1">
              {config ? (
                <Tabs.Root defaultValue="general" orientation="vertical" className="h-full min-h-0">
                <div className="grid h-full grid-cols-[240px_minmax(0,1fr)] gap-4">
                  <Card className="h-full p-3" style={sectionCardStyle}>
                    <Tabs.List className="mc-settings-tabs-list flex h-full w-full flex-col gap-1">
                      <Text size="1" color="gray" className="px-2 pt-1 uppercase tracking-wide">Runtime</Text>
                      <Tabs.Trigger value="general" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">⚙️  General</Tabs.Trigger>
                      <Tabs.Trigger value="model" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">🧠  Model</Tabs.Trigger>

                      <Text size="1" color="gray" className="px-2 pt-3 uppercase tracking-wide">Channels</Text>
                      <Tabs.Trigger value="telegram" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">✈️  Telegram</Tabs.Trigger>
                      <Tabs.Trigger value="discord" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">💬  Discord</Tabs.Trigger>
                      <Tabs.Trigger value="irc" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">🧵  IRC</Tabs.Trigger>
                      {DYNAMIC_CHANNELS.map((ch) => (
                        <Tabs.Trigger key={ch.name} value={ch.name} className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">{ch.icon}  {ch.title}</Tabs.Trigger>
                      ))}

                      <Text size="1" color="gray" className="px-2 pt-3 uppercase tracking-wide">Integrations</Text>
                      <Tabs.Trigger value="web" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">🌐  Web</Tabs.Trigger>
                      {authAuthenticated ? (
                        <div className="mt-auto pt-3">
                          <Separator size="4" />
                          <button
                            type="button"
                            onClick={() => void logout()}
                            className="mt-3 inline-flex w-full items-center justify-center rounded-lg border px-3 py-2 text-sm font-medium transition hover:brightness-110 active:brightness-95"
                            style={
                              appearance === 'dark'
                                ? {
                                    borderColor: 'var(--mc-border-soft)',
                                    background: 'var(--mc-bg-panel)',
                                    color: 'var(--mc-text)',
                                  }
                                : undefined
                            }
                          >
                            Log out
                          </button>
                        </div>
                      ) : null}
                    </Tabs.List>
                  </Card>

                  <div className="min-w-0 overflow-y-auto pr-1">
                    <Tabs.Content value="general">
                      <div className={sectionCardClass} style={sectionCardStyle}>
                        <Text size="3" weight="bold">General</Text>
                        <Text size="1" color="gray" className="mt-1 block">
                          Runtime defaults used across all channels.
                        </Text>
                        <Text size="1" color="gray" className="mt-2 block">working_dir_isolation: chat = isolated workspace per chat; shared = one shared workspace.</Text>
                        <Text size="1" color="gray" className="mt-1 block">max_tokens / max_tool_iterations / max_document_size_mb / memory_token_budget control response budget and tool loop safety.</Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="bot_username" description={<>Global default bot username. Channel-specific <code>channels.&lt;name&gt;.bot_username</code> overrides this.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.bot_username || '')}
                              onChange={(e) => setConfigField('bot_username', e.target.value)}
                              placeholder="bot"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="working_dir_isolation" description={<>Use <code>chat</code> for per-chat isolation, or <code>shared</code> for one shared workspace.</>}>
                            <select
                              className="mt-2 w-full rounded-md border border-[color:var(--mc-border-soft)] bg-transparent px-3 py-2 text-base text-[color:inherit] outline-none focus:border-[color:var(--mc-accent)]"
                              value={normalizeWorkingDirIsolation(
                                configDraft.working_dir_isolation || DEFAULT_CONFIG_VALUES.working_dir_isolation,
                              )}
                              onChange={(e) => setConfigField('working_dir_isolation', e.target.value)}
                            >
                              <option value="chat">chat (per-chat isolated workspace)</option>
                              <option value="shared">shared (single shared workspace)</option>
                            </select>
                          </ConfigFieldCard>
                          <ConfigFieldCard label="max_tokens" description={<>Maximum output tokens for one model response.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.max_tokens || DEFAULT_CONFIG_VALUES.max_tokens)}
                              onChange={(e) => setConfigField('max_tokens', e.target.value)}
                              placeholder="8192"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="max_tool_iterations" description={<>Upper bound for tool loop iterations in one request.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.max_tool_iterations || DEFAULT_CONFIG_VALUES.max_tool_iterations)}
                              onChange={(e) => setConfigField('max_tool_iterations', e.target.value)}
                              placeholder="100"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="max_document_size_mb" description={<>Maximum uploaded file size in MB.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.max_document_size_mb || DEFAULT_CONFIG_VALUES.max_document_size_mb)}
                              onChange={(e) => setConfigField('max_document_size_mb', e.target.value)}
                              placeholder="100"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="memory_token_budget" description={<>Estimated token budget for injecting structured memories into the system prompt.</>}>
                            <TextField.Root
                              className="mt-2"
                              type="number"
                              value={String(configDraft.memory_token_budget || DEFAULT_CONFIG_VALUES.memory_token_budget)}
                              onChange={(e) => setConfigField('memory_token_budget', e.target.value)}
                              placeholder="1500"
                            />
                          </ConfigFieldCard>
                        </div>
                        <div className="mt-4 grid grid-cols-1 gap-3">
                          <ConfigToggleCard
                            label="show_thinking"
                            description={<>Show intermediate reasoning text in responses.</>}
                            checked={Boolean(configDraft.show_thinking)}
                            onCheckedChange={(checked) => setConfigField('show_thinking', checked)}
                            className={toggleCardClass}
                            style={toggleCardStyle}
                          />
                          <ConfigToggleCard
                            label="web_enabled"
                            description={<>Enable built-in Web UI and API endpoint.</>}
                            checked={Boolean(configDraft.web_enabled)}
                            onCheckedChange={(checked) => setConfigField('web_enabled', checked)}
                            className={toggleCardClass}
                            style={toggleCardStyle}
                          />
                          <ConfigToggleCard
                            label="reflector_enabled"
                            description={<>Periodically extract structured memories from conversations in the background.</>}
                            checked={configDraft.reflector_enabled !== false}
                            onCheckedChange={(checked) => setConfigField('reflector_enabled', checked)}
                            className={toggleCardClass}
                            style={toggleCardStyle}
                          />
                        </div>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="reflector_interval_mins" description={<>How often (in minutes) the memory reflector runs. Requires restart.</>}>
                            <TextField.Root
                              className="mt-2"
                              type="number"
                              value={String(configDraft.reflector_interval_mins ?? DEFAULT_CONFIG_VALUES.reflector_interval_mins)}
                              onChange={(e) => setConfigField('reflector_interval_mins', e.target.value)}
                              placeholder="15"
                            />
                          </ConfigFieldCard>
                        </div>
                      </div>
                    </Tabs.Content>

                    <Tabs.Content value="model">
                      <div className={sectionCardClass} style={sectionCardStyle}>
                        <Text size="3" weight="bold">Model</Text>
                        <Text size="1" color="gray" className="mt-1 block">
                          LLM provider and API settings.
                        </Text>
                        <Text size="1" color="gray" className="mt-2 block">llm_provider selects routing preset; model is the exact model id sent to provider API.</Text>
                        <Text size="1" color="gray" className="mt-1 block">For custom providers set <code>llm_base_url</code>. For <code>openai-codex</code>, configure auth/provider in <code>~/.codex/auth.json</code> and <code>~/.codex/config.toml</code> (this form ignores <code>api_key</code>/<code>llm_base_url</code>). <code>ollama</code> can leave <code>api_key</code> empty.</Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="llm_provider" description={<>Select provider preset for request routing and defaults.</>}>
                            <div className="mt-2">
                              <Select.Root
                                value={String(configDraft.llm_provider || DEFAULT_CONFIG_VALUES.llm_provider)}
                                onValueChange={(value) => setConfigField('llm_provider', value)}
                              >
                                <Select.Trigger className="w-full mc-select-trigger-full" placeholder="Select provider" />
                                <Select.Content>
                                  {providerOptions.map((provider) => (
                                    <Select.Item key={provider} value={provider}>
                                      {provider}
                                    </Select.Item>
                                  ))}
                                </Select.Content>
                              </Select.Root>
                            </div>
                          </ConfigFieldCard>

                          <ConfigFieldCard label="model" description={<>Exact model id to use for requests.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.model || defaultModelForProvider(String(configDraft.llm_provider || DEFAULT_CONFIG_VALUES.llm_provider)))}
                              onChange={(e) => setConfigField('model', e.target.value)}
                              placeholder="claude-sonnet-4-5-20250929"
                            />
                            {modelOptions.length > 0 ? (
                              <Text size="1" color="gray" className="mt-2 block">Suggested: {modelOptions.join(' / ')}</Text>
                            ) : null}
                          </ConfigFieldCard>

                          {currentProvider === 'custom' ? (
                            <ConfigFieldCard label="llm_base_url" description={<>Base URL for OpenAI-compatible custom provider endpoint.</>}>
                              <TextField.Root
                                className="mt-2"
                                value={String(configDraft.llm_base_url || '')}
                                onChange={(e) => setConfigField('llm_base_url', e.target.value)}
                                placeholder="https://api.example.com/v1"
                              />
                          </ConfigFieldCard>
                          ) : null}

                          <ConfigFieldCard
                            label="api_key"
                            description={
                              currentProvider === 'openai-codex'
                                ? <>For <code>openai-codex</code>, this field is ignored. Configure <code>~/.codex/auth.json</code> instead.</>
                                : <>Provider API key. Leave blank to keep current secret unchanged.</>
                            }
                          >
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.api_key || '')}
                              onChange={(e) => setConfigField('api_key', e.target.value)}
                              placeholder={currentProvider === 'openai-codex' ? '(ignored for openai-codex)' : 'sk-...'}
                            />
                          </ConfigFieldCard>
                        </div>
                      </div>
                      <div className={`${sectionCardClass} mt-4`} style={sectionCardStyle}>
                        <Text size="3" weight="bold">Embedding</Text>
                        <Text size="1" color="gray" className="mt-1 block">
                          Optional embedding runtime settings for semantic memory (requires sqlite-vec build).
                        </Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="embedding_provider" description={<>Optional runtime embedding provider: <code>openai</code> or <code>ollama</code>.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.embedding_provider || '')}
                              onChange={(e) => setConfigField('embedding_provider', e.target.value)}
                              placeholder="openai"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="embedding_api_key" description={<>Optional embedding API key. Leave blank to keep unchanged.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.embedding_api_key || '')}
                              onChange={(e) => setConfigField('embedding_api_key', e.target.value)}
                              placeholder="sk-..."
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="embedding_base_url" description={<>Optional embedding base URL override.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.embedding_base_url || '')}
                              onChange={(e) => setConfigField('embedding_base_url', e.target.value)}
                              placeholder="https://api.openai.com/v1"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="embedding_model" description={<>Optional embedding model id.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.embedding_model || '')}
                              onChange={(e) => setConfigField('embedding_model', e.target.value)}
                              placeholder="text-embedding-3-small"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="embedding_dim" description={<>Optional embedding vector dimension.</>}>
                            <TextField.Root
                              className="mt-2"
                              type="number"
                              value={String(configDraft.embedding_dim || '')}
                              onChange={(e) => setConfigField('embedding_dim', e.target.value)}
                              placeholder="1536"
                            />
                          </ConfigFieldCard>
                        </div>
                      </div>
                    </Tabs.Content>

                    <Tabs.Content value="telegram">
                      <div className={sectionCardClass} style={sectionCardStyle}>
                        <Text size="3" weight="bold">Telegram</Text>
                        <ConfigStepsCard
                          steps={[
                            <>Open Telegram and chat with <code>@BotFather</code>.</>,
                            <>Run <code>/newbot</code>, set name and username (must end with <code>bot</code>).</>,
                            <>Copy the bot token and paste below.</>,
                            <>Configure one or more bot accounts; each account can set its own username.</>,
                            <>In groups, mention the bot to trigger replies.</>,
                          ]}
                        />
                        <Text size="1" color="gray" className="mt-3 block">
                          Configure one or more bots (up to 10). Leave token blank to keep existing secret unchanged.
                        </Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="telegram_default_account" description={<>Default account id under <code>channels.telegram.accounts</code>.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.telegram_account_id || 'main')}
                              onChange={(e) => setConfigField('telegram_account_id', e.target.value)}
                              placeholder="main"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="telegram_bot_count" description={<>Number of Telegram bot accounts to configure (1-10).</>}>
                            <TextField.Root
                              className="mt-2"
                              type="number"
                              min="1"
                              max={String(BOT_SLOT_MAX)}
                              value={String(configDraft.telegram_bot_count || 1)}
                              onChange={(e) => setConfigField('telegram_bot_count', normalizeBotCount(e.target.value))}
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="telegram_model" description={<>Optional Telegram channel-level model override.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.telegram_model || '')}
                              onChange={(e) => setConfigField('telegram_model', e.target.value)}
                              placeholder="claude-sonnet-4-5-20250929"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="telegram_allowed_user_ids" description={<>Optional channel-level allowlist. Accepts CSV or JSON array (for example <code>123,456</code> or <code>[123,456]</code>). Merged with each bot account&apos;s <code>allowed_user_ids</code>.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.telegram_allowed_user_ids || '')}
                              onChange={(e) => setConfigField('telegram_allowed_user_ids', e.target.value)}
                              placeholder="123456789,987654321"
                            />
                          </ConfigFieldCard>
                          {Array.from({ length: normalizeBotCount(configDraft.telegram_bot_count || 1) }).map((_, idx) => {
                            const slot = idx + 1
                            return (
                              <Card key={`telegram-bot-${slot}`} className="p-3">
                                <Text size="2" weight="medium">Telegram bot #{slot}</Text>
                                <div className="mt-2 space-y-3">
                                  <ConfigFieldCard label={`telegram_bot_${slot}_account_id`} description={<>Bot account id used under <code>channels.telegram.accounts</code>.</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`telegram_bot_${slot}_account_id`] || defaultTelegramAccountIdForSlot(slot))}
                                      onChange={(e) => setConfigField(`telegram_bot_${slot}_account_id`, e.target.value)}
                                      placeholder={defaultTelegramAccountIdForSlot(slot)}
                                    />
                                  </ConfigFieldCard>
                                  <ConfigFieldCard label={`telegram_bot_${slot}_token`} description={<>BotFather token for this account. Leave blank to keep current secret unchanged.</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`telegram_bot_${slot}_token`] || '')}
                                      onChange={(e) => setConfigField(`telegram_bot_${slot}_token`, e.target.value)}
                                      placeholder="123456789:AA..."
                                    />
                                  </ConfigFieldCard>
                                  <ConfigFieldCard label={`telegram_bot_${slot}_username`} description={<>Telegram username without <code>@</code>, used for group mention trigger.</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`telegram_bot_${slot}_username`] || '')}
                                      onChange={(e) => setConfigField(`telegram_bot_${slot}_username`, e.target.value)}
                                      placeholder={slot === 1 ? 'my_main_bot' : `my_bot_${slot}`}
                                    />
                                  </ConfigFieldCard>
                                  <ConfigFieldCard label={`telegram_bot_${slot}_allowed_user_ids`} description={<>Optional per-bot private-chat allowlist (CSV or JSON array).</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`telegram_bot_${slot}_allowed_user_ids`] || '')}
                                      onChange={(e) => setConfigField(`telegram_bot_${slot}_allowed_user_ids`, e.target.value)}
                                      placeholder="123456789,987654321"
                                    />
                                  </ConfigFieldCard>
                                </div>
                              </Card>
                            )
                          })}
                        </div>
                      </div>
                    </Tabs.Content>

                    <Tabs.Content value="discord">
                      <div className={sectionCardClass} style={sectionCardStyle}>
                        <Text size="3" weight="bold">Discord</Text>
                        <ConfigStepsCard
                          steps={[
                            <>Open Discord Developer Portal and create an application + bot.</>,
                            <>Enable <code>Message Content Intent</code> under Bot settings.</>,
                            <>Invite bot with scopes/permissions: bot, View Channels, Send Messages, Read Message History.</>,
                            <>Paste bot token below.</>,
                            <>Optional: limit handling to specific channel IDs.</>,
                          ]}
                        />
                        <Text size="1" color="gray" className="mt-3 block">
                          Configure one or more Discord bot accounts (up to 10).
                        </Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="discord_default_account" description={<>Default account id under <code>channels.discord.accounts</code>.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.discord_account_id || 'main')}
                              onChange={(e) => setConfigField('discord_account_id', e.target.value)}
                              placeholder="main"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="discord_bot_count" description={<>Number of Discord bot accounts to configure (1-10).</>}>
                            <TextField.Root
                              className="mt-2"
                              type="number"
                              min="1"
                              max={String(BOT_SLOT_MAX)}
                              value={String(configDraft.discord_bot_count || 1)}
                              onChange={(e) => setConfigField('discord_bot_count', normalizeBotCount(e.target.value))}
                            />
                          </ConfigFieldCard>
                          {Array.from({ length: normalizeBotCount(configDraft.discord_bot_count || 1) }).map((_, idx) => {
                            const slot = idx + 1
                            return (
                              <Card key={`discord-bot-${slot}`} className="p-3">
                                <Text size="2" weight="medium">Discord bot #{slot}</Text>
                                <div className="mt-2 space-y-3">
                                  <ConfigFieldCard label={`discord_bot_${slot}_account_id`} description={<>Bot account id used under <code>channels.discord.accounts</code>.</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`discord_bot_${slot}_account_id`] || defaultAccountIdForSlot(slot))}
                                      onChange={(e) => setConfigField(`discord_bot_${slot}_account_id`, e.target.value)}
                                      placeholder={defaultAccountIdForSlot(slot)}
                                    />
                                  </ConfigFieldCard>
                                  <ConfigFieldCard label={`discord_bot_${slot}_token`} description={<>Discord bot token for this account. Leave blank to keep current secret unchanged.</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`discord_bot_${slot}_token`] || '')}
                                      onChange={(e) => setConfigField(`discord_bot_${slot}_token`, e.target.value)}
                                      placeholder="MTAx..."
                                    />
                                  </ConfigFieldCard>
                                  <ConfigFieldCard label={`discord_bot_${slot}_allowed_channels`} description={<>Optional allowlist. Only listed channel IDs can trigger this bot.</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`discord_bot_${slot}_allowed_channels_csv`] || '')}
                                      onChange={(e) => setConfigField(`discord_bot_${slot}_allowed_channels_csv`, e.target.value)}
                                      placeholder="1234567890,9876543210"
                                    />
                                  </ConfigFieldCard>
                                  <ConfigFieldCard label={`discord_bot_${slot}_username`} description={<>Optional Discord bot username override.</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`discord_bot_${slot}_username`] || '')}
                                      onChange={(e) => setConfigField(`discord_bot_${slot}_username`, e.target.value)}
                                      placeholder={slot === 1 ? 'discord_main_bot' : `discord_bot_${slot}`}
                                    />
                                  </ConfigFieldCard>
                                  <ConfigFieldCard label={`discord_bot_${slot}_model`} description={<>Optional model override for this bot account.</>}>
                                    <TextField.Root
                                      className="mt-2"
                                      value={String(configDraft[`discord_bot_${slot}_model`] || '')}
                                      onChange={(e) => setConfigField(`discord_bot_${slot}_model`, e.target.value)}
                                      placeholder="claude-sonnet-4-5-20250929"
                                    />
                                  </ConfigFieldCard>
                                </div>
                              </Card>
                            )
                          })}
                        </div>
                      </div>
                    </Tabs.Content>

                    <Tabs.Content value="irc">
                      <div className={sectionCardClass} style={sectionCardStyle}>
                        <Text size="3" weight="bold">IRC</Text>
                        <ConfigStepsCard
                          steps={[
                            <>Set IRC server and nick.</>,
                            <>Set channels as comma-separated list, for example <code>#general,#bot</code>.</>,
                            <>Use TLS fields when connecting to secure endpoints.</>,
                          ]}
                        />
                        <Text size="1" color="gray" className="mt-3 block">
                          Required for IRC runtime: server and nick.
                        </Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="irc_server" description={<>IRC server hostname.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_server || '')}
                              onChange={(e) => setConfigField('irc_server', e.target.value)}
                              placeholder="irc.libera.chat"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_port" description={<>IRC server port. Typical values: 6667 or 6697 (TLS).</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_port || '')}
                              onChange={(e) => setConfigField('irc_port', e.target.value)}
                              placeholder="6667"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_nick" description={<>Bot nickname.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_nick || '')}
                              onChange={(e) => setConfigField('irc_nick', e.target.value)}
                              placeholder="microclaw"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_username" description={<>Optional IRC username. Defaults to nick when empty.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_username || '')}
                              onChange={(e) => setConfigField('irc_username', e.target.value)}
                              placeholder="microclaw"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_real_name" description={<>Optional IRC real name/gecos field.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_real_name || '')}
                              onChange={(e) => setConfigField('irc_real_name', e.target.value)}
                              placeholder="MicroClaw"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_channels" description={<>Comma-separated target channels.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_channels || '')}
                              onChange={(e) => setConfigField('irc_channels', e.target.value)}
                              placeholder="#general,#support"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_password" description={<>Optional IRC server password. Leave blank to keep current secret unchanged.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_password || '')}
                              onChange={(e) => setConfigField('irc_password', e.target.value)}
                              placeholder="password"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_mention_required" description={<>In channels, require bot mention before responding (<code>true</code>/<code>false</code>).</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_mention_required || '')}
                              onChange={(e) => setConfigField('irc_mention_required', e.target.value)}
                              placeholder="true"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_tls" description={<>Enable TLS (<code>true</code>/<code>false</code>).</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_tls || '')}
                              onChange={(e) => setConfigField('irc_tls', e.target.value)}
                              placeholder="false"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_tls_server_name" description={<>Optional TLS SNI server name. Defaults to server.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_tls_server_name || '')}
                              onChange={(e) => setConfigField('irc_tls_server_name', e.target.value)}
                              placeholder="irc.libera.chat"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_tls_danger_accept_invalid_certs" description={<>Allow invalid TLS certs (<code>true</code>/<code>false</code>). Only for testing.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_tls_danger_accept_invalid_certs || '')}
                              onChange={(e) => setConfigField('irc_tls_danger_accept_invalid_certs', e.target.value)}
                              placeholder="false"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="irc_model" description={<>Optional IRC model override.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.irc_model || '')}
                              onChange={(e) => setConfigField('irc_model', e.target.value)}
                              placeholder="claude-sonnet-4-5-20250929"
                            />
                          </ConfigFieldCard>
                        </div>
                      </div>
                    </Tabs.Content>

                    {DYNAMIC_CHANNELS.map((ch) => (
                      <Tabs.Content key={ch.name} value={ch.name}>
                        <div className={sectionCardClass} style={sectionCardStyle}>
                          <Text size="3" weight="bold">{ch.title}</Text>
                          <ConfigStepsCard steps={ch.steps.map((s, i) => <span key={i}>{s}</span>)} />
                          <Text size="1" color="gray" className="mt-3 block">{ch.hint}</Text>
                          <div className="mt-4 space-y-3">
                            <ConfigFieldCard
                              key={`${ch.name}__account_id`}
                              label={`${ch.name}_default_account`}
                              description={<>Default account id under <code>channels.{ch.name}.accounts</code>.</>}
                            >
                              <TextField.Root
                                className="mt-2"
                                value={String(configDraft[`${ch.name}__account_id`] || 'main')}
                                onChange={(e) => setConfigField(`${ch.name}__account_id`, e.target.value)}
                                placeholder="main"
                              />
                            </ConfigFieldCard>
                            <ConfigFieldCard
                              key={`${ch.name}__bot_count`}
                              label={`${ch.name}_bot_count`}
                              description={<>Number of bot accounts to configure for <code>{ch.name}</code> (1-10).</>}
                            >
                              <TextField.Root
                                className="mt-2"
                                type="number"
                                min="1"
                                max={String(BOT_SLOT_MAX)}
                                value={String(configDraft[`${ch.name}__bot_count`] || 1)}
                                onChange={(e) => setConfigField(`${ch.name}__bot_count`, normalizeBotCount(e.target.value))}
                              />
                            </ConfigFieldCard>
                            {Array.from({ length: normalizeBotCount(configDraft[`${ch.name}__bot_count`] || 1) }).map((_, idx) => {
                              const slot = idx + 1
                              return (
                                <Card key={`${ch.name}-bot-${slot}`} className="p-3">
                                  <Text size="2" weight="medium">{ch.title} bot #{slot}</Text>
                                  <div className="mt-2 space-y-3">
                                    <ConfigFieldCard
                                      key={`${ch.name}__bot_${slot}__account_id`}
                                      label={`${ch.name}_bot_${slot}_account_id`}
                                      description={<>Bot account id used under <code>channels.{ch.name}.accounts</code>.</>}
                                    >
                                      <TextField.Root
                                        className="mt-2"
                                        value={String(configDraft[`${ch.name}__bot_${slot}__account_id`] || defaultAccountIdForSlot(slot))}
                                        onChange={(e) => setConfigField(`${ch.name}__bot_${slot}__account_id`, e.target.value)}
                                        placeholder={defaultAccountIdForSlot(slot)}
                                      />
                                    </ConfigFieldCard>
                                    {ch.fields.map((f) => {
                                      const stateKey = `${ch.name}__bot_${slot}__${f.yamlKey}`
                                      return (
                                        <ConfigFieldCard key={stateKey} label={`${ch.name}_bot_${slot}_${f.yamlKey}`} description={<>{f.description}</>}>
                                          <TextField.Root
                                            className="mt-2"
                                            value={String(configDraft[stateKey] || '')}
                                            onChange={(e) => setConfigField(stateKey, e.target.value)}
                                            placeholder={f.placeholder}
                                          />
                                        </ConfigFieldCard>
                                      )
                                    })}
                                  </div>
                                </Card>
                              )
                            })}
                          </div>
                        </div>
                      </Tabs.Content>
                    ))}

                    <Tabs.Content value="web">
                      <div className={sectionCardClass} style={sectionCardStyle}>
                        <Text size="3" weight="bold">Web</Text>
                        <ConfigStepsCard
                          steps={[
                            <>Keep <code>web_enabled</code> on for local UI access.</>,
                            <>Use <code>127.0.0.1</code> for local-only host, or set LAN host explicitly.</>,
                            <>Choose web port (default <code>10961</code>).</>,
                          ]}
                        />
                        <Text size="1" color="gray" className="mt-3 block">
                          For local only, keep host as 127.0.0.1. Use 0.0.0.0 only behind trusted network controls.
                        </Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="web_host" description={<>Use <code>127.0.0.1</code> for local-only. Use <code>0.0.0.0</code> only when intentionally exposing on LAN.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.web_host || DEFAULT_CONFIG_VALUES.web_host)}
                              onChange={(e) => setConfigField('web_host', e.target.value)}
                              placeholder="127.0.0.1"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="web_port" description={<>HTTP port for Web UI and API endpoint.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.web_port || DEFAULT_CONFIG_VALUES.web_port)}
                              onChange={(e) => setConfigField('web_port', e.target.value)}
                              placeholder="10961"
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="web_bot_username" description={<>Optional Web-specific bot username override.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.web_bot_username || '')}
                              onChange={(e) => setConfigField('web_bot_username', e.target.value)}
                              placeholder="web_bot_name"
                            />
                          </ConfigFieldCard>
                        </div>
                        {Array.isArray(configSelfCheck?.warnings) && configSelfCheck!.warnings!.length > 0 ? (
                          <details className="mt-4">
                            <summary className="cursor-pointer text-sm text-[color:var(--gray-11)]">
                              Critical config warnings ({configSelfCheck!.warnings!.length})
                            </summary>
                            <Card className="mt-2 p-3">
                              <Text size="2" weight="bold">Critical Config Warnings</Text>
                              <div className="mt-2 space-y-2">
                                {configSelfCheck!.warnings!.map((w, idx) => (
                                  <Callout.Root
                                    key={`${w.code || 'warning'}-${idx}`}
                                    color={w.severity === 'high' ? 'red' : 'orange'}
                                    size="1"
                                    variant="soft"
                                  >
                                    <Callout.Text>
                                      [{String(w.severity || 'unknown')}] {String(w.code || 'warning')}: {String(w.message || '')}
                                      {' '}
                                      <a
                                        href={warningDocUrl(w.code)}
                                        target="_blank"
                                        rel="noreferrer"
                                        className="underline"
                                      >
                                        Docs
                                      </a>
                                    </Callout.Text>
                                  </Callout.Root>
                                ))}
                              </div>
                            </Card>
                          </details>
                        ) : null}
                      </div>
                    </Tabs.Content>

                  </div>
                </div>
                </Tabs.Root>
              ) : (
                <Text size="2" color="gray">Loading...</Text>
              )}
            </div>

            <div className="mt-3 flex items-center justify-between border-t border-[color:var(--mc-border-soft)] pt-3">
              {saveStatus ? (
                <Text size="2" color={saveStatus.startsWith('Save failed') ? 'red' : 'green'}>
                  {saveStatus}
                </Text>
              ) : (
                <span />
              )}
              <Flex justify="end" gap="2">
                <Dialog.Close>
                  <Button variant="soft">Close</Button>
                </Dialog.Close>
                <Button onClick={() => void saveConfigChanges()}>Save</Button>
              </Flex>
            </div>
          </Dialog.Content>
        </Dialog.Root>
        <UsagePanel
          open={usageOpen}
          onOpenChange={setUsageOpen}
          usageSession={usageSession}
          sessionKey={sessionKey}
          usageLoading={usageLoading}
          usageError={usageError}
          usageReport={usageReport}
          usageMemory={usageMemory}
          reflectorRuns={usageReflectorRuns}
          injectionLogs={usageInjectionLogs}
          onRefreshCurrent={() => void openUsage(sessionKey)}
          onRefreshThis={() => void openUsage(usageSession || sessionKey)}
        />
      </div>
    </Theme>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
