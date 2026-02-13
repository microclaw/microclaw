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
  Callout,
  Card,
  Dialog,
  Flex,
  Heading,
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
import type { SessionItem } from './types'

type ConfigPayload = Record<string, unknown>

type StreamEvent = {
  event: string
  payload: Record<string, unknown>
}

type BackendMessage = {
  id?: string
  sender_name?: string
  content?: string
  is_from_bot?: boolean
  timestamp?: string
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
  openai: ['gpt-5.2', 'gpt-5', 'gpt-4.1'],
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
  show_thinking: false,
  web_enabled: true,
  web_host: '127.0.0.1',
  web_port: 10961,
}

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

function defaultModelForProvider(providerRaw: string): string {
  const provider = providerRaw.trim().toLowerCase()
  if (provider === 'anthropic') return 'claude-sonnet-4-5-20250929'
  if (provider === 'ollama') return 'llama3.2'
  return 'gpt-5.2'
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

function pickLatestSessionKey(items: SessionItem[]): string {
  if (items.length === 0) return makeSessionKey()

  const parsed = items
    .map((item) => ({ item, ts: Date.parse(item.last_message_time || '') }))
    .filter((v) => Number.isFinite(v.ts))

  if (parsed.length > 0) {
    parsed.sort((a, b) => b.ts - a.ts)
    return parsed[0]?.item.session_key || makeSessionKey()
  }

  return items[items.length - 1]?.session_key || makeSessionKey()
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
  return headers
}

async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(path, { ...options, headers: makeHeaders(options) })
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    throw new Error(String(data.error || data.message || `HTTP ${res.status}`))
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
  const hasRenderableContent = useMessage((m) =>
    Array.isArray(m.content)
      ? m.content.some((part) => {
          if (part.type === 'text') return Boolean(part.text?.trim())
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
  const MarkdownText = makeMarkdownText()
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
  const [saveStatus, setSaveStatus] = useState<string>('')
  const [usageOpen, setUsageOpen] = useState<boolean>(false)
  const [usageLoading, setUsageLoading] = useState<boolean>(false)
  const [usageReport, setUsageReport] = useState<string>('')
  const [usageError, setUsageError] = useState<string>('')
  const [usageSession, setUsageSession] = useState<string>('')

  const sessionItems = useMemo(() => {
    const map = new Map<string, SessionItem>()

    for (const item of [...extraSessions, ...sessions]) {
      if (!map.has(item.session_key)) {
        map.set(item.session_key, item)
      }
    }

    if (!map.has(sessionKey) && !sessionKey.startsWith('chat:')) {
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

    return Array.from(map.values())
  }, [extraSessions, sessions, sessionKey])

  const selectedSession = useMemo(
    () => sessionItems.find((item) => item.session_key === sessionKey),
    [sessionItems, sessionKey],
  )

  const selectedSessionLabel = selectedSession?.label || sessionKey
  const selectedSessionReadOnly = Boolean(selectedSession && selectedSession.chat_type !== 'web')

  async function loadSessions(): Promise<void> {
    const data = await api<{ sessions?: SessionItem[] }>('/api/sessions')
    setSessions(Array.isArray(data.sessions) ? data.sessions : [])
  }

  async function loadHistory(target = sessionKey): Promise<void> {
    const query = new URLSearchParams({ session_key: target, limit: '200' })
    const data = await api<{ messages?: BackendMessage[] }>(`/api/history?${query.toString()}`)
    const rawMessages = Array.isArray(data.messages) ? data.messages : []
    const mapped = mapBackendHistory(rawMessages)
    setHistorySeed(mapped)
    setHistoryCountBySession((prev) => ({ ...prev, [target]: rawMessages.length }))
    setRuntimeNonce((x) => x + 1)
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
            cache: 'no-store',
            signal: options.abortSignal,
          })

          if (!streamResponse.ok) {
            const text = await streamResponse.text().catch(() => '')
            throw new Error(text || `HTTP ${streamResponse.status}`)
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
    const item: SessionItem = {
      session_key: key,
      label: key,
      chat_id: 0,
      chat_type: 'web',
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
    const data = await api<{ config?: ConfigPayload }>('/api/config')
    setConfig(data.config || null)
    setConfigDraft({
      llm_provider: data.config?.llm_provider || '',
      model: data.config?.model || defaultModelForProvider(String(data.config?.llm_provider || 'anthropic')),
      llm_base_url: String(data.config?.llm_base_url || ''),
      api_key: '',
      telegram_bot_token: '',
      bot_username: String(data.config?.bot_username || ''),
      discord_bot_token: '',
      discord_allowed_channels_csv: Array.isArray(data.config?.discord_allowed_channels)
        ? (data.config?.discord_allowed_channels as number[]).join(',')
        : '',
      working_dir_isolation: normalizeWorkingDirIsolation(
        data.config?.working_dir_isolation || DEFAULT_CONFIG_VALUES.working_dir_isolation,
      ),
      max_tokens: Number(data.config?.max_tokens ?? 8192),
      max_tool_iterations: Number(data.config?.max_tool_iterations ?? 100),
      max_document_size_mb: Number(data.config?.max_document_size_mb ?? DEFAULT_CONFIG_VALUES.max_document_size_mb),
      show_thinking: Boolean(data.config?.show_thinking),
      web_enabled: Boolean(data.config?.web_enabled),
      web_host: String(data.config?.web_host || '127.0.0.1'),
      web_port: Number(data.config?.web_port ?? 10961),
    })
    setConfigOpen(true)
  }

  async function openUsage(targetSession = sessionKey): Promise<void> {
    setUsageLoading(true)
    setUsageError('')
    setUsageReport('')
    setUsageSession(targetSession)
    try {
      const query = new URLSearchParams({ session_key: targetSession })
      const data = await api<{ report?: string }>(`/api/usage?${query.toString()}`)
      setUsageReport(String(data.report || '').trim())
      setUsageOpen(true)
    } catch (e) {
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
        case 'telegram_bot_token':
          next.telegram_bot_token = ''
          break
        case 'bot_username':
          next.bot_username = ''
          break
        case 'discord_bot_token':
          next.discord_bot_token = ''
          break
        case 'discord_allowed_channels_csv':
          next.discord_allowed_channels_csv = ''
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
        default:
          break
      }
      return next
    })
  }

  async function saveConfigChanges(): Promise<void> {
    try {
      const payload: Record<string, unknown> = {
        llm_provider: String(configDraft.llm_provider || ''),
        model: String(configDraft.model || ''),
        bot_username: String(configDraft.bot_username || '').trim(),
        discord_allowed_channels: parseDiscordChannelCsv(String(configDraft.discord_allowed_channels_csv || '')),
        working_dir_isolation: normalizeWorkingDirIsolation(
          configDraft.working_dir_isolation || DEFAULT_CONFIG_VALUES.working_dir_isolation,
        ),
        max_tokens: Number(configDraft.max_tokens || 8192),
        max_tool_iterations: Number(configDraft.max_tool_iterations || 100),
        max_document_size_mb: Number(
          configDraft.max_document_size_mb || DEFAULT_CONFIG_VALUES.max_document_size_mb,
        ),
        show_thinking: Boolean(configDraft.show_thinking),
        web_enabled: Boolean(configDraft.web_enabled),
        web_host: String(configDraft.web_host || '127.0.0.1'),
        web_port: Number(configDraft.web_port || 10961),
      }
      if (String(configDraft.llm_provider || '').trim().toLowerCase() === 'custom') {
        payload.llm_base_url = String(configDraft.llm_base_url || '').trim() || null
      }
      const apiKey = String(configDraft.api_key || '').trim()
      if (apiKey) payload.api_key = apiKey

      const tg = String(configDraft.telegram_bot_token || '').trim()
      if (tg) payload.telegram_bot_token = tg

      const discordToken = String(configDraft.discord_bot_token || '').trim()
      if (discordToken) payload.discord_bot_token = discordToken

      await api('/api/config', { method: 'PUT', body: JSON.stringify(payload) })
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
        setError('')
        const data = await api<{ sessions?: SessionItem[] }>('/api/sessions')
        const loaded = Array.isArray(data.sessions) ? data.sessions : []
        setSessions(loaded)

        const latestSession = pickLatestSessionKey(loaded)
        const initialSession = latestSession

        setSessionKey(initialSession)
        writeSessionToUrl(initialSession)
        await loadHistory(initialSession)
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e))
      }
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    loadHistory(sessionKey).catch((e) => setError(e instanceof Error ? e.message : String(e)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionKey])

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
        <Dialog.Root open={configOpen} onOpenChange={setConfigOpen}>
          <Dialog.Content maxWidth="1120px" className="overflow-hidden flex flex-col" style={{ width: "1120px", height: "760px", maxWidth: "1120px", maxHeight: "760px" }}>
            <Dialog.Title>Settings</Dialog.Title>
            <Dialog.Description size="2" mb="3">
              Channel-first configuration. Save writes to microclaw.config.yaml. Restart is required.
            </Dialog.Description>
            <div className="mt-2 min-h-0 flex-1">
              {config ? (
                <Tabs.Root defaultValue="general" orientation="vertical" className="h-full min-h-0">
                <div className="grid h-full grid-cols-[240px_minmax(0,1fr)] gap-4">
                  <Card className="h-full p-3" style={sectionCardStyle}>
                    <Tabs.List className="mc-settings-tabs-list flex w-full flex-col gap-1">
                      <Text size="1" color="gray" className="px-2 pt-1 uppercase tracking-wide">Runtime</Text>
                      <Tabs.Trigger value="general" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">⚙️  General</Tabs.Trigger>
                      <Tabs.Trigger value="model" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">🧠  Model</Tabs.Trigger>

                      <Text size="1" color="gray" className="px-2 pt-3 uppercase tracking-wide">Channels</Text>
                      <Tabs.Trigger value="telegram" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">✈️  Telegram</Tabs.Trigger>
                      <Tabs.Trigger value="discord" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">💬  Discord</Tabs.Trigger>
                      
                      <Text size="1" color="gray" className="px-2 pt-3 uppercase tracking-wide">Integrations</Text>
                      <Tabs.Trigger value="web" className="mc-settings-tab-trigger w-full justify-start rounded-lg px-3 py-2 text-[18px] leading-6 bg-transparent data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-200 hover:bg-white/8">🌐  Web</Tabs.Trigger>
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
                        <Text size="1" color="gray" className="mt-1 block">max_tokens / max_tool_iterations / max_document_size_mb control response budget and tool loop safety.</Text>
                        <div className="mt-4 space-y-3">
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
                        <Text size="1" color="gray" className="mt-1 block">For custom providers set llm_base_url. Keep api_key empty only if your deployment handles auth elsewhere.</Text>
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

                          <ConfigFieldCard label="api_key" description={<>Provider API key. Leave blank to keep current secret unchanged.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.api_key || '')}
                              onChange={(e) => setConfigField('api_key', e.target.value)}
                              placeholder="sk-..."
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
                            <>Set <code>bot_username</code> without <code>@</code>.</>,
                            <>In groups, mention the bot to trigger replies.</>,
                          ]}
                        />
                        <Text size="1" color="gray" className="mt-3 block">
                          Required: bot token and username. Leave token unchanged if already configured.
                        </Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="telegram_bot_token" description={<>BotFather token for sending and receiving Telegram messages. Leave blank to keep current secret unchanged.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.telegram_bot_token || '')}
                              onChange={(e) => setConfigField('telegram_bot_token', e.target.value)}
                              placeholder="123456789:AA..."
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="bot_username" description={<>Telegram bot username without <code>@</code>, used for group mention trigger.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.bot_username || '')}
                              onChange={(e) => setConfigField('bot_username', e.target.value)}
                              placeholder="my_microclaw_bot"
                            />
                          </ConfigFieldCard>
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
                          Required: bot token. Optional: restrict handling to listed channel IDs.
                        </Text>
                        <div className="mt-4 space-y-3">
                          <ConfigFieldCard label="discord_bot_token" description={<>Discord bot token from Developer Portal. Leave blank to keep current secret unchanged.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.discord_bot_token || '')}
                              onChange={(e) => setConfigField('discord_bot_token', e.target.value)}
                              placeholder="MTAx..."
                            />
                          </ConfigFieldCard>
                          <ConfigFieldCard label="discord_allowed_channels" description={<>Optional allowlist. Only listed channel IDs can trigger the bot.</>}>
                            <TextField.Root
                              className="mt-2"
                              value={String(configDraft.discord_allowed_channels_csv || '')}
                              onChange={(e) => setConfigField('discord_allowed_channels_csv', e.target.value)}
                              placeholder="1234567890, 9876543210"
                            />
                          </ConfigFieldCard>
                        </div>
                      </div>
                    </Tabs.Content>

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
                        </div>
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
        <Dialog.Root open={usageOpen} onOpenChange={setUsageOpen}>
          <Dialog.Content maxWidth="980px" className="overflow-hidden flex flex-col" style={{ width: '980px', height: '720px', maxWidth: '980px', maxHeight: '720px' }}>
            <Dialog.Title>Usage Panel</Dialog.Title>
            <Dialog.Description size="2" mb="3">
              Token and cost summary for session <code>{usageSession || sessionKey}</code>
            </Dialog.Description>
            <div className="mb-3">
              <Flex gap="2">
                <Button size="2" variant="soft" onClick={() => void openUsage(sessionKey)} disabled={usageLoading}>
                  Refresh Current Session
                </Button>
                <Button size="2" variant="soft" onClick={() => void openUsage(usageSession || sessionKey)} disabled={usageLoading}>
                  Refresh This Panel
                </Button>
              </Flex>
            </div>
            <Card className="min-h-0 flex-1 overflow-auto p-3">
              {usageLoading ? (
                <Text size="2">Loading usage report...</Text>
              ) : usageError ? (
                <Callout.Root color="red" size="1" variant="soft">
                  <Callout.Text>{usageError}</Callout.Text>
                </Callout.Root>
              ) : (
                <pre className="whitespace-pre-wrap break-words text-[13px] leading-6">{usageReport || '(no usage data)'}</pre>
              )}
            </Card>
          </Dialog.Content>
        </Dialog.Root>
      </div>
    </Theme>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
