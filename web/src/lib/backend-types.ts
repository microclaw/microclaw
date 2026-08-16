// Shared response/payload shapes for the web backend API, plus doc links
// for config warnings.

export type ConfigPayload = Record<string, unknown>

export type StreamEvent = {
  event: string
  payload: Record<string, unknown>
}

export type AuthStatusResponse = {
  ok?: boolean
  authenticated?: boolean
  has_password?: boolean
  using_default_password?: boolean
}

export type HealthResponse = {
  version?: string
}

export type BackendMessage = {
  id?: string
  sender_name?: string
  content?: string
  is_from_bot?: boolean
  timestamp?: string
}

export type ConfigWarning = {
  code?: string
  severity?: string
  message?: string
}

export type ExecutionPolicyItem = {
  tool?: string
  risk?: string
  policy?: string
}

export type MountAllowlistStatus = {
  path?: string
  exists?: boolean
  has_entries?: boolean
}

export type SecurityPosture = {
  sandbox_mode?: 'off' | 'all' | string
  sandbox_runtime_available?: boolean
  sandbox_backend?: string
  sandbox_require_runtime?: boolean
  execution_policies?: ExecutionPolicyItem[]
  mount_allowlist?: MountAllowlistStatus | null
}

export type ConfigSelfCheck = {
  ok?: boolean
  risk_level?: 'none' | 'medium' | 'high' | string
  warning_count?: number
  warnings?: ConfigWarning[]
  security_posture?: SecurityPosture
}

export type A2APeerDraft = {
  name: string
  enabled: boolean
  base_url: string
  bearer_token: string
  has_bearer_token?: boolean
  description: string
  default_session_key: string
}

export type ProviderProfileDraft = {
  id: string
  provider: string
  api_key: string
  llm_base_url: string
  llm_user_agent: string
  default_model: string
  show_thinking: boolean
}

export const DOCS_BASE = 'https://microclaw.org/docs'

export function warningDocUrl(code?: string): string {
  switch (code) {
    case 'sandbox_disabled':
    case 'sandbox_runtime_unavailable':
    case 'sandbox_mount_allowlist_missing':
      return `${DOCS_BASE}/configuration#sandbox`
    case 'auth_password_not_configured':
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

export type ToolStartPayload = {
  tool_use_id: string
  name: string
  input?: unknown
}

export type ToolResultPayload = {
  tool_use_id: string
  name: string
  is_error?: boolean
  output?: unknown
  duration_ms?: number
  bytes?: number
  status_code?: number
  error_type?: string
}
