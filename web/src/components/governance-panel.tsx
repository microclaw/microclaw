import React, { useEffect, useState } from 'react'
import { Badge, Button, Callout, Flex, Select, Switch, Text, TextField } from '@radix-ui/themes'
import { api } from '../lib/api'
import { ConfigFieldCard } from './config-field-card'

type ProgressChannel = {
  enabled: boolean
  groups: boolean
  min_turn_seconds: number
  update_interval_seconds: number
}

type ToolGrant = {
  chat_id?: number | null
  channel?: string | null
  principal?: string | null
  allow_tools: string[]
  deny_tools: string[]
  max_risk?: 'low' | 'medium' | 'high' | null
}

type Governance = {
  ok: boolean
  tool_policy: {
    mode: 'off' | 'warn' | 'block'
    deny_tools: string[]
    allow_tools: string[]
    max_risk?: 'low' | 'medium' | 'high' | null
    grants_mode: 'off' | 'warn' | 'block'
    control_chat_bypass: boolean
    grants: ToolGrant[]
  }
  egress_policy: {
    mode: 'off' | 'warn' | 'block'
    allow_hosts: string[]
    deny_hosts: string[]
    block_private_ips: boolean
  }
  sandbox_credentials: {
    credential_env_allowlist: string[]
    no_network: boolean
    security_profile: 'hardened' | 'standard' | 'privileged'
  }
  token_budget: {
    daily_per_chat: number
    exempt_control_chats: boolean
    enabled: boolean
  }
  heartbeat: {
    enabled: boolean
    interval_mins: number
    max_chars: number
  }
  progress_updates: Record<string, ProgressChannel>
  supervision: {
    restarts: { loop: string; restarts: number }[]
  }
  scheduled_tasks: {
    runs_24h: number
    success_24h: number
    with_contract: number
    dlq_pending: number
  }
  delivery?: {
    outbox_pending: number
  }
  durable_runs?: {
    active: {
      run_id?: string | null
      chat_id: number
      channel: string
      phase: string
      iteration: number
      resumable: boolean
      progress?: string | null
      tool_summary?: string | null
      started_at: string
      last_checkpoint_at?: string | null
    }[]
    recent_recoveries: {
      action: string
      status: string
      detail?: string | null
      created_at: string
    }[]
  }
}

function OnOff({ on }: { on: boolean }) {
  return <Badge size="1" color={on ? 'green' : 'gray'}>{on ? 'on' : 'off'}</Badge>
}

function parseToolList(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

export function GovernancePanel() {
  const [gov, setGov] = useState<Governance | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  // Editable drafts (initialized from the snapshot on load).
  const [mode, setMode] = useState<'off' | 'warn' | 'block'>('off')
  const [maxRisk, setMaxRisk] = useState<'none' | 'low' | 'medium' | 'high'>('none')
  const [denyTools, setDenyTools] = useState('')
  const [allowTools, setAllowTools] = useState('')
  const [grantsMode, setGrantsMode] = useState<'off' | 'warn' | 'block'>('off')
  const [controlChatBypass, setControlChatBypass] = useState(true)
  const [grantsJson, setGrantsJson] = useState('[]')
  const [egressMode, setEgressMode] = useState<'off' | 'warn' | 'block'>('off')
  const [egressAllowHosts, setEgressAllowHosts] = useState('')
  const [egressDenyHosts, setEgressDenyHosts] = useState('')
  const [blockPrivateIps, setBlockPrivateIps] = useState(true)
  const [credentialEnvAllowlist, setCredentialEnvAllowlist] = useState('')
  const [budget, setBudget] = useState('0')
  const [exemptControl, setExemptControl] = useState(true)
  const [hbEnabled, setHbEnabled] = useState(false)
  const [hbInterval, setHbInterval] = useState('30')
  const [hbMaxChars, setHbMaxChars] = useState('8000')

  const load = async () => {
    setError('')
    try {
      const g = await api<Governance>('/api/governance')
      setGov(g)
      setMode(g.tool_policy.mode)
      setMaxRisk(g.tool_policy.max_risk ?? 'none')
      setDenyTools(g.tool_policy.deny_tools.join(', '))
      setAllowTools(g.tool_policy.allow_tools.join(', '))
      setGrantsMode(g.tool_policy.grants_mode)
      setControlChatBypass(g.tool_policy.control_chat_bypass)
      setGrantsJson(JSON.stringify(g.tool_policy.grants, null, 2))
      setEgressMode(g.egress_policy.mode)
      setEgressAllowHosts(g.egress_policy.allow_hosts.join(', '))
      setEgressDenyHosts(g.egress_policy.deny_hosts.join(', '))
      setBlockPrivateIps(g.egress_policy.block_private_ips)
      setCredentialEnvAllowlist(g.sandbox_credentials.credential_env_allowlist.join(', '))
      setBudget(String(g.token_budget.daily_per_chat))
      setExemptControl(g.token_budget.exempt_control_chats)
      setHbEnabled(g.heartbeat.enabled)
      setHbInterval(String(g.heartbeat.interval_mins))
      setHbMaxChars(String(g.heartbeat.max_chars))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const saveSection = async (payload: Record<string, unknown>, label: string) => {
    setError('')
    setNotice('')
    try {
      await api('/api/config', { method: 'PUT', body: JSON.stringify(payload) })
      setNotice(`${label} saved. Restart MicroClaw to apply.`)
      await load()
    } catch (e) {
      setError(`Failed to save ${label}: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const saveToolPolicy = () => {
    try {
      const grants = JSON.parse(grantsJson) as unknown
      if (!Array.isArray(grants)) {
        throw new Error('grants must be a JSON array')
      }
      void saveSection(
        {
          tool_policy: {
            mode,
            deny_tools: parseToolList(denyTools),
            allow_tools: parseToolList(allowTools),
            max_risk: maxRisk === 'none' ? null : maxRisk,
            grants_mode: grantsMode,
            control_chat_bypass: controlChatBypass,
            grants,
          },
        },
        'Tool policy',
      )
    } catch (e) {
      setError(`Invalid grants JSON: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const saveEgressPolicy = () =>
    saveSection(
      {
        egress_policy: {
          mode: egressMode,
          allow_hosts: parseToolList(egressAllowHosts),
          deny_hosts: parseToolList(egressDenyHosts),
          block_private_ips: blockPrivateIps,
        },
      },
      'Egress policy',
    )

  const saveSandboxCredentials = () =>
    saveSection(
      {
        sandbox_credential_env_allowlist: parseToolList(credentialEnvAllowlist),
      },
      'Sandbox credential policy',
    )

  const saveTokenBudget = () =>
    saveSection(
      {
        token_budget: {
          daily_per_chat: Math.max(0, parseInt(budget, 10) || 0),
          exempt_control_chats: exemptControl,
        },
      },
      'Token budget',
    )

  const saveHeartbeat = () =>
    saveSection(
      {
        heartbeat: {
          enabled: hbEnabled,
          interval_mins: Math.max(1, parseInt(hbInterval, 10) || 30),
          max_chars: Math.max(100, parseInt(hbMaxChars, 10) || 8000),
        },
      },
      'Heartbeat',
    )

  return (
    <div className="flex flex-col gap-4">
      {error && (
        <Callout.Root color="red" size="1" variant="soft">
          <Callout.Text>{error}</Callout.Text>
        </Callout.Root>
      )}
      {notice && (
        <Callout.Root color="green" size="1" variant="soft">
          <Callout.Text>{notice}</Callout.Text>
        </Callout.Root>
      )}

      <Flex>
        <Button size="1" variant="soft" onClick={() => void load()}>Refresh</Button>
      </Flex>

      {gov && (
        <>
          <ConfigFieldCard
            label="Tool policy"
            description="Pre-tool-call gate enforced at the registry choke point (covers sub-agents). Saved to config.yaml; restart to apply."
          >
            <div className="mt-2 flex flex-col gap-3">
              <Flex align="center" gap="3" wrap="wrap">
                <Text size="1" color="gray">mode</Text>
                <Select.Root value={mode} onValueChange={(v) => setMode(v as typeof mode)}>
                  <Select.Trigger variant="surface" />
                  <Select.Content>
                    <Select.Item value="off">off — allow everything</Select.Item>
                    <Select.Item value="warn">warn — log violations, allow</Select.Item>
                    <Select.Item value="block">block — deny violations</Select.Item>
                  </Select.Content>
                </Select.Root>
                <Text size="1" color="gray">max risk</Text>
                <Select.Root value={maxRisk} onValueChange={(v) => setMaxRisk(v as typeof maxRisk)}>
                  <Select.Trigger variant="surface" />
                  <Select.Content>
                    <Select.Item value="none">unrestricted</Select.Item>
                    <Select.Item value="low">low</Select.Item>
                    <Select.Item value="medium">medium</Select.Item>
                    <Select.Item value="high">high</Select.Item>
                  </Select.Content>
                </Select.Root>
              </Flex>
              <div>
                <Text size="1" color="gray">deny tools (comma separated)</Text>
                <TextField.Root
                  className="mt-1"
                  value={denyTools}
                  onChange={(e) => setDenyTools(e.target.value)}
                  placeholder="execute_command, write_file"
                />
              </div>
              <div>
                <Text size="1" color="gray">allow tools — exempt from deny/max-risk (comma separated)</Text>
                <TextField.Root
                  className="mt-1"
                  value={allowTools}
                  onChange={(e) => setAllowTools(e.target.value)}
                  placeholder="read_file"
                />
              </div>
              <Flex align="center" gap="3" wrap="wrap">
                <Text size="1" color="gray">capability grants</Text>
                <Select.Root value={grantsMode} onValueChange={(v) => setGrantsMode(v as typeof grantsMode)}>
                  <Select.Trigger variant="surface" />
                  <Select.Content>
                    <Select.Item value="off">off</Select.Item>
                    <Select.Item value="warn">warn</Select.Item>
                    <Select.Item value="block">block</Select.Item>
                  </Select.Content>
                </Select.Root>
                <Text size="1" color="gray">control chats bypass grants</Text>
                <Switch checked={controlChatBypass} onCheckedChange={setControlChatBypass} />
              </Flex>
              <div>
                <Text as="div" size="1" color="gray">
                  per-chat / channel / principal grants (JSON array; trailing * wildcards are supported)
                </Text>
                <textarea
                  className="mt-1 min-h-32 w-full rounded-md border border-white/10 bg-black/20 p-2 font-mono text-xs"
                  value={grantsJson}
                  onChange={(e) => setGrantsJson(e.target.value)}
                  spellCheck={false}
                />
              </div>
              <Flex>
                <Button size="1" onClick={() => void saveToolPolicy()}>Save tool policy</Button>
              </Flex>
            </div>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Outbound network policy"
            description="Checks HTTP(S) destinations at the shared tool boundary and validates configured endpoints on startup."
          >
            <div className="mt-2 flex flex-col gap-3">
              <Flex align="center" gap="3" wrap="wrap">
                <Text size="1" color="gray">mode</Text>
                <Select.Root value={egressMode} onValueChange={(v) => setEgressMode(v as typeof egressMode)}>
                  <Select.Trigger variant="surface" />
                  <Select.Content>
                    <Select.Item value="off">off</Select.Item>
                    <Select.Item value="warn">warn</Select.Item>
                    <Select.Item value="block">block</Select.Item>
                  </Select.Content>
                </Select.Root>
                <Text size="1" color="gray">block private / metadata IPs</Text>
                <Switch checked={blockPrivateIps} onCheckedChange={setBlockPrivateIps} />
              </Flex>
              <div>
                <Text size="1" color="gray">allowed hosts (empty permits public hosts; supports *.example.com)</Text>
                <TextField.Root
                  className="mt-1"
                  value={egressAllowHosts}
                  onChange={(e) => setEgressAllowHosts(e.target.value)}
                  placeholder="api.openai.com, *.example.com"
                />
              </div>
              <div>
                <Text size="1" color="gray">denied hosts</Text>
                <TextField.Root
                  className="mt-1"
                  value={egressDenyHosts}
                  onChange={(e) => setEgressDenyHosts(e.target.value)}
                  placeholder="tracking.example.com"
                />
              </div>
              <Flex>
                <Button size="1" onClick={() => void saveEgressPolicy()}>Save egress policy</Button>
              </Flex>
            </div>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Sandbox credentials"
            description="Credential-like environment variables are withheld from containers by default. Add only exact names a sandboxed tool must receive."
          >
            <div className="mt-2 flex flex-col gap-3">
              <Flex align="center" gap="2" wrap="wrap">
                <Badge size="1" color={gov.sandbox_credentials.no_network ? 'green' : 'orange'}>
                  network: {gov.sandbox_credentials.no_network ? 'disabled' : 'enabled'}
                </Badge>
                <Badge size="1" color={gov.sandbox_credentials.security_profile === 'hardened' ? 'green' : 'orange'}>
                  {gov.sandbox_credentials.security_profile}
                </Badge>
              </Flex>
              <div>
                <Text size="1" color="gray">credential environment allowlist (exact names, comma separated)</Text>
                <TextField.Root
                  className="mt-1"
                  value={credentialEnvAllowlist}
                  onChange={(e) => setCredentialEnvAllowlist(e.target.value)}
                  placeholder="SEARCH_API_TOKEN"
                />
              </div>
              <Flex>
                <Button size="1" onClick={() => void saveSandboxCredentials()}>Save credential policy</Button>
              </Flex>
            </div>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Token budget"
            description="Per-chat rolling 24h token cap. 0 = unlimited."
          >
            <div className="mt-2 flex flex-col gap-3">
              <Flex align="center" gap="3" wrap="wrap">
                <Text size="1" color="gray">daily tokens per chat</Text>
                <TextField.Root
                  type="number"
                  value={budget}
                  onChange={(e) => setBudget(e.target.value)}
                  style={{ width: 140 }}
                />
                <Text size="1" color="gray">exempt control chats</Text>
                <Switch checked={exemptControl} onCheckedChange={setExemptControl} />
              </Flex>
              <Flex>
                <Button size="1" onClick={() => void saveTokenBudget()}>Save token budget</Button>
              </Flex>
            </div>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Proactive heartbeat"
            description="Periodic HEARTBEAT.md sweep that lets the bot check in on its own."
          >
            <div className="mt-2 flex flex-col gap-3">
              <Flex align="center" gap="3" wrap="wrap">
                <Text size="1" color="gray">enabled</Text>
                <Switch checked={hbEnabled} onCheckedChange={setHbEnabled} />
                <Text size="1" color="gray">every (min)</Text>
                <TextField.Root
                  type="number"
                  value={hbInterval}
                  onChange={(e) => setHbInterval(e.target.value)}
                  style={{ width: 90 }}
                />
                <Text size="1" color="gray">max chars</Text>
                <TextField.Root
                  type="number"
                  value={hbMaxChars}
                  onChange={(e) => setHbMaxChars(e.target.value)}
                  style={{ width: 110 }}
                />
              </Flex>
              <Flex>
                <Button size="1" onClick={() => void saveHeartbeat()}>Save heartbeat</Button>
              </Flex>
            </div>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Progress heartbeats (non-web channels)"
            description="Live '⏳ Working…' message edited in place during long turns. Configure under channels.<name>.progress_updates in config.yaml."
          >
            <div className="mt-2 flex flex-col gap-1">
              {Object.entries(gov.progress_updates).map(([name, p]) => (
                <Flex key={name} align="center" gap="2" wrap="wrap">
                  <Text size="1" style={{ width: 80 }}>{name}</Text>
                  <OnOff on={p.enabled} />
                  {p.enabled && (
                    <>
                      <Badge size="1" color="gray">groups: {p.groups ? 'yes' : 'no'}</Badge>
                      <Badge size="1" color="gray">min turn {p.min_turn_seconds}s</Badge>
                      <Badge size="1" color="gray">every {p.update_interval_seconds}s</Badge>
                    </>
                  )}
                </Flex>
              ))}
            </div>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Background loop health"
            description="Supervised loops restarted after a panic since process start. Empty = healthy."
          >
            <div className="mt-2">
              {gov.supervision.restarts.length === 0 && (
                <Badge size="1" color="green">no restarts — all loops healthy</Badge>
              )}
              {gov.supervision.restarts.map((r) => (
                <Flex key={r.loop} align="center" gap="2" className="py-0.5">
                  <Badge size="1" color="red">{r.loop}</Badge>
                  <Text size="1" color="gray">{r.restarts} restart(s) after panic</Text>
                </Flex>
              ))}
            </div>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Delivery & task health (24h)"
            description="Run outcomes, contract coverage, dead-letter queue and reply-outbox depth."
          >
            <Flex align="center" gap="2" className="mt-2" wrap="wrap">
              <Badge size="1" color="blue">{gov.scheduled_tasks.runs_24h} runs</Badge>
              <Badge size="1" color={gov.scheduled_tasks.success_24h === gov.scheduled_tasks.runs_24h ? 'green' : 'orange'}>
                {gov.scheduled_tasks.success_24h} succeeded
              </Badge>
              <Badge size="1" color="green">{gov.scheduled_tasks.with_contract} with contract</Badge>
              <Badge size="1" color={gov.scheduled_tasks.dlq_pending > 0 ? 'red' : 'gray'}>
                DLQ pending: {gov.scheduled_tasks.dlq_pending}
              </Badge>
              <Badge size="1" color={(gov.delivery?.outbox_pending ?? 0) > 0 ? 'orange' : 'gray'}>
                reply outbox: {gov.delivery?.outbox_pending ?? 0}
              </Badge>
            </Flex>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Durable coworker runs"
            description="Live agent-loop checkpoints and recent restart outcomes. A resumable checkpoint can continue automatically; an uncertain tool boundary always stops for verification."
          >
            <div className="mt-2 flex flex-col gap-2">
              {(gov.durable_runs?.active.length ?? 0) === 0 && (
                <Badge size="1" color="green">no interactive runs in flight</Badge>
              )}
              {gov.durable_runs?.active.map((run) => (
                <div key={`${run.channel}:${run.chat_id}`} className="rounded-md border border-white/10 p-2">
                  <Flex align="center" gap="2" wrap="wrap">
                    <Badge size="1" color={run.resumable ? 'green' : 'orange'}>
                      {run.resumable ? 'resumable' : 'uncertain boundary'}
                    </Badge>
                    <Text size="1">{run.channel}:{run.chat_id}</Text>
                    <Badge size="1" color="gray">{run.phase}</Badge>
                    <Badge size="1" color="gray">iteration {run.iteration + 1}</Badge>
                  </Flex>
                  {(run.progress || run.tool_summary) && (
                    <Text as="div" size="1" color="gray" className="mt-1">
                      {run.progress ?? run.tool_summary}
                    </Text>
                  )}
                </div>
              ))}
              {(gov.durable_runs?.recent_recoveries.length ?? 0) > 0 && (
                <div className="mt-1">
                  <Text as="div" size="1" weight="bold">Recent restart outcomes</Text>
                  {gov.durable_runs?.recent_recoveries.slice(0, 5).map((event, index) => (
                    <Flex key={`${event.created_at}:${index}`} align="center" gap="2" className="py-0.5" wrap="wrap">
                      <Badge size="1" color={event.action === 'resume' ? 'green' : 'orange'}>{event.action}</Badge>
                      <Text size="1" color="gray">{event.created_at}</Text>
                      {event.detail && <Text size="1" color="gray">{event.detail}</Text>}
                    </Flex>
                  ))}
                </div>
              )}
            </div>
          </ConfigFieldCard>
        </>
      )}
    </div>
  )
}
