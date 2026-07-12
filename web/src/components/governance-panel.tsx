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

type Governance = {
  ok: boolean
  tool_policy: {
    mode: 'off' | 'warn' | 'block'
    deny_tools: string[]
    allow_tools: string[]
    max_risk?: 'low' | 'medium' | 'high' | null
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

  const saveToolPolicy = () =>
    saveSection(
      {
        tool_policy: {
          mode,
          deny_tools: parseToolList(denyTools),
          allow_tools: parseToolList(allowTools),
          max_risk: maxRisk === 'none' ? null : maxRisk,
        },
      },
      'Tool policy',
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
              <Flex>
                <Button size="1" onClick={() => void saveToolPolicy()}>Save tool policy</Button>
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
        </>
      )}
    </div>
  )
}
