import React, { useEffect, useState } from 'react'
import { Badge, Button, Callout, Card, Flex, Text } from '@radix-ui/themes'
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
}

const MODE_COLORS: Record<string, 'gray' | 'orange' | 'red'> = {
  off: 'gray',
  warn: 'orange',
  block: 'red',
}

function OnOff({ on }: { on: boolean }) {
  return <Badge size="1" color={on ? 'green' : 'gray'}>{on ? 'on' : 'off'}</Badge>
}

export function GovernancePanel() {
  const [gov, setGov] = useState<Governance | null>(null)
  const [error, setError] = useState('')

  const load = async () => {
    setError('')
    try {
      setGov(await api<Governance>('/api/governance'))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  return (
    <div className="flex flex-col gap-4">
      {error && (
        <Callout.Root color="red" size="1" variant="soft">
          <Callout.Text>{error}</Callout.Text>
        </Callout.Root>
      )}

      <Flex>
        <Button size="1" variant="soft" onClick={() => void load()}>Refresh</Button>
      </Flex>

      {gov && (
        <>
          <ConfigFieldCard
            label="Tool policy"
            description="Pre-tool-call gate enforced at the registry choke point (covers sub-agents). Edit via tool_policy in config.yaml."
          >
            <Flex align="center" gap="2" className="mt-2" wrap="wrap">
              <Badge size="1" color={MODE_COLORS[gov.tool_policy.mode] || 'gray'}>mode: {gov.tool_policy.mode}</Badge>
              {gov.tool_policy.max_risk && <Badge size="1" color="orange">max risk: {gov.tool_policy.max_risk}</Badge>}
            </Flex>
            {gov.tool_policy.deny_tools.length > 0 && (
              <Text size="1" color="gray" className="mt-2 block">deny: {gov.tool_policy.deny_tools.join(', ')}</Text>
            )}
            {gov.tool_policy.allow_tools.length > 0 && (
              <Text size="1" color="gray" className="mt-1 block">allow (wins): {gov.tool_policy.allow_tools.join(', ')}</Text>
            )}
            {gov.tool_policy.mode === 'off' && (
              <Text size="1" color="gray" className="mt-2 block">Policy is off — every tool call is permitted (guardrail warnings still apply).</Text>
            )}
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Token budget"
            description="Per-chat rolling 24h token cap. 0 = unlimited."
          >
            <Flex align="center" gap="2" className="mt-2" wrap="wrap">
              <OnOff on={gov.token_budget.enabled} />
              {gov.token_budget.enabled && (
                <Badge size="1" color="blue">{gov.token_budget.daily_per_chat.toLocaleString()} tokens / chat / 24h</Badge>
              )}
              {gov.token_budget.enabled && gov.token_budget.exempt_control_chats && (
                <Badge size="1" color="gray">control chats exempt</Badge>
              )}
            </Flex>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Proactive heartbeat"
            description="Periodic HEARTBEAT.md sweep that lets the bot check in on its own."
          >
            <Flex align="center" gap="2" className="mt-2" wrap="wrap">
              <OnOff on={gov.heartbeat.enabled} />
              {gov.heartbeat.enabled && (
                <Badge size="1" color="blue">every {gov.heartbeat.interval_mins} min</Badge>
              )}
            </Flex>
          </ConfigFieldCard>

          <ConfigFieldCard
            label="Progress heartbeats (non-web channels)"
            description="Live '⏳ Working…' message edited in place during long turns."
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
            label="Scheduled-task health (24h)"
            description="Run outcomes, contract coverage and dead-letter queue depth."
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
            </Flex>
          </ConfigFieldCard>
        </>
      )}
    </div>
  )
}
