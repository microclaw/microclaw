import React, { useMemo } from 'react'
import { Button, Callout, Card, Dialog, Flex, Text } from '@radix-ui/themes'

export type MemoryObservability = {
  total: number
  active: number
  archived: number
  low_confidence: number
  avg_confidence: number
  reflector_runs_24h: number
  reflector_inserted_24h: number
  reflector_updated_24h: number
  reflector_skipped_24h: number
  injection_events_24h: number
  injection_selected_24h: number
  injection_candidates_24h: number
}

export type ReflectorRunPoint = {
  started_at: string
  inserted_count: number
  updated_count: number
  skipped_count: number
}

export type InjectionLogPoint = {
  created_at: string
  selected_count: number
  candidate_count: number
}

type UsagePanelProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  usageSession: string
  sessionKey: string
  usageLoading: boolean
  usageError: string
  usageReport: string
  usageMemory: MemoryObservability | null
  reflectorRuns: ReflectorRunPoint[]
  injectionLogs: InjectionLogPoint[]
  onRefreshCurrent: () => void
  onRefreshThis: () => void
}

function fmtInt(value: number): string {
  if (!Number.isFinite(value)) return '0'
  return Math.trunc(value).toLocaleString('en-US')
}

function fmtPct(num: number, den: number): string {
  if (!Number.isFinite(num) || !Number.isFinite(den) || den <= 0) return '0%'
  return `${((num / den) * 100).toFixed(1)}%`
}

function buildBuckets(
  points: Array<{ ts: string; a: number; b: number; c: number }>,
  hours: number,
  bucketHours: number,
): Array<{ label: string; a: number; b: number; c: number }> {
  const now = Date.now()
  const msPerHour = 3600 * 1000
  const start = now - hours * msPerHour
  const buckets = Math.max(1, Math.ceil(hours / bucketHours))
  const out = Array.from({ length: buckets }, (_, i) => ({
    label: `${i + 1}`,
    a: 0,
    b: 0,
    c: 0,
  }))
  for (const p of points) {
    const ts = Date.parse(p.ts)
    if (!Number.isFinite(ts) || ts < start || ts > now) continue
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor((ts - start) / (bucketHours * msPerHour))),
    )
    out[idx].a += p.a
    out[idx].b += p.b
    out[idx].c += p.c
  }
  return out
}

function sparklinePath(values: number[], width = 320, height = 70): string {
  if (values.length === 0) return ''
  const max = Math.max(...values, 1)
  const min = Math.min(...values, 0)
  const span = Math.max(1e-6, max - min)
  return values
    .map((v, i) => {
      const x = (i / Math.max(1, values.length - 1)) * width
      const y = height - ((v - min) / span) * height
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
}

function TrendRow({
  title,
  subtitle,
  values,
  color,
}: {
  title: string
  subtitle: string
  values: number[]
  color: string
}) {
  const d = sparklinePath(values)
  return (
    <Card className="p-3">
      <Text size="1" color="gray">{title}</Text>
      <Text size="1" color="gray" className="block">{subtitle}</Text>
      <div className="mt-2">
        <svg viewBox="0 0 320 70" className="h-[70px] w-full">
          <path d={d} fill="none" stroke={color} strokeWidth="2.5" />
        </svg>
      </div>
    </Card>
  )
}

export function UsagePanel(props: UsagePanelProps) {
  const {
    open,
    onOpenChange,
    usageSession,
    sessionKey,
    usageLoading,
    usageError,
    usageReport,
    usageMemory,
    reflectorRuns,
    injectionLogs,
    onRefreshCurrent,
    onRefreshThis,
  } = props

  const trend24h = useMemo(() => {
    const reflector = buildBuckets(
      reflectorRuns.map((r) => ({
        ts: r.started_at,
        a: r.inserted_count,
        b: r.updated_count,
        c: r.skipped_count,
      })),
      24,
      1,
    )
    const coverage = buildBuckets(
      injectionLogs.map((r) => ({
        ts: r.created_at,
        a: r.selected_count,
        b: r.candidate_count,
        c: 0,
      })),
      24,
      1,
    )
    return {
      inserted: reflector.map((r) => r.a),
      updated: reflector.map((r) => r.b),
      skipped: reflector.map((r) => r.c),
      coverage: coverage.map((r) => (r.b > 0 ? (r.a / r.b) * 100 : 0)),
    }
  }, [reflectorRuns, injectionLogs])

  const trend7d = useMemo(() => {
    const reflector = buildBuckets(
      reflectorRuns.map((r) => ({
        ts: r.started_at,
        a: r.inserted_count,
        b: r.updated_count,
        c: r.skipped_count,
      })),
      24 * 7,
      24,
    )
    const coverage = buildBuckets(
      injectionLogs.map((r) => ({
        ts: r.created_at,
        a: r.selected_count,
        b: r.candidate_count,
        c: 0,
      })),
      24 * 7,
      24,
    )
    return {
      inserted: reflector.map((r) => r.a),
      updated: reflector.map((r) => r.b),
      skipped: reflector.map((r) => r.c),
      coverage: coverage.map((r) => (r.b > 0 ? (r.a / r.b) * 100 : 0)),
    }
  }, [reflectorRuns, injectionLogs])

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Content maxWidth="980px" className="min-h-0 overflow-hidden flex flex-col" style={{ width: '980px', height: '760px', maxWidth: '980px', maxHeight: '760px' }}>
        <Dialog.Title>Usage Panel</Dialog.Title>
        <Dialog.Description size="2" mb="3">
          Token and memory observability for session <code>{usageSession || sessionKey}</code>
        </Dialog.Description>
        <div className="mb-3">
          <Flex gap="2">
            <Button size="2" variant="soft" onClick={onRefreshCurrent} disabled={usageLoading}>
              Refresh Current Session
            </Button>
            <Button size="2" variant="soft" onClick={onRefreshThis} disabled={usageLoading}>
              Refresh This Panel
            </Button>
          </Flex>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">
          <Card className="min-h-0 p-3">
            {usageLoading ? (
              <Text size="2">Loading usage report...</Text>
            ) : usageError ? (
              <Callout.Root color="red" size="1" variant="soft">
                <Callout.Text>{usageError}</Callout.Text>
              </Callout.Root>
            ) : (
              <div className="space-y-4">
                {usageMemory ? (
                  <div className="space-y-3">
                    <Flex justify="between" align="center">
                      <Text size="2" weight="bold">Memory Observability</Text>
                      <Text size="1" color="gray">24h + 7d trends</Text>
                    </Flex>
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
                      <Card className="p-3">
                        <Text size="1" color="gray" className="block">Memory Pool</Text>
                        <Text size="4" weight="bold" className="mt-1 block">{fmtInt(usageMemory.total)}</Text>
                        <Text size="1" color="gray" className="mt-1 block">
                          active {fmtInt(usageMemory.active)} / archived {fmtInt(usageMemory.archived)}
                        </Text>
                      </Card>
                      <Card className="p-3">
                        <Text size="1" color="gray" className="block">Avg Confidence</Text>
                        <Text size="4" weight="bold" className="mt-1 block">{(usageMemory.avg_confidence * 100).toFixed(1)}%</Text>
                        <Text size="1" color="gray" className="mt-1 block">low confidence: {fmtInt(usageMemory.low_confidence)}</Text>
                      </Card>
                      <Card className="p-3">
                        <Text size="1" color="gray" className="block">Reflector 24h</Text>
                        <Text size="4" weight="bold" className="mt-1 block">{fmtInt(usageMemory.reflector_runs_24h)}</Text>
                        <Text size="1" color="gray" className="mt-1 block">
                          +{fmtInt(usageMemory.reflector_inserted_24h)} / ~{fmtInt(usageMemory.reflector_updated_24h)} / -{fmtInt(usageMemory.reflector_skipped_24h)}
                        </Text>
                      </Card>
                      <Card className="p-3">
                        <Text size="1" color="gray" className="block">Injection Coverage 24h</Text>
                        <Text size="4" weight="bold" className="mt-1 block">
                          {fmtPct(usageMemory.injection_selected_24h, usageMemory.injection_candidates_24h)}
                        </Text>
                        <Text size="1" color="gray" className="mt-1 block">
                          {fmtInt(usageMemory.injection_selected_24h)} selected / {fmtInt(usageMemory.injection_candidates_24h)} candidates
                        </Text>
                      </Card>
                    </div>

                    <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                      <TrendRow title="Reflector Inserts (24h)" subtitle="hourly buckets" values={trend24h.inserted} color="#10b981" />
                      <TrendRow title="Reflector Updates (24h)" subtitle="hourly buckets" values={trend24h.updated} color="#3b82f6" />
                      <TrendRow title="Reflector Skips (24h)" subtitle="hourly buckets" values={trend24h.skipped} color="#f59e0b" />
                      <TrendRow title="Injection Coverage (24h)" subtitle="selected/candidates %" values={trend24h.coverage} color="#a855f7" />
                    </div>

                    <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                      <TrendRow title="Reflector Inserts (7d)" subtitle="daily buckets" values={trend7d.inserted} color="#059669" />
                      <TrendRow title="Reflector Updates (7d)" subtitle="daily buckets" values={trend7d.updated} color="#2563eb" />
                      <TrendRow title="Reflector Skips (7d)" subtitle="daily buckets" values={trend7d.skipped} color="#d97706" />
                      <TrendRow title="Injection Coverage (7d)" subtitle="selected/candidates %" values={trend7d.coverage} color="#7e22ce" />
                    </div>
                  </div>
                ) : null}
                <Card className="p-3">
                  <Text size="2" weight="bold">Token Usage Report</Text>
                  <pre className="mt-2 whitespace-pre-wrap break-words text-[13px] leading-6">{usageReport || '(no usage data)'}</pre>
                </Card>
              </div>
            )}
          </Card>
        </div>
      </Dialog.Content>
    </Dialog.Root>
  )
}
