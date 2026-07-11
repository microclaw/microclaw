import React, { useEffect, useState } from 'react'
import { Badge, Button, Callout, Card, Flex, Select, Text } from '@radix-ui/themes'
import { api } from '../lib/api'
import { ConfigFieldCard } from './config-field-card'

export type TaskView = {
  id: number
  chat_id: number
  prompt: string
  schedule_type: string
  schedule_value: string
  timezone: string
  status: string
  next_run: string
  next_run_in?: string | null
  last_run?: string | null
  created_at: string
  cadence: string
  run_count: number
  max_runs?: number | null
  not_after?: string | null
  has_contract: boolean
}

type TaskRun = {
  id: number
  started_at: string
  finished_at: string
  duration_ms: number
  success: boolean
  result_summary?: string | null
}

const STATUS_COLORS: Record<string, 'green' | 'orange' | 'gray' | 'red' | 'blue'> = {
  active: 'green',
  paused: 'orange',
  running: 'blue',
  completed: 'gray',
  cancelled: 'gray',
  failed: 'red',
}

export function TasksPanel() {
  const [tasks, setTasks] = useState<TaskView[]>([])
  const [statusFilter, setStatusFilter] = useState('all')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [runsFor, setRunsFor] = useState<number | null>(null)
  const [runs, setRuns] = useState<TaskRun[]>([])

  const loadTasks = async (filter = statusFilter) => {
    setLoading(true)
    setError('')
    try {
      const qs = filter === 'all' ? '' : `?status=${encodeURIComponent(filter)}`
      const res = await api<{ ok: boolean; tasks: TaskView[] }>(`/api/tasks${qs}`)
      setTasks(res.tasks)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadTasks()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter])

  const doAction = async (id: number, action: 'pause' | 'resume' | 'cancel') => {
    if (action === 'cancel' && !window.confirm(`Cancel task #${id}? This cannot be undone.`)) return
    setError('')
    try {
      await api(`/api/tasks/${id}/${action}`, { method: 'POST' })
      await loadTasks()
    } catch (e) {
      setError(`Failed to ${action} task #${id}: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const toggleRuns = async (id: number) => {
    if (runsFor === id) {
      setRunsFor(null)
      setRuns([])
      return
    }
    try {
      const res = await api<{ ok: boolean; runs: TaskRun[] }>(`/api/tasks/${id}/runs`)
      setRunsFor(id)
      setRuns(res.runs)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {error && (
        <Callout.Root color="red" size="1" variant="soft">
          <Callout.Text>{error}</Callout.Text>
        </Callout.Root>
      )}

      <ConfigFieldCard
        label="Scheduled Tasks"
        description="All scheduled tasks across chats: cadence, run progress, deadlines and completion contracts. Pause, resume or cancel without touching the chat."
      >
        <Flex align="center" gap="3" className="mt-2">
          <Select.Root value={statusFilter} onValueChange={setStatusFilter}>
            <Select.Trigger variant="surface" />
            <Select.Content>
              <Select.Item value="all">All statuses</Select.Item>
              <Select.Item value="active">Active</Select.Item>
              <Select.Item value="paused">Paused</Select.Item>
              <Select.Item value="running">Running</Select.Item>
              <Select.Item value="completed">Completed</Select.Item>
              <Select.Item value="cancelled">Cancelled</Select.Item>
              <Select.Item value="failed">Failed</Select.Item>
            </Select.Content>
          </Select.Root>
          <Button size="1" variant="soft" onClick={() => void loadTasks()}>Refresh</Button>
          {loading && <Text size="1" color="gray">Loading…</Text>}
        </Flex>

        <div className="flex flex-col gap-2 mt-3">
          {!loading && tasks.length === 0 && (
            <Text size="1" color="gray">No scheduled tasks{statusFilter !== 'all' ? ` with status "${statusFilter}"` : ''}.</Text>
          )}
          {tasks.map((task) => (
            <Card key={task.id} variant="surface" className="p-3">
              <Flex justify="between" align="start" gap="3">
                <Flex direction="column" gap="1" style={{ flex: 1, minWidth: 0 }}>
                  <Flex align="center" gap="2" wrap="wrap">
                    <Text weight="bold" size="2">#{task.id}</Text>
                    <Badge size="1" color={STATUS_COLORS[task.status] || 'gray'}>{task.status}</Badge>
                    <Badge size="1" color="gray">chat {task.chat_id}</Badge>
                    <Badge size="1" color="blue">{task.cadence}</Badge>
                    {task.max_runs != null && (
                      <Badge size="1" color="purple">runs {task.run_count}/{task.max_runs}</Badge>
                    )}
                    {task.max_runs == null && task.run_count > 0 && (
                      <Badge size="1" color="gray">runs {task.run_count}</Badge>
                    )}
                    {task.not_after && (
                      <Badge size="1" color="orange">until {task.not_after}</Badge>
                    )}
                    {task.has_contract && (
                      <Badge size="1" color="green" title="Completion contract: exit criteria verified after each run">contract</Badge>
                    )}
                  </Flex>
                  <Text
                    size="1"
                    color="gray"
                    style={{
                      display: '-webkit-box',
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: 'vertical' as any,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {task.prompt}
                  </Text>
                  <Text size="1" color="gray">
                    next: {task.next_run}
                    {task.next_run_in ? ` (in ${task.next_run_in})` : ''}
                    {task.last_run ? ` · last: ${task.last_run}` : ''}
                  </Text>
                </Flex>
                <Flex direction="column" gap="2" align="end">
                  <Flex gap="2">
                    {task.status === 'active' && (
                      <Button size="1" variant="soft" onClick={() => void doAction(task.id, 'pause')}>Pause</Button>
                    )}
                    {task.status === 'paused' && (
                      <Button size="1" variant="soft" color="green" onClick={() => void doAction(task.id, 'resume')}>Resume</Button>
                    )}
                    {(task.status === 'active' || task.status === 'paused') && (
                      <Button size="1" variant="soft" color="red" onClick={() => void doAction(task.id, 'cancel')}>Cancel</Button>
                    )}
                  </Flex>
                  <Button size="1" variant="ghost" onClick={() => void toggleRuns(task.id)}>
                    {runsFor === task.id ? 'Hide runs' : 'Runs'}
                  </Button>
                </Flex>
              </Flex>
              {runsFor === task.id && (
                <div className="mt-2 border-t border-white/10 pt-2">
                  {runs.length === 0 && <Text size="1" color="gray">No runs recorded yet.</Text>}
                  {runs.map((run) => (
                    <Flex key={run.id} align="center" gap="2" className="py-0.5" wrap="wrap">
                      <Badge size="1" color={run.success ? 'green' : 'red'}>{run.success ? 'ok' : 'failed'}</Badge>
                      <Text size="1" color="gray">{run.started_at}</Text>
                      <Text size="1" color="gray">{run.duration_ms} ms</Text>
                      {run.result_summary && (
                        <Text size="1" color="gray" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 480 }}>
                          {run.result_summary}
                        </Text>
                      )}
                    </Flex>
                  ))}
                </div>
              )}
            </Card>
          ))}
        </div>
      </ConfigFieldCard>
    </div>
  )
}
