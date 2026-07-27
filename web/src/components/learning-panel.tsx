import React, { useEffect, useState } from 'react'
import { Badge, Button, Callout, Flex, Text } from '@radix-ui/themes'
import { api } from '../lib/api'

type Run = {
  run_id: string
  status: string
  run_kind: string
  objective: string
  result_summary?: string | null
  started_at: string
  input_tokens: number
  output_tokens: number
  tool_calls: number
  tool_errors: number
  task_signature: {
    task_type: string
    task_family: string
    capability_tags: string[]
  }
}

type Outcome = {
  envelope_id: string
  schema_version: number
  source_kind: string
  source_name: string
  verdict: string
  confidence: number
  evidence?: string | null
}

type Retrieval = {
  source_run_id: string
  rank: number
  selection_reason: string
  relevance_score: number
  source_objective: string
  source_result_summary?: string | null
}

type Skill = {
  skill_name: string
  skill_version?: number | null
}

type Detail = {
  run: Run
  outcomes: Outcome[]
  retrieved_experiences: Retrieval[]
  activated_skills: Skill[]
}

type ObservabilityResponse = {
  recent_runs: Run[]
  skill_task_utilities: SkillUtility[]
}

type SkillUtility = {
  skill_name: string
  skill_version: number
  task_type: string
  task_family: string
  total_outcomes: number
  success_rate: number
  utility_lower_bound: number
}

type DetailResponse = {
  detail: Detail
}

export function LearningPanel({ sessionKey }: { sessionKey: string }) {
  const [runs, setRuns] = useState<Run[]>([])
  const [utilities, setUtilities] = useState<SkillUtility[]>([])
  const [detail, setDetail] = useState<Detail | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const loadDetail = async (runId: string) => {
    setError('')
    try {
      const result = await api<DetailResponse>(
        `/api/learning/experiences/${encodeURIComponent(runId)}?session_key=${encodeURIComponent(sessionKey)}`,
      )
      setDetail(result.detail)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const result = await api<ObservabilityResponse>(
        `/api/learning_observability?session_key=${encodeURIComponent(sessionKey)}`,
      )
      setRuns(result.recent_runs)
      setUtilities(result.skill_task_utilities)
      if (result.recent_runs.length > 0) {
        await loadDetail(result.recent_runs[0].run_id)
      } else {
        setDetail(null)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [sessionKey])

  return (
    <div className="mt-3 flex flex-col gap-3">
      {error && (
        <Callout.Root color="red" size="1" variant="soft">
          <Callout.Text>{error}</Callout.Text>
        </Callout.Root>
      )}
      <Flex align="center" gap="2">
        <Button size="1" variant="soft" disabled={loading} onClick={() => void load()}>
          {loading ? 'Loading…' : 'Refresh'}
        </Button>
        <Text size="1" color="gray">{runs.length} recent run(s)</Text>
      </Flex>

      {utilities.length > 0 && (
        <div className="rounded-md border border-white/10 p-3">
          <Text as="div" size="2" weight="bold">Risk-adjusted skill utility by task family</Text>
          <div className="mt-2 grid gap-2 md:grid-cols-2">
            {utilities.slice(0, 12).map((item) => (
              <div
                key={`${item.skill_name}:${item.skill_version}:${item.task_family}`}
                className="rounded-md bg-black/20 p-2"
              >
                <Flex align="center" gap="2" wrap="wrap">
                  <Text size="1" weight="bold">{item.skill_name} v{item.skill_version}</Text>
                  <Badge size="1" color="purple">{item.task_family}</Badge>
                  <Badge size="1" color="gray">n={item.total_outcomes}</Badge>
                </Flex>
                <Text as="div" size="1" color="gray" className="mt-1">
                  pass {(item.success_rate * 100).toFixed(0)}% · conservative utility floor{' '}
                  {(item.utility_lower_bound * 100).toFixed(0)}%
                </Text>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid min-h-0 grid-cols-[minmax(220px,0.8fr)_minmax(0,1.7fr)] gap-3">
        <div className="max-h-[65vh] overflow-auto rounded-md border border-white/10 p-2">
          {runs.length === 0 && <Text size="1" color="gray">No learning runs for this session.</Text>}
          {runs.map((run) => (
            <button
              key={run.run_id}
              type="button"
              onClick={() => void loadDetail(run.run_id)}
              className="mb-2 block w-full rounded-md border border-white/10 p-2 text-left hover:bg-white/5"
            >
              <Flex align="center" gap="2" wrap="wrap">
                <Badge size="1" color={run.status === 'completed' ? 'green' : 'orange'}>{run.status}</Badge>
                <Badge size="1" color="gray">{run.run_kind}</Badge>
              </Flex>
              <Text as="div" size="1" weight="bold" className="mt-1">{run.objective}</Text>
              <Text as="div" size="1" color="gray" className="mt-1 font-mono">{run.run_id}</Text>
            </button>
          ))}
        </div>

        <div className="max-h-[65vh] overflow-auto rounded-md border border-white/10 p-3">
          {!detail && <Text size="1" color="gray">Select a run to inspect its learning evidence.</Text>}
          {detail && (
            <div className="flex flex-col gap-4">
              <div>
                <Text as="div" size="2" weight="bold">{detail.run.objective}</Text>
                <Text as="div" size="1" color="gray" className="mt-1">
                  {detail.run.result_summary || '(no result summary)'}
                </Text>
                <Flex gap="2" wrap="wrap" className="mt-2">
                  <Badge size="1" color="blue">{detail.run.task_signature.task_type}</Badge>
                  <Badge size="1" color="purple">{detail.run.task_signature.task_family}</Badge>
                  <Badge size="1" color="gray">
                    {detail.run.input_tokens + detail.run.output_tokens} tokens
                  </Badge>
                  <Badge size="1" color={detail.run.tool_errors > 0 ? 'red' : 'gray'}>
                    {detail.run.tool_calls} tools / {detail.run.tool_errors} errors
                  </Badge>
                </Flex>
                <Flex gap="1" wrap="wrap" className="mt-1">
                  {detail.run.task_signature.capability_tags.map((tag) => (
                    <Badge key={tag} size="1" color="gray">{tag}</Badge>
                  ))}
                </Flex>
              </div>

              <div>
                <Text as="div" size="2" weight="bold">
                  Prior experiences used ({detail.retrieved_experiences.length})
                </Text>
                {detail.retrieved_experiences.length === 0 && (
                  <Text size="1" color="gray">None.</Text>
                )}
                {detail.retrieved_experiences.map((item) => (
                  <div key={item.source_run_id} className="mt-2 rounded-md bg-black/20 p-2">
                    <Text as="div" size="1" className="font-mono">
                      #{item.rank} {item.source_run_id} · score {item.relevance_score.toFixed(3)}
                    </Text>
                    <Text as="div" size="1" weight="bold">{item.source_objective}</Text>
                    <Text as="div" size="1" color="gray">
                      {item.source_result_summary || '(no result summary)'}
                    </Text>
                    <Text as="div" size="1" color="gray">{item.selection_reason}</Text>
                  </div>
                ))}
              </div>

              <div>
                <Text as="div" size="2" weight="bold">Outcome evidence ({detail.outcomes.length})</Text>
                {detail.outcomes.length === 0 && <Text size="1" color="gray">None.</Text>}
                {detail.outcomes.map((outcome) => (
                  <div key={outcome.envelope_id} className="mt-2 rounded-md bg-black/20 p-2">
                    <Flex align="center" gap="2" wrap="wrap">
                      <Badge size="1" color={outcome.verdict === 'passed' ? 'green' : 'red'}>
                        {outcome.verdict}
                      </Badge>
                      <Text size="1">{outcome.source_kind}:{outcome.source_name}</Text>
                      <Badge size="1" color="gray">v{outcome.schema_version}</Badge>
                      <Badge size="1" color="gray">{outcome.confidence.toFixed(2)}</Badge>
                    </Flex>
                    <Text as="div" size="1" color="gray" className="mt-1 whitespace-pre-wrap">
                      {outcome.evidence || '(no evidence text)'}
                    </Text>
                  </div>
                ))}
              </div>

              <div>
                <Text as="div" size="2" weight="bold">Skills used ({detail.activated_skills.length})</Text>
                <Flex gap="2" wrap="wrap" className="mt-1">
                  {detail.activated_skills.map((skill) => (
                    <Badge key={`${skill.skill_name}:${skill.skill_version ?? '?'}`} size="1" color="blue">
                      {skill.skill_name} v{skill.skill_version ?? '?'}
                    </Badge>
                  ))}
                </Flex>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
