// Chat thread pane: assistant/user message renderers, tool-call cards,
// the think-segment disclosure, and the high-risk approval button bar.
import {
  AssistantRuntimeProvider,
  MessagePrimitive,
  useMessage,
  useLocalRuntime,
  useThreadRuntime,
  type ChatModelAdapter,
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
import remarkBreaks from 'remark-breaks'
import remarkGfm from 'remark-gfm'
import { collectThinkText, extractThinkSegments } from '../lib/think'
import { asObject, formatUnknown } from '../lib/json-utils'

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
        <details className="mc-think-details" open>
          <summary>
            <span className="mc-think-summary-icon" aria-hidden="true" />
            <span>Thinking & Processing ...</span>
          </summary>
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

export type PendingApproval = {
  approvalId: string
  tool: string
  preview: string | null
  options: string[]
  advisory: string | null
}

// Option-card buttons for a paused high-risk approval. Clicking sends the
// bare option number ("1"/"2"/"3") through the normal composer path — the
// backend recognizes numbered replies, so the button bar is sugar over the
// same contract as typing.
function ApprovalBar({ approval }: { approval: PendingApproval }) {
  const threadRuntime = useThreadRuntime()
  const labels = approval.options.length > 0
    ? approval.options
    : ['Approve once', `Always allow '${approval.tool}' in this chat`, 'Deny']
  return (
    <div className="border-t px-3 py-2" data-testid="approval-bar">
      <div className="mb-2 text-xs opacity-80">
        High-risk tool <code>{approval.tool}</code> is waiting for approval.
        {approval.advisory ? <span> Reviewer: {approval.advisory}</span> : null}
      </div>
      <div className="flex flex-wrap gap-2">
        {labels.map((label, i) => (
          <button
            key={label}
            type="button"
            className="rounded border px-3 py-1 text-sm hover:opacity-80"
            onClick={() => threadRuntime.append(String(i + 1))}
          >
            {i + 1}. {label}
          </button>
        ))}
      </div>
    </div>
  )
}

type ThreadPaneProps = {
  adapter: ChatModelAdapter
  initialMessages: ThreadMessageLike[]
  runtimeKey: string
  pendingApproval?: PendingApproval | null
}

export function ThreadPane({ adapter, initialMessages, runtimeKey, pendingApproval }: ThreadPaneProps) {
  const MarkdownText = makeMarkdownText({
    preprocess: (text) => extractThinkSegments(text).visibleText,
    remarkPlugins: [remarkGfm, remarkBreaks],
  })
  const runtime = useLocalRuntime(adapter, {
    initialMessages,
    maxSteps: 100,
  })

  return (
    <AssistantRuntimeProvider key={runtimeKey} runtime={runtime}>
      <div className="flex h-full min-h-0 flex-col">
        <div className="aui-root min-h-0 flex-1">
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
        {pendingApproval ? <ApprovalBar approval={pendingApproval} /> : null}
      </div>
    </AssistantRuntimeProvider>
  )
}
