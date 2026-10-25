// Chat thread pane: assistant/user message renderers, tool-call cards,
// the think-segment disclosure, and the high-risk approval button bar.
//
// Built directly on @assistant-ui/react primitives. The pre-styled
// @assistant-ui/react-ui package stayed on the 0.14 core line (it imports
// `useThread`, which 0.15 removed), so its Thread/AssistantMessage/
// UserMessage/BranchPicker/action-bar components and `makeMarkdownText` are
// reproduced here with the same `aui-*` class names; the matching base
// styles live in ../assistant-ui.css and the theming in ../styles.css.
import { memo, useState, type ButtonHTMLAttributes, type FC, type SVGProps } from 'react'
import {
  ActionBarPrimitive,
  AssistantRuntimeProvider,
  BranchPickerPrimitive,
  ComposerPrimitive,
  MessagePartPrimitive,
  MessagePrimitive,
  ThreadPrimitive,
  useAui,
  useAuiState,
  useLocalRuntime,
  type ChatModelAdapter,
  type ThreadMessageLike,
  type ToolCallMessagePartProps,
} from '@assistant-ui/react'
import {
  MarkdownTextPrimitive,
  memoizeMarkdownComponents,
  useIsMarkdownCodeBlock,
  type CodeHeaderProps,
} from '@assistant-ui/react-markdown'
import remarkBreaks from 'remark-breaks'
import remarkGfm from 'remark-gfm'
import { collectThinkText, extractThinkSegments } from '../lib/think'
import { asObject, formatUnknown } from '../lib/json-utils'

type ContentPart = { type: string; text?: string }

function cx(...names: (string | false | null | undefined)[]): string {
  return names.filter(Boolean).join(' ')
}

// --- icons (lucide outlines, inlined to avoid a dependency) ---------------

function Icon({ children, ...rest }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      {children}
    </svg>
  )
}

const SendIcon = () => (
  <Icon>
    <path d="M3.714 3.048a.498.498 0 0 0-.683.627l2.843 7.627a2 2 0 0 1 0 1.396l-2.842 7.627a.498.498 0 0 0 .682.627l18-8.5a.5.5 0 0 0 0-.904z" />
    <path d="M6 12h16" />
  </Icon>
)
const StopIcon = () => (
  <Icon>
    <circle cx="12" cy="12" r="10" />
    <rect x="9" y="9" width="6" height="6" rx="1" />
  </Icon>
)
const ArrowDownIcon = () => (
  <Icon>
    <path d="M12 5v14" />
    <path d="m19 12-7 7-7-7" />
  </Icon>
)
const CopyIcon = () => (
  <Icon>
    <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
    <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
  </Icon>
)
const CheckIcon = () => (
  <Icon>
    <path d="M20 6 9 17l-5-5" />
  </Icon>
)
const ChevronLeftIcon = () => (
  <Icon>
    <path d="m15 18-6-6 6-6" />
  </Icon>
)
const ChevronRightIcon = () => (
  <Icon>
    <path d="m9 18 6-6-6-6" />
  </Icon>
)

// --- small building blocks -----------------------------------------------

type IconButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  tooltip: string
  variant?: 'primary' | 'outline' | 'ghost'
}

// Used as the `asChild` target of the primitive action buttons, which merge
// their onClick/disabled props into it.
function IconButton({ tooltip, variant = 'ghost', className, children, ...rest }: IconButtonProps) {
  return (
    <button
      title={tooltip}
      className={cx('aui-button', `aui-button-${variant}`, 'aui-button-icon', className)}
      {...rest}
    >
      {children}
      <span className="aui-sr-only">{tooltip}</span>
    </button>
  )
}

function AssistantAvatar() {
  return (
    <div className="aui-avatar-root">
      <span className="aui-avatar-fallback">M</span>
    </div>
  )
}

// --- markdown ---------------------------------------------------------------

// Header bar above fenced code blocks: language label plus copy-to-clipboard.
function CodeHeader({ language, code }: CodeHeaderProps) {
  const [copied, setCopied] = useState(false)
  const onCopy = () => {
    if (!code || copied) return
    void navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 3000)
    })
  }
  return (
    <div className="aui-code-header-root">
      <span className="aui-code-header-language">{language}</span>
      <IconButton tooltip="Copy" type="button" onClick={onCopy}>
        {copied ? <CheckIcon /> : <CopyIcon />}
      </IconButton>
    </div>
  )
}

const markdownComponents = memoizeMarkdownComponents({
  h1: ({ className, ...props }) => <h1 className={cx('aui-md-h1', className)} {...props} />,
  h2: ({ className, ...props }) => <h2 className={cx('aui-md-h2', className)} {...props} />,
  h3: ({ className, ...props }) => <h3 className={cx('aui-md-h3', className)} {...props} />,
  h4: ({ className, ...props }) => <h4 className={cx('aui-md-h4', className)} {...props} />,
  h5: ({ className, ...props }) => <h5 className={cx('aui-md-h5', className)} {...props} />,
  h6: ({ className, ...props }) => <h6 className={cx('aui-md-h6', className)} {...props} />,
  p: ({ className, ...props }) => <p className={cx('aui-md-p', className)} {...props} />,
  a: ({ className, ...props }) => <a className={cx('aui-md-a', className)} {...props} />,
  blockquote: ({ className, ...props }) => (
    <blockquote className={cx('aui-md-blockquote', className)} {...props} />
  ),
  ul: ({ className, ...props }) => <ul className={cx('aui-md-ul', className)} {...props} />,
  ol: ({ className, ...props }) => <ol className={cx('aui-md-ol', className)} {...props} />,
  hr: ({ className, ...props }) => <hr className={cx('aui-md-hr', className)} {...props} />,
  table: ({ className, ...props }) => <table className={cx('aui-md-table', className)} {...props} />,
  th: ({ className, ...props }) => <th className={cx('aui-md-th', className)} {...props} />,
  td: ({ className, ...props }) => <td className={cx('aui-md-td', className)} {...props} />,
  tr: ({ className, ...props }) => <tr className={cx('aui-md-tr', className)} {...props} />,
  sup: ({ className, ...props }) => <sup className={cx('aui-md-sup', className)} {...props} />,
  pre: ({ className, ...props }) => <pre className={cx('aui-md-pre', className)} {...props} />,
  code: function Code({ className, ...props }) {
    const isCodeBlock = useIsMarkdownCodeBlock()
    return <code className={cx(!isCodeBlock && 'aui-md-inline-code', className)} {...props} />
  },
  CodeHeader,
})

const remarkPlugins = [remarkGfm, remarkBreaks]
const stripThinkSegments = (text: string) => extractThinkSegments(text).visibleText

// Text part renderer for assistant messages: markdown with <think> blocks
// removed (they are shown separately by the disclosure below the message).
const MarkdownText: FC = memo(
  function MarkdownText() {
    return (
      <MarkdownTextPrimitive
        preprocess={stripThinkSegments}
        remarkPlugins={remarkPlugins}
        components={markdownComponents}
      />
    )
  },
  () => true,
)

const UserText: FC = () => <MessagePartPrimitive.Text className="aui-text" component="p" />

// --- tool calls ---------------------------------------------------------------

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

// --- message chrome -----------------------------------------------------------

function MessageTimestamp({ align }: { align: 'left' | 'right' }) {
  const createdAt = useAuiState((s) => s.message.createdAt)
  const formatted = createdAt ? createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
  return (
    <div className={align === 'right' ? 'mc-msg-time mc-msg-time-right' : 'mc-msg-time'}>
      {formatted}
    </div>
  )
}

function BranchPicker() {
  return (
    <BranchPickerPrimitive.Root hideWhenSingleBranch className="aui-branch-picker-root">
      <BranchPickerPrimitive.Previous asChild>
        <IconButton tooltip="Previous">
          <ChevronLeftIcon />
        </IconButton>
      </BranchPickerPrimitive.Previous>
      <span className="aui-branch-picker-state">
        <BranchPickerPrimitive.Number /> / <BranchPickerPrimitive.Count />
      </span>
      <BranchPickerPrimitive.Next asChild>
        <IconButton tooltip="Next">
          <ChevronRightIcon />
        </IconButton>
      </BranchPickerPrimitive.Next>
    </BranchPickerPrimitive.Root>
  )
}

function CopyStateIcon() {
  const copied = useAuiState((s) => s.message.isCopied)
  return copied ? <CheckIcon /> : <CopyIcon />
}

// Copy only: reload, speak and feedback are intentionally not offered.
function AssistantActionBar() {
  return (
    <ActionBarPrimitive.Root
      hideWhenRunning
      autohide="not-last"
      autohideFloat="single-branch"
      className="aui-assistant-action-bar-root"
    >
      <ActionBarPrimitive.Copy asChild>
        <IconButton tooltip="Copy">
          <CopyStateIcon />
        </IconButton>
      </ActionBarPrimitive.Copy>
    </ActionBarPrimitive.Root>
  )
}

function AssistantMessage() {
  const thinkText = useAuiState((s) => collectThinkText(s.message.content as readonly ContentPart[] | undefined))

  const hasRenderableContent = useAuiState((s) =>
    s.message.content.some((part) => {
      if (part.type === 'text') return Boolean(extractThinkSegments(part.text ?? '').visibleText.trim())
      return part.type === 'tool-call'
    }),
  )

  return (
    <MessagePrimitive.Root className="aui-assistant-message-root">
      <AssistantAvatar />
      {hasRenderableContent ? (
        <div className="aui-assistant-message-content">
          <MessagePrimitive.Parts
            components={{
              Text: MarkdownText,
              tools: { Fallback: ToolCallCard },
            }}
          />
        </div>
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
    </MessagePrimitive.Root>
  )
}

// No attachments and no edit action on user messages.
function UserMessage() {
  const hasContent = useAuiState((s) => s.message.content.length > 0)
  return (
    <MessagePrimitive.Root className="aui-user-message-root">
      {hasContent ? (
        <div className="mc-user-content-wrap">
          <div className="aui-user-message-content">
            <MessagePrimitive.Parts components={{ Text: UserText }} />
          </div>
          <MessageTimestamp align="right" />
        </div>
      ) : null}
      <BranchPicker />
    </MessagePrimitive.Root>
  )
}

// --- composer + thread ---------------------------------------------------------

function Composer() {
  const isRunning = useAuiState((s) => s.thread.isRunning)
  return (
    <ComposerPrimitive.Root className="aui-composer-root">
      <ComposerPrimitive.Input
        rows={1}
        autoFocus
        placeholder="Message MicroClaw..."
        className="aui-composer-input"
      />
      {isRunning ? (
        <ComposerPrimitive.Cancel asChild>
          <IconButton tooltip="Cancel" variant="primary" className="aui-composer-cancel">
            <StopIcon />
          </IconButton>
        </ComposerPrimitive.Cancel>
      ) : (
        <ComposerPrimitive.Send asChild>
          <IconButton tooltip="Send" variant="primary" className="aui-composer-send">
            <SendIcon />
          </IconButton>
        </ComposerPrimitive.Send>
      )}
    </ComposerPrimitive.Root>
  )
}

function ThreadWelcome() {
  return (
    <ThreadPrimitive.Empty>
      <div className="aui-thread-welcome-root">
        <div className="aui-thread-welcome-center">
          <AssistantAvatar />
          <p className="aui-thread-welcome-message">How can I help you today?</p>
        </div>
      </div>
    </ThreadPrimitive.Empty>
  )
}

function Thread() {
  const isEmpty = useAuiState((s) => s.thread.isEmpty)
  return (
    <ThreadPrimitive.Root className="aui-root aui-thread-root">
      <ThreadPrimitive.Viewport className="aui-thread-viewport">
        <ThreadWelcome />
        <ThreadPrimitive.Messages components={{ UserMessage, AssistantMessage }} />
        {isEmpty ? null : <div style={{ flexGrow: 1 }} />}
        <ThreadPrimitive.ViewportFooter className="aui-thread-viewport-footer">
          <ThreadPrimitive.ScrollToBottom asChild>
            <IconButton tooltip="Scroll to bottom" variant="outline" className="aui-thread-scroll-to-bottom">
              <ArrowDownIcon />
            </IconButton>
          </ThreadPrimitive.ScrollToBottom>
          <Composer />
        </ThreadPrimitive.ViewportFooter>
      </ThreadPrimitive.Viewport>
    </ThreadPrimitive.Root>
  )
}

// --- approvals ------------------------------------------------------------------

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
  const aui = useAui()
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
            onClick={() => aui.thread.append(String(i + 1))}
          >
            {i + 1}. {label}
          </button>
        ))}
      </div>
    </div>
  )
}

// --- pane -------------------------------------------------------------------------

type ThreadPaneProps = {
  adapter: ChatModelAdapter
  initialMessages: ThreadMessageLike[]
  runtimeKey: string
  pendingApproval?: PendingApproval | null
}

export function ThreadPane({ adapter, initialMessages, runtimeKey, pendingApproval }: ThreadPaneProps) {
  const runtime = useLocalRuntime(adapter, {
    initialMessages,
    maxSteps: 100,
  })

  return (
    <AssistantRuntimeProvider key={runtimeKey} runtime={runtime}>
      <div className="flex h-full min-h-0 flex-col">
        <div className="aui-root min-h-0 flex-1">
          <Thread />
        </div>
        {pendingApproval ? <ApprovalBar approval={pendingApproval} /> : null}
      </div>
    </AssistantRuntimeProvider>
  )
}
