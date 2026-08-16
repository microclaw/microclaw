// Think-tag extraction: pulls <think>/<reasoning> segments out of model text
// and strips agent-protocol tool blocks from the visible remainder.

export type ThinkExtraction = {
  visibleText: string
  thinkSegments: string[]
}

const THINK_TAGS = ['think', 'thought', 'thinking', 'reasoning'] as const

export function stripAgentProtocolBlocks(text: string): string {
  if (!text) return ''

  let out = text
  const pairedTagPatterns = [
    /<tool_call>[\s\S]*?<\/tool_call>/g,
    /<function(?:=[^>\n]*)?>[\s\S]*?<\/function>/g,
    /<parameter(?:=[^>\n]*)?>[\s\S]*?<\/parameter>/g,
  ]

  for (const pattern of pairedTagPatterns) {
    out = out.replace(pattern, '')
  }

  return out
    .replace(/<tool_call>[\s\S]*$/g, '')
    .replace(/<function(?:=[^>\n]*)?>[\s\S]*$/g, '')
    .replace(/<parameter(?:=[^>\n]*)?>[\s\S]*$/g, '')
    .replace(/<\/?(?:tool_call|function|parameter)(?:=[^>\n]*)?>/g, '')
}

export function extractThinkSegments(text: string): ThinkExtraction {
  if (!text) return { visibleText: '', thinkSegments: [] }

  const thinkSegments: string[] = []
  let visibleText = ''
  let index = 0

  while (index < text.length) {
    const next = THINK_TAGS
      .map((tag) => ({ tag, start: text.indexOf(`<${tag}>`, index) }))
      .filter((entry) => entry.start >= 0)
      .sort((a, b) => a.start - b.start)[0]

    if (!next) {
      visibleText += text.slice(index)
      break
    }

    visibleText += text.slice(index, next.start)
    const openTag = `<${next.tag}>`
    const closeTag = `</${next.tag}>`
    const contentStart = next.start + openTag.length
    const end = text.indexOf(closeTag, contentStart)

    if (end < 0) {
      const tail = stripAgentProtocolBlocks(text.slice(contentStart)).trim()
      if (tail) thinkSegments.push(tail)
      break
    }

    const segment = stripAgentProtocolBlocks(text.slice(contentStart, end)).trim()
    if (segment) thinkSegments.push(segment)
    index = end + closeTag.length
  }

  return {
    visibleText: stripAgentProtocolBlocks(visibleText),
    thinkSegments,
  }
}

export function collectThinkText(parts: readonly { type: string; text?: string }[] | undefined): string {
  if (!Array.isArray(parts)) return ''
  const segments: string[] = []
  for (const part of parts) {
    if (part.type !== 'text' || typeof part.text !== 'string') continue
    const extracted = extractThinkSegments(part.text)
    if (extracted.thinkSegments.length > 0) segments.push(...extracted.thinkSegments)
  }
  return segments.join('\n\n')
}
