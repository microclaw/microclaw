// Mapping between backend message history and assistant-ui thread messages.
import type { ChatModelRunOptions, ThreadMessageLike } from '@assistant-ui/react'
import type { BackendMessage } from './backend-types'

export function extractLatestUserText(messages: readonly ChatModelRunOptions['messages'][number][]): string {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i]
    if (message.role !== 'user') continue

    const text = message.content
      .map((part) => {
        if (part.type === 'text') return part.text
        return ''
      })
      .join('\n')
      .trim()

    if (text.length > 0) return text
  }
  return ''
}

export function mapBackendHistory(messages: BackendMessage[]): ThreadMessageLike[] {
  return messages.map((item, index) => ({
    id: item.id || `history-${index}`,
    role: item.is_from_bot ? 'assistant' : 'user',
    content: item.content || '',
    createdAt: item.timestamp ? new Date(item.timestamp) : new Date(),
  }))
}
