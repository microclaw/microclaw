// Small JSON coercion helpers shared by the chat UI.
import type { ReadonlyJSONObject, ReadonlyJSONValue } from 'assistant-stream/utils'

export function asObject(value: unknown): Record<string, unknown> {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return {}
}

export function toJsonValue(value: unknown): ReadonlyJSONValue {
  try {
    return JSON.parse(JSON.stringify(value)) as ReadonlyJSONValue
  } catch {
    return String(value)
  }
}

export function toJsonObject(value: unknown): ReadonlyJSONObject {
  const normalized = toJsonValue(value)
  if (typeof normalized === 'object' && normalized !== null && !Array.isArray(normalized)) {
    return normalized as ReadonlyJSONObject
  }
  return {}
}

export function formatUnknown(value: unknown): string {
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}
