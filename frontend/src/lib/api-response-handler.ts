/**
 * API Response Handler
 *
 * Utilities for handling and formatting API responses and errors
 */
import toast from 'react-hot-toast'

const FALLBACK_ERROR_MESSAGE = 'An unexpected error occurred'

function toSentenceCase(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function normalizeMessage(value: unknown): string[] {
  if (value == null) {
    return []
  }

  if (typeof value === 'string') {
    const trimmed = value.trim()
    return trimmed ? [trimmed] : []
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return [String(value)]
  }

  if (Array.isArray(value)) {
    return value.flatMap(normalizeMessage)
  }

  if (typeof value === 'object') {
    return formatStructuredErrors(value)
  }

  return []
}

function formatStructuredErrors(
  value: unknown,
  parentKey?: string,
  seen: WeakSet<object> = new WeakSet()
): string[] {
  if (value == null) {
    return []
  }

  if (typeof value !== 'object') {
    return normalizeMessage(value)
  }

  if (seen.has(value as object)) {
    return []
  }
  seen.add(value as object)

  if (Array.isArray(value)) {
    return value.flatMap((item) => formatStructuredErrors(item, parentKey, seen))
  }

  const entries = Object.entries(value as Record<string, unknown>)
  const messages: string[] = []

  for (const [key, raw] of entries) {
    if (key === 'code' || raw == null) {
      continue
    }

    if (['detail', 'message', 'error'].includes(key)) {
      messages.push(...normalizeMessage(raw))
      continue
    }

    if (key === 'errors') {
      messages.push(...formatStructuredErrors(raw, parentKey, seen))
      continue
    }

    const label = ['non_field_errors', 'nonFieldErrors', '__all__'].includes(key)
      ? parentKey
      : toSentenceCase(key)

    const normalized = normalizeMessage(raw)
    if (normalized.length === 0) {
      continue
    }

    for (const message of normalized) {
      messages.push(label ? `${label}: ${message}` : message)
    }
  }

  return messages
}

function dedupeMessages(messages: string[]): string[] {
  const seen = new Set<string>()
  const result: string[] = []

  for (const message of messages) {
    const normalized = message.trim()
    if (!normalized) {
      continue
    }

    const key = normalized.toLowerCase()
    if (seen.has(key)) {
      continue
    }

    seen.add(key)
    result.push(normalized)
  }

  return result
}

export function getErrorMessages(error: any): string[] {
  if (!error) {
    return [FALLBACK_ERROR_MESSAGE]
  }

  if (typeof error === 'string') {
    return normalizeMessage(error)
  }

  if (error.response) {
    const response = error.response
    const data = response.data
    const messages = dedupeMessages([
      ...formatStructuredErrors(data),
      ...(typeof data === 'string' ? normalizeMessage(data) : []),
    ])

    if (messages.length > 0) {
      return messages
    }

    if (response.statusText) {
      return [`HTTP ${response.status}: ${response.statusText}`]
    }

    return [`HTTP ${response.status}: Request failed`]
  }

  if (error instanceof Error) {
    return normalizeMessage(error.message || FALLBACK_ERROR_MESSAGE)
  }

  if (error.message) {
    return normalizeMessage(error.message)
  }

  if (error.code && error.message) {
    return normalizeMessage(`${error.code}: ${error.message}`)
  }

  try {
    const stringified = JSON.stringify(error)
    if (stringified && stringified !== '{}') {
      return [stringified]
    }
  } catch {
    // Ignore stringify failures and fall through to fallback.
  }

  return [FALLBACK_ERROR_MESSAGE]
}

/**
 * Show a toast with the actual error details extracted from an Axios/DRF response.
 * Replaces the pattern `toast.error(error.message || 'Fallback')` throughout the app.
 *
 * @param error   - The caught error (AxiosError, Error, or anything)
 * @param fallback - Optional context prefix shown when no detail is available,
 *                   e.g. "Failed to save project" → "Failed to save project: <detail>"
 * @param toastId  - Optional toast id (for loading→error replacement)
 */
export function showErrorToast(error: any, fallback?: string, toastId?: string): void {
  const detail = formatErrorForUser(error)
  const message = fallback && detail !== fallback ? `${fallback}: ${detail}` : detail
  if (toastId) {
    toast.error(message, { id: toastId })
  } else {
    toast.error(message)
  }
}

/**
 * Formats an error object into a user-friendly error message.
 * @param error - The error object (can be Error, AxiosError, or any object)
 * @returns A formatted error message string
 */
export function formatErrorForUser(error: any): string {
  return getErrorMessages(error).join('\n')
}

/**
 * Checks if an error is a network error
 */
export function isNetworkError(error: any): boolean {
  return (
    error?.code === 'NETWORK_ERROR' ||
    error?.code === 'ECONNABORTED' ||
    error?.message?.includes('Network Error') ||
    error?.message?.includes('timeout')
  )
}

/**
 * Checks if an error is an authentication error
 */
export function isAuthError(error: any): boolean {
  return (
    error?.response?.status === 401 ||
    error?.code === 'UNAUTHORIZED' ||
    error?.status === 401
  )
}

/**
 * Checks if an error is a permission error
 */
export function isPermissionError(error: any): boolean {
  return (
    error?.response?.status === 403 ||
    error?.code === 'FORBIDDEN' ||
    error?.status === 403
  )
}

