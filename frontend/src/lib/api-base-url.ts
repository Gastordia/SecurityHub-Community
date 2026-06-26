export function getApiBaseUrl(): string {
  const raw = (import.meta.env.VITE_APP_API_URL || '').trim().replace(/\/+$/, '')

  if (!raw) {
    return ''
  }

  return raw.replace(/\/api$/i, '')
}
