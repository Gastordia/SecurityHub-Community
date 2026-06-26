import { useAuthStore } from '@/stores/auth-store'

let isHandlingSessionExpiry = false

export function handleSessionExpired(redirectPath = '/login') {
  if (isHandlingSessionExpiry) return
  isHandlingSessionExpiry = true

  try {
    useAuthStore.getState().clearAuthState()
  } catch (error) {
    localStorage.removeItem('auth-storage')
  }

  if (typeof window !== 'undefined' && window.location.pathname !== redirectPath) {
    window.location.href = redirectPath
  }

  window.setTimeout(() => {
    isHandlingSessionExpiry = false
  }, 1000)
}
