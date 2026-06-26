import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { standardizedApiClient } from '../lib/standardized-api-client'

// Guard console statements - only log in development
const isDevelopment = import.meta.env.MODE === 'development' || import.meta.env.DEV
const safeWarn = (...args: any[]) => {
  if (isDevelopment) console.warn(...args)
}

export interface User {
  id: number
  username: string
  email: string
  first_name: string
  last_name: string
  position?: string
  is_active: boolean
  is_staff: boolean
  is_superuser: boolean
  user_type: 'staff' | 'customer'
  last_login: string | null
  date_joined: string
}

export interface AuthState {
  user: User | null
  token: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
}

export interface AuthActions {
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  clearAuthState: () => void
  setTokens: (accessToken: string, refreshToken: string) => void
  checkAuthStatus: () => Promise<void>
}

export const useAuthStore = create<AuthState & AuthActions>()(
  persist(
    (set, get) => ({
      // State
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,

      clearAuthState: () => {
        localStorage.removeItem('auth-storage')
        set({
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
        })
      },

      // Actions
      login: async (email: string, password: string) => {
        set({ isLoading: true })

        try {
          const response = await standardizedApiClient.login(email, password)

          // Handle the actual backend response format
          const { access, username, isAdmin, isStaff } = response

          const user: User = {
            id: 1, // Will be fetched from profile
            username: username,
            email: email,
            first_name: username,
            last_name: '',
            is_active: true,
            is_staff: isStaff,
            is_superuser: isAdmin,
            user_type: isStaff ? 'staff' : 'customer',
            last_login: new Date().toISOString(),
            date_joined: new Date().toISOString(),
          }

          set({
            user,
            token: access,
            refreshToken: '',
            isAuthenticated: true,
            isLoading: false,
          })

          // Fetch full user profile to get accurate id, name, etc.
          try {
            const profileResponse = await standardizedApiClient.getCurrentUser()
            const mergedUser = {
              ...user,
              ...profileResponse,
              is_superuser: user.is_superuser,
              is_staff: user.is_staff,
              user_type: ((profileResponse as any).user_type as 'staff' | 'customer') || user.user_type,
            }
            set({ user: mergedUser })
          } catch (profileError) {
            safeWarn('Failed to fetch user profile:', profileError)
          }
        } catch (error: any) {
          set({ isLoading: false })
          throw error
        }
      },

      logout: async () => {
        const { clearAuthState } = get()
        // Prevent multiple simultaneous logout calls
        const { isAuthenticated } = get()
        if (!isAuthenticated) {
          // Already logged out, just clear state
          clearAuthState()
          return
        }

        try {
          // Call logout API before clearing state
          await standardizedApiClient.logout()
        } catch (error) {
          // Logout API call failure is non-critical - continue with state cleanup
          safeWarn('Logout API call failed (non-critical):', error)
        } finally {
          // Always clear state, even if API call fails
          clearAuthState()
        }
      },

      setTokens: (accessToken: string, refreshToken: string) => {
        set({
          token: accessToken,
          refreshToken,
          isAuthenticated: true
        })
      },

      checkAuthStatus: async () => {
        // Called on page load when isAuthenticated=true but no access token in memory.
        // The httpOnly access_token cookie (set by the backend) authenticates the request.
        // If the access token cookie is expired, the 401 interceptor fires a cookie-based refresh.
        const { user: currentUser } = get()
        try {
          const response = await standardizedApiClient.getCurrentUser()
          const updatedUser = {
            ...response,
            is_superuser: (response as any).is_superuser ?? (currentUser?.is_superuser || false),
            is_staff: (response as any).is_staff ?? (currentUser?.is_staff || false),
          }
          set({ user: updatedUser, isAuthenticated: true })
        } catch (error) {
          if (isDevelopment) console.error('Auth check failed:', error)
          get().logout()
        }
      },
    }),
    {
      name: 'auth-storage',
      // Tokens are NOT persisted to localStorage — they live in memory only.
      // The backend issues httpOnly cookies (access_token, refresh_token) that
      // the browser sends automatically, so sessions survive page reloads without
      // the refresh token ever being readable by JS.
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)
