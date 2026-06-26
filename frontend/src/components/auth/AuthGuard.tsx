import { useEffect, useState } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth-store'

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, token, checkAuthStatus } = useAuthStore()
  const location = useLocation()
  const [checking, setChecking] = useState(isAuthenticated && !token)

  useEffect(() => {
    // After a page reload, isAuthenticated may be true (from localStorage) but token is
    // null (tokens aren't persisted). Re-validate via the httpOnly cookie silently.
    if (isAuthenticated && !token) {
      checkAuthStatus().finally(() => setChecking(false))
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (checking) return null  // brief blank while cookie auth resolves
  if (!isAuthenticated) return <Navigate to="/login" state={{ from: location }} replace />
  return <>{children}</>
}

export function AdminGuard({ children }: { children: React.ReactNode }) {
  const { user, isAuthenticated } = useAuthStore()
  const location = useLocation()
  if (!isAuthenticated) return <Navigate to="/login" state={{ from: location }} replace />
  if (!user?.is_superuser && !user?.is_staff) return <Navigate to="/" replace />
  return <>{children}</>
}
