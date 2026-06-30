import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { EyeIcon, EyeSlashIcon, CheckCircleIcon } from '@heroicons/react/24/outline'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/Button'

// ── Hex logo mark (same as Layout, kept local to avoid circular dep) ──────────

function HexLogo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id="login-hex-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#8b82ff" />
          <stop offset="100%" stopColor="#6d63ff" />
        </linearGradient>
      </defs>
      <path
        d="M14 2L24.39 8V20L14 26L3.61 20V8L14 2Z"
        fill="url(#login-hex-grad)"
        fillOpacity="0.18"
        stroke="url(#login-hex-grad)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M14 7.5L9.5 9.5V14C9.5 17 11.5 19.5 14 20.5C16.5 19.5 18.5 17 18.5 14V9.5L14 7.5Z"
        fill="url(#login-hex-grad)"
        fillOpacity="0.4"
        stroke="url(#login-hex-grad)"
        strokeWidth="1"
        strokeLinejoin="round"
      />
      <path
        d="M11.5 13.5L13.2 15.3L16.5 11.5"
        stroke="#8b82ff"
        strokeWidth="1.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// ── Feature list item ──────────────────────────────────────────────────────────

function Feature({ text }: { text: string }) {
  return (
    <li className="flex items-start gap-3">
      <CheckCircleIcon className="w-4 h-4 text-accent-400 mt-0.5 shrink-0" />
      <span className="text-sm text-text-secondary">{text}</span>
    </li>
  )
}

// ── Login page ─────────────────────────────────────────────────────────────────

export default function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login } = useAuthStore()

  const [username, setUsername]         = useState('')
  const [password, setPassword]         = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading]           = useState(false)
  const [error, setError]               = useState('')

  const from = (location.state as any)?.from?.pathname || '/'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password) {
      setError('Please enter your username and password.')
      return
    }
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch (err: any) {
      setError(err?.message || 'Invalid credentials. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-app-bg flex">
      {/* ── Left panel (desktop only) ── */}
      <div className="hidden lg:flex lg:w-[40%] flex-col bg-app-surface border-r border-border-subtle px-10 py-12">
        {/* Logo */}
        <div className="flex items-center gap-3 mb-auto">
          <HexLogo size={32} />
          <span className="text-base font-semibold text-text-primary">SecurityHub</span>
        </div>

        {/* Headline */}
        <div className="flex-1 flex flex-col justify-center py-16 max-w-xs">
          <h1 className="text-2xl font-semibold text-text-primary leading-snug mb-3">
            Secure your findings,<br />
            not just your perimeter.
          </h1>
          <p className="text-sm text-text-muted mb-10">
            Open-source vulnerability management for security teams.
          </p>
          <ul className="space-y-4">
            <Feature text="12 scanner integrations — Nessus, Burp, Nuclei and more" />
            <Feature text="CVE enrichment with NVD and EPSS scoring" />
            <Feature text="SLA tracking, retests, and audit trails" />
          </ul>
        </div>

        {/* Footer note */}
        <p className="text-xs text-text-muted mt-auto">MIT licensed. Self-hosted.</p>
      </div>

      {/* ── Right panel ── */}
      <div className="flex-1 flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-sm">
          {/* Mobile logo */}
          <div className="flex items-center gap-2.5 justify-center mb-8 lg:hidden">
            <HexLogo size={28} />
            <span className="text-base font-semibold text-text-primary">SecurityHub</span>
          </div>

          {/* Card */}
          <div className="bg-app-surface border border-border-default rounded-2xl p-7 shadow-2xl">
            <div className="mb-6">
              <h2 className="text-xl font-semibold text-text-primary">Welcome back</h2>
              <p className="text-sm text-text-muted mt-1">Sign in to SecurityHub</p>
            </div>

            {/* Error banner */}
            {error && (
              <div className="mb-4 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
                <p className="text-xs text-red-400">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              {/* Username */}
              <div className="space-y-1.5">
                <label htmlFor="username" className="block text-xs font-medium text-text-secondary">
                  Username
                </label>
                <input
                  id="username"
                  type="text"
                  autoComplete="username"
                  autoFocus
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  disabled={loading}
                  className="w-full rounded-lg bg-app-raised border border-border-default text-text-primary placeholder:text-text-muted px-3 py-2 text-sm outline-none transition-all focus:border-accent-500 focus:ring-1 focus:ring-accent-500/30 disabled:opacity-40"
                  placeholder="your-username"
                />
              </div>

              {/* Password */}
              <div className="space-y-1.5">
                <label htmlFor="password" className="block text-xs font-medium text-text-secondary">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    disabled={loading}
                    className="w-full rounded-lg bg-app-raised border border-border-default text-text-primary placeholder:text-text-muted px-3 py-2 pr-10 text-sm outline-none transition-all focus:border-accent-500 focus:ring-1 focus:ring-accent-500/30 disabled:opacity-40"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    tabIndex={-1}
                  >
                    {showPassword
                      ? <EyeSlashIcon className="w-4 h-4" />
                      : <EyeIcon className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Submit */}
              <Button
                type="submit"
                variant="primary"
                size="md"
                className="w-full mt-2"
                loading={loading}
              >
                Sign in
              </Button>
            </form>
          </div>
        </div>
      </div>
    </div>
  )
}
