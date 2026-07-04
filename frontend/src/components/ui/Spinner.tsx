import { ReactNode } from 'react'
import { clsx } from 'clsx'

// ── InlineSpinner ────────────────────────────────────────────────────────────

export function InlineSpinner({ className }: { className?: string }) {
  return (
    <span
      className={clsx('block rounded-full border-2 border-accent-500/30 border-t-accent-500 animate-spin', className)}
      style={{ width: 16, height: 16 }}
      aria-hidden="true"
    />
  )
}

// ── PageSpinner ───────────────────────────────────────────────────────────────

export function PageSpinner() {
  return (
    <div className="flex h-64 items-center justify-center">
      <span
        className="block rounded-full border-2 border-accent-500/30 border-t-accent-500 animate-spin"
        style={{ width: 32, height: 32 }}
        role="status"
        aria-label="Loading"
      />
    </div>
  )
}

// ── Legacy Spinner (kept for backward compatibility) ──────────────────────────

export function Spinner({ size = 'md', className = '' }: { size?: 'sm' | 'md' | 'lg'; className?: string }) {
  const dims = { sm: 16, md: 24, lg: 32 }[size]
  return (
    <span
      className={clsx('block rounded-full border-2 border-accent-500/30 border-t-accent-500 animate-spin', className)}
      style={{ width: dims, height: dims }}
      aria-hidden="true"
    />
  )
}

// ── ErrorState ────────────────────────────────────────────────────────────────

export function ErrorState({ message = 'Something went wrong. Please try again.' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center px-4">
      <div className="w-10 h-10 rounded-full bg-critical/10 flex items-center justify-center mb-3">
        <svg className="w-5 h-5 text-critical" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
        </svg>
      </div>
      <p className="text-sm font-medium text-text-secondary">Failed to load data</p>
      <p className="text-xs text-text-muted mt-1">{message}</p>
    </div>
  )
}

// ── EmptyState ────────────────────────────────────────────────────────────────

interface EmptyStateProps {
  icon?: React.ComponentType<{ className?: string }>
  title: string
  description?: string
  /** Legacy alias for description */
  subtitle?: string
  action?: ReactNode
}

export function EmptyState({ icon: Icon, title, description, subtitle, action }: EmptyStateProps) {
  const body = description ?? subtitle
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center px-4">
      {Icon && <Icon className="w-10 h-10 text-text-muted mb-3" />}
      <p className="text-sm font-medium text-text-secondary">{title}</p>
      {body && <p className="text-xs text-text-muted mt-1">{body}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
