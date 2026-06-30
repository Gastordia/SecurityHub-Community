import { clsx } from 'clsx'
import { ButtonHTMLAttributes, forwardRef, ReactNode } from 'react'

export type ButtonVariant = 'primary' | 'ghost' | 'danger' | 'outline'
export type ButtonSize = 'sm' | 'md' | 'lg'

const base =
  'inline-flex items-center justify-center gap-2 font-medium rounded-lg transition-all ' +
  'disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none ' +
  'focus-visible:ring-2 focus-visible:ring-accent-500/50'

const variants: Record<ButtonVariant, string> = {
  primary: 'bg-accent-500 hover:bg-accent-600 text-white',
  ghost:   'text-text-secondary hover:text-text-primary hover:bg-app-overlay',
  danger:  'bg-red-600/15 text-red-400 hover:bg-red-600/25',
  outline: 'border border-border-default text-text-secondary hover:border-border-strong hover:text-text-primary',
}

const sizes: Record<ButtonSize, string> = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-5 py-2.5 text-sm',
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
  icon?: ReactNode
}

function CssSpinner() {
  return (
    <span
      className="block rounded-full animate-spin"
      style={{
        width: 14,
        height: 14,
        border: '2px solid transparent',
        borderTopColor: 'currentColor',
        borderRightColor: 'currentColor',
        opacity: 0.9,
      }}
      aria-hidden="true"
    />
  )
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', loading, icon, className, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={clsx(base, variants[variant], sizes[size], className)}
      {...props}
    >
      {loading ? <CssSpinner /> : icon ? <span className="shrink-0 flex items-center">{icon}</span> : null}
      {children}
    </button>
  )
)

Button.displayName = 'Button'
