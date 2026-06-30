import { clsx } from 'clsx'
import {
  InputHTMLAttributes,
  TextareaHTMLAttributes,
  SelectHTMLAttributes,
  forwardRef,
  useId,
  useState,
  ReactNode,
} from 'react'
import { MagnifyingGlassIcon, XMarkIcon } from '@heroicons/react/24/outline'

// ── Shared base style ─────────────────────────────────────────────────────────

const inputBase =
  'w-full rounded-lg bg-app-surface border border-border-default text-text-primary ' +
  'placeholder:text-text-muted px-3 py-2 text-sm outline-none transition-all ' +
  'focus:border-accent-500 focus:ring-1 focus:ring-accent-500/30 ' +
  'disabled:opacity-40 disabled:cursor-not-allowed'

// ── Label ──────────────────────────────────────────────────────────────────────

export function Label({ htmlFor, children, className }: { htmlFor?: string; children: ReactNode; className?: string }) {
  return (
    <label htmlFor={htmlFor} className={clsx('block text-xs font-medium text-text-secondary mb-1.5', className)}>
      {children}
    </label>
  )
}

// ── FormField ─────────────────────────────────────────────────────────────────

interface FormFieldProps {
  label?: string
  error?: string
  children: ReactNode
  htmlFor?: string
  className?: string
}

export function FormField({ label, error, children, htmlFor, className }: FormFieldProps) {
  return (
    <div className={clsx('space-y-0', className)}>
      {label && <Label htmlFor={htmlFor}>{label}</Label>}
      {children}
      {error && <p className="mt-1.5 text-xs text-red-400">{error}</p>}
    </div>
  )
}

// ── Input ─────────────────────────────────────────────────────────────────────

type InputProps = InputHTMLAttributes<HTMLInputElement> & {
  label?: string
  error?: string
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, className, id: idProp, ...props }, ref) => {
    const generated = useId()
    const id = idProp ?? generated
    return (
      <FormField label={label} error={error} htmlFor={id}>
        <input
          ref={ref}
          id={id}
          className={clsx(inputBase, error && 'border-red-500 focus:border-red-500 focus:ring-red-500/30', className)}
          {...props}
        />
      </FormField>
    )
  }
)
Input.displayName = 'Input'

// ── Textarea ──────────────────────────────────────────────────────────────────

type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement> & {
  label?: string
  error?: string
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ label, error, className, id: idProp, rows = 3, ...props }, ref) => {
    const generated = useId()
    const id = idProp ?? generated
    return (
      <FormField label={label} error={error} htmlFor={id}>
        <textarea
          ref={ref}
          id={id}
          rows={rows}
          className={clsx(inputBase, 'resize-none', error && 'border-red-500 focus:border-red-500 focus:ring-red-500/30', className)}
          {...props}
        />
      </FormField>
    )
  }
)
Textarea.displayName = 'Textarea'

// ── Select ────────────────────────────────────────────────────────────────────

type SelectProps = SelectHTMLAttributes<HTMLSelectElement> & {
  label?: string
  error?: string
}

export function Select({ label, error, className, id: idProp, children, ...props }: SelectProps) {
  const generated = useId()
  const id = idProp ?? generated
  return (
    <FormField label={label} error={error} htmlFor={id}>
      <select
        id={id}
        className={clsx(inputBase, 'appearance-none', error && 'border-red-500 focus:border-red-500 focus:ring-red-500/30', className)}
        {...props}
      >
        {children}
      </select>
    </FormField>
  )
}

// ── SearchInput ───────────────────────────────────────────────────────────────

interface SearchInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  className?: string
}

export function SearchInput({ value, onChange, placeholder = 'Search…', className, ...props }: SearchInputProps) {
  return (
    <div className={clsx('relative flex items-center', className)}>
      <MagnifyingGlassIcon className="absolute left-3 w-4 h-4 text-text-muted pointer-events-none shrink-0" />
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className={clsx(inputBase, 'pl-9', value && 'pr-8')}
        {...props}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          className="absolute right-3 text-text-muted hover:text-text-secondary transition-colors"
          aria-label="Clear search"
        >
          <XMarkIcon className="w-4 h-4" />
        </button>
      )}
    </div>
  )
}
