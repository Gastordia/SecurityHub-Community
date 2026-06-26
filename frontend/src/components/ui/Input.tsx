import { clsx } from 'clsx'
import { InputHTMLAttributes, TextareaHTMLAttributes, forwardRef } from 'react'

const inputBase = 'w-full rounded-lg bg-slate-800 border border-slate-700 text-slate-200 placeholder-slate-500 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-colors disabled:opacity-50 disabled:cursor-not-allowed'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { label?: string; error?: string }>(
  ({ label, error, className, id, ...props }, ref) => (
    <div className="space-y-1">
      {label && <label htmlFor={id} className="block text-xs font-medium text-slate-400">{label}</label>}
      <input ref={ref} id={id} className={clsx(inputBase, error && 'border-red-500 focus:ring-red-500', className)} {...props} />
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  )
)
Input.displayName = 'Input'

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement> & { label?: string; error?: string }>(
  ({ label, error, className, id, rows = 3, ...props }, ref) => (
    <div className="space-y-1">
      {label && <label htmlFor={id} className="block text-xs font-medium text-slate-400">{label}</label>}
      <textarea ref={ref} id={id} rows={rows} className={clsx(inputBase, 'resize-none', error && 'border-red-500', className)} {...props} />
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  )
)
Textarea.displayName = 'Textarea'

export function Select({ label, error, className, id, children, ...props }: React.SelectHTMLAttributes<HTMLSelectElement> & { label?: string; error?: string }) {
  return (
    <div className="space-y-1">
      {label && <label htmlFor={id} className="block text-xs font-medium text-slate-400">{label}</label>}
      <select id={id} className={clsx(inputBase, error && 'border-red-500', className)} {...props}>
        {children}
      </select>
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  )
}
