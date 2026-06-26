import { clsx } from 'clsx'

type Variant = 'default' | 'success' | 'warning' | 'danger' | 'info' | 'purple'

const variants: Record<Variant, string> = {
  default: 'bg-slate-700 text-slate-300',
  success: 'bg-green-500/15 text-green-400 ring-1 ring-green-500/30',
  warning: 'bg-yellow-500/15 text-yellow-400 ring-1 ring-yellow-500/30',
  danger:  'bg-red-500/15 text-red-400 ring-1 ring-red-500/30',
  info:    'bg-blue-500/15 text-blue-400 ring-1 ring-blue-500/30',
  purple:  'bg-indigo-500/15 text-indigo-400 ring-1 ring-indigo-500/30',
}

export function Badge({ children, variant = 'default', className }: {
  children: React.ReactNode
  variant?: Variant
  className?: string
}) {
  return (
    <span className={clsx(
      'inline-flex items-center rounded px-2 py-0.5 text-xs font-medium',
      variants[variant],
      className
    )}>
      {children}
    </span>
  )
}

export function severityBadge(severity: string) {
  const s = severity?.toLowerCase()
  if (s === 'critical') return <Badge variant="danger">Critical</Badge>
  if (s === 'high')     return <Badge variant="danger">High</Badge>
  if (s === 'medium')   return <Badge variant="warning">Medium</Badge>
  if (s === 'low')      return <Badge variant="info">Low</Badge>
  return <Badge variant="default">{severity || 'Info'}</Badge>
}

export function statusBadge(status: string) {
  const s = status?.toLowerCase()
  if (s === 'completed')  return <Badge variant="success">Completed</Badge>
  if (s === 'in progress' || s === 'ongoing') return <Badge variant="info">In Progress</Badge>
  if (s === 'upcoming')   return <Badge variant="purple">Upcoming</Badge>
  if (s === 'on hold')    return <Badge variant="warning">On Hold</Badge>
  if (s === 'delay')      return <Badge variant="danger">Delayed</Badge>
  return <Badge variant="default">{status}</Badge>
}
