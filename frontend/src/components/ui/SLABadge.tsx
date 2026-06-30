type SLAStatus = 'ok' | 'due_soon' | 'breached' | null

interface SLABadgeProps {
  sla_status: SLAStatus
  days_remaining?: number
}

export function SLABadge({ sla_status, days_remaining }: SLABadgeProps) {
  if (!sla_status) return null

  if (sla_status === 'ok') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-low/15 text-low border border-low/30">
        SLA OK
      </span>
    )
  }

  if (sla_status === 'due_soon') {
    const label = days_remaining !== undefined ? `Due in ${days_remaining}d` : 'Due Soon'
    return (
      <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-medium/15 text-medium border border-medium/30">
        {label}
      </span>
    )
  }

  if (sla_status === 'breached') {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium bg-critical/15 text-critical border border-critical/30">
        <span className="relative flex h-1.5 w-1.5 shrink-0">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-critical opacity-75" />
          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-critical" />
        </span>
        SLA Breached
      </span>
    )
  }

  return null
}
