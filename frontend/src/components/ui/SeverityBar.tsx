interface SeverityBarProps {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

interface Segment {
  key: keyof SeverityBarProps
  label: string
  color: string
  textColor: string
}

const SEGMENTS: Segment[] = [
  { key: 'critical', label: 'Critical', color: '#ef4444', textColor: 'text-critical' },
  { key: 'high',     label: 'High',     color: '#f97316', textColor: 'text-high'     },
  { key: 'medium',   label: 'Medium',   color: '#eab308', textColor: 'text-medium'   },
  { key: 'low',      label: 'Low',      color: '#22c55e', textColor: 'text-low'      },
  { key: 'info',     label: 'Info',     color: '#3b82f6', textColor: 'text-info'     },
]

export function SeverityBar({ critical, high, medium, low, info }: SeverityBarProps) {
  const counts = { critical, high, medium, low, info }
  const total = critical + high + medium + low + info

  if (total === 0) {
    return (
      <div className="space-y-1.5">
        <div className="h-1.5 w-full rounded-full bg-border-default" />
        <p className="text-xs text-text-muted">No findings</p>
      </div>
    )
  }

  const present = SEGMENTS.filter(s => counts[s.key] > 0)

  return (
    <div className="space-y-2">
      {/* Bar */}
      <div className="flex h-1.5 w-full overflow-hidden rounded-full">
        {present.map((seg, i) => {
          const pct = (counts[seg.key] / total) * 100
          const isFirst = i === 0
          const isLast = i === present.length - 1
          return (
            <div
              key={seg.key}
              style={{
                width: `${pct}%`,
                backgroundColor: seg.color,
                borderRadius: isFirst && isLast
                  ? '9999px'
                  : isFirst
                  ? '9999px 0 0 9999px'
                  : isLast
                  ? '0 9999px 9999px 0'
                  : '0',
              }}
              title={`${seg.label}: ${counts[seg.key]}`}
            />
          )
        })}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 flex-wrap">
        {present.map(seg => (
          <span key={seg.key} className="flex items-center gap-1">
            <span
              className="inline-block w-1.5 h-1.5 rounded-full shrink-0"
              style={{ backgroundColor: seg.color }}
            />
            <span className="text-xs text-text-muted">
              {seg.label}{' '}
              <span className="font-medium text-text-secondary">{counts[seg.key]}</span>
            </span>
          </span>
        ))}
      </div>
    </div>
  )
}
