import { clsx } from 'clsx'
import React from 'react'

// ── Generic Badge ────────────────────────────────────────────────────────────

interface BadgeProps {
  children: React.ReactNode
  className?: string
}

export function Badge({ children, className }: BadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-mono font-medium',
        className
      )}
    >
      {children}
    </span>
  )
}

// ── Severity ─────────────────────────────────────────────────────────────────

/**
 * Returns a Tailwind class string for bg + text + border that matches the severity.
 * Suitable for use on any element, not just Badge.
 */
export function severityColor(severity: string): string {
  const s = severity?.toLowerCase()
  if (s === 'critical') return 'bg-critical/15 text-critical border border-critical/30'
  if (s === 'high')     return 'bg-high/15 text-high border border-high/30'
  if (s === 'medium')   return 'bg-medium/15 text-medium border border-medium/30'
  if (s === 'low')      return 'bg-low/15 text-low border border-low/30'
  return                       'bg-info/15 text-info border border-info/30'
}

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const label = severity
    ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase()
    : 'Info'
  return (
    <Badge className={clsx(severityColor(severity), className)}>
      {label}
    </Badge>
  )
}

// ── Status ────────────────────────────────────────────────────────────────────

function statusColor(status: string): string {
  const s = status?.toLowerCase()
  if (s === 'vulnerable')      return 'bg-critical/15 text-critical border border-critical/30'
  if (s === 'confirm_fixed' || s === 'confirm fixed' || s === 'fixed')
                                return 'bg-low/15 text-low border border-low/30'
  if (s === 'accepted_risk' || s === 'accepted risk')
                                return 'bg-medium/15 text-medium border border-medium/30'
  if (s === 'false_positive' || s === 'false positive')
                                return 'bg-text-muted/15 text-text-secondary border border-border-default'
  return                               'bg-info/15 text-info border border-info/30'
}

function statusLabel(status: string): string {
  const s = status?.toLowerCase()
  if (s === 'vulnerable')                                  return 'Vulnerable'
  if (s === 'confirm_fixed' || s === 'confirm fixed' || s === 'fixed') return 'Confirm Fixed'
  if (s === 'accepted_risk' || s === 'accepted risk')      return 'Accepted Risk'
  if (s === 'false_positive' || s === 'false positive')    return 'False Positive'
  return status || 'Unknown'
}

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <Badge className={clsx(statusColor(status), className)}>
      {statusLabel(status)}
    </Badge>
  )
}
