import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { severityColor, SeverityBadge } from '../src/components/ui/Badge'

describe('severityColor', () => {
  it('maps known severities to their color classes', () => {
    expect(severityColor('Critical')).toContain('text-critical')
    expect(severityColor('High')).toContain('text-high')
    expect(severityColor('Medium')).toContain('text-medium')
    expect(severityColor('Low')).toContain('text-low')
  })

  it('falls back to the info style for anything else, case-insensitively', () => {
    expect(severityColor('Info')).toContain('text-info')
    expect(severityColor('unknown-value')).toContain('text-info')
  })
})

describe('SeverityBadge', () => {
  it('renders the severity label, title-cased', () => {
    render(<SeverityBadge severity="high" />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })

  it('renders "Info" when given an empty severity', () => {
    render(<SeverityBadge severity="" />)
    expect(screen.getByText('Info')).toBeInTheDocument()
  })
})
