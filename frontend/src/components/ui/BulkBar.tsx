import { XMarkIcon } from '@heroicons/react/24/outline'
import { Button } from './Button'
import { ReactNode } from 'react'

interface BulkAction {
  label: string
  icon?: ReactNode
  onClick: () => void
  danger?: boolean
}

interface BulkBarProps {
  selectedCount: number
  onClear: () => void
  actions: BulkAction[]
}

export function BulkBar({ selectedCount, onClear, actions }: BulkBarProps) {
  if (selectedCount === 0) return null

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-30 animate-float-up">
      <div className="bg-app-raised border border-border-strong rounded-2xl shadow-2xl px-4 py-3 flex items-center gap-3">
        {/* Count + clear */}
        <span className="text-sm text-text-secondary whitespace-nowrap">
          {selectedCount} selected
        </span>
        <button
          onClick={onClear}
          className="text-text-muted hover:text-text-secondary transition-colors rounded p-0.5"
          aria-label="Clear selection"
        >
          <XMarkIcon className="w-4 h-4" />
        </button>

        {/* Divider */}
        <span className="w-px h-4 bg-border-default shrink-0" aria-hidden="true" />

        {/* Actions */}
        <div className="flex items-center gap-1.5">
          {actions.map((action, i) => (
            <Button
              key={i}
              variant={action.danger ? 'danger' : 'ghost'}
              size="sm"
              onClick={action.onClick}
              icon={action.icon}
            >
              {action.label}
            </Button>
          ))}
        </div>
      </div>
    </div>
  )
}
