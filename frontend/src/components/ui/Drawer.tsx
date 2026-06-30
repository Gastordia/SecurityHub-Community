import { useEffect, useRef, ReactNode } from 'react'
import { XMarkIcon } from '@heroicons/react/24/outline'

type DrawerWidth = 'md' | 'lg' | 'xl'

interface DrawerProps {
  isOpen: boolean
  onClose: () => void
  title: string
  subtitle?: string
  width?: DrawerWidth
  children: ReactNode
}

const widthStyles: Record<DrawerWidth, string> = {
  md: '480px',
  lg: '600px',
  xl: '760px',
}

export function Drawer({ isOpen, onClose, title, subtitle, width = 'lg', children }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null)

  // Escape to close
  useEffect(() => {
    if (!isOpen) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [isOpen, onClose])

  // Focus trap: move focus into panel when opened
  useEffect(() => {
    if (!isOpen) return
    const prev = document.activeElement as HTMLElement | null
    const panel = panelRef.current
    if (panel) {
      const focusable = panel.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
      if (focusable.length) focusable[0].focus()
    }
    return () => {
      prev?.focus()
    }
  }, [isOpen])

  if (!isOpen) return null

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div
        ref={panelRef}
        className="fixed top-0 right-0 bottom-0 bg-app-raised border-l border-border-default z-50 overflow-y-auto animate-slide-in"
        style={{ width: widthStyles[width] }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
      >
        {/* Header */}
        <div className="sticky top-0 bg-app-raised border-b border-border-subtle px-6 py-4 flex items-center justify-between z-10">
          <div className="min-w-0 mr-3">
            <h2 id="drawer-title" className="text-base font-semibold text-text-primary truncate">
              {title}
            </h2>
            {subtitle && (
              <p className="text-xs text-text-muted mt-0.5 truncate">{subtitle}</p>
            )}
          </div>
          <button
            onClick={onClose}
            className="shrink-0 text-text-muted hover:text-text-secondary transition-colors rounded-lg p-1"
            aria-label="Close panel"
          >
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5">{children}</div>
      </div>
    </>
  )
}
