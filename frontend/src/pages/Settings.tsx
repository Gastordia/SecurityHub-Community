import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowPathIcon } from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/Button'
import { PageSpinner } from '@/components/ui/Spinner'
import toast from 'react-hot-toast'

type SettingsTab = 'project-types' | 'report-standards'

// ── Read-only list viewer ───────────────────────────────────────────────────

function ListViewer<T extends { id: number; name?: string }>({
  items, loading, nameKey, isAdmin, onSync, syncing,
}: {
  items: T[]; loading: boolean; nameKey: keyof T
  isAdmin: boolean; onSync: () => void; syncing: boolean
}) {
  return (
    <>
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-slate-500">{items.length} entries — sourced from GitHub</p>
        {isAdmin && (
          <Button size="sm" variant="secondary" onClick={onSync} loading={syncing}>
            <ArrowPathIcon className="w-4 h-4" /> Sync from GitHub
          </Button>
        )}
      </div>
      {loading ? <PageSpinner /> : items.length === 0 ? (
        <div className="py-8 text-center">
          <p className="text-sm text-slate-600 mb-3">None defined yet.</p>
          {isAdmin && (
            <Button size="sm" variant="secondary" onClick={onSync} loading={syncing}>
              <ArrowPathIcon className="w-4 h-4" /> Sync from GitHub
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-1">
          {items.map(item => (
            <div key={item.id} className="flex items-center bg-slate-800/60 border border-slate-700/50 rounded-lg px-4 py-2.5">
              <span className="text-sm text-white">{item[nameKey] as string}</span>
            </div>
          ))}
        </div>
      )}
    </>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.is_superuser || user?.is_staff
  const [tab, setTab] = useState<SettingsTab>('project-types')

  const { data: ptData, isLoading: ptLoading } = useQuery({
    queryKey: ['project-types'],
    queryFn: () => standardizedApiClient.getProjectTypes(),
  })
  const { data: rsData, isLoading: rsLoading } = useQuery({
    queryKey: ['report-standards'],
    queryFn: () => standardizedApiClient.getReportStandards(),
  })

  const pts = Array.isArray(ptData?.results) ? ptData.results : Array.isArray(ptData) ? ptData : []
  const rss = Array.isArray(rsData?.results) ? rsData.results : Array.isArray(rsData) ? rsData : []

  const syncPT = useMutation({
    mutationFn: () => standardizedApiClient.syncProjectTypes(),
    onSuccess: (result: any) => {
      qc.invalidateQueries({ queryKey: ['project-types'] })
      toast.success(`Sync complete — ${result?.created ?? 0} added, ${result?.updated ?? 0} updated`)
    },
    onError: (e: any) => toast.error(e?.message || 'Sync failed'),
  })
  const syncRS = useMutation({
    mutationFn: () => standardizedApiClient.syncReportStandards(),
    onSuccess: (result: any) => {
      qc.invalidateQueries({ queryKey: ['report-standards'] })
      toast.success(`Sync complete — ${result?.created ?? 0} added, ${result?.updated ?? 0} updated`)
    },
    onError: (e: any) => toast.error(e?.message || 'Sync failed'),
  })

  const tabs: { id: SettingsTab; label: string }[] = [
    { id: 'project-types',    label: 'Project Types' },
    { id: 'report-standards', label: 'Report Standards' },
  ]

  return (
    <div className="p-6 space-y-5 max-w-3xl">
      <div>
        <h1 className="text-lg font-semibold text-white">Settings</h1>
        <p className="text-xs text-slate-500 mt-0.5">Configure your SecurityHub workspace</p>
      </div>

      <div className="border-b border-slate-800">
        <nav className="-mb-px flex gap-4">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
                tab === t.id ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        {tab === 'project-types' && (
          <ListViewer items={pts} loading={ptLoading} nameKey="name"
            isAdmin={!!isAdmin} onSync={() => syncPT.mutate()} syncing={syncPT.isPending} />
        )}
        {tab === 'report-standards' && (
          <ListViewer items={rss} loading={rsLoading} nameKey="name"
            isAdmin={!!isAdmin} onSync={() => syncRS.mutate()} syncing={syncRS.isPending} />
        )}
      </div>
    </div>
  )
}
