import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { MagnifyingGlassIcon, BookOpenIcon, ArrowPathIcon } from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/Button'
import { PageSpinner, EmptyState } from '@/components/ui/Spinner'
import { severityBadge } from '@/components/ui/Badge'
import toast from 'react-hot-toast'

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info']

export default function VulnDBPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.is_superuser || user?.is_staff

  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['vulndb', { search, page, severity }],
    queryFn: () =>
      standardizedApiClient.getVulnDB({
        search,
        page,
        page_size: 20,
        vulnerabilityseverity: severity || undefined,
      }),
  })
  const entries = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []
  const total = data?.count ?? entries.length

  const sync = useMutation({
    mutationFn: () => standardizedApiClient.syncVulnDB(),
    onSuccess: (result: any) => {
      qc.invalidateQueries({ queryKey: ['vulndb'] })
      toast.success(
        `Sync complete — ${result?.created ?? 0} added, ${result?.updated ?? 0} updated`
      )
    },
    onError: (e: any) => toast.error(e?.message || 'Sync failed'),
  })

  return (
    <div className="p-6 space-y-5 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-white">Vulnerability Library</h1>
          <p className="text-xs text-slate-500 mt-0.5">{total} entries — sourced from GitHub</p>
        </div>
        {isAdmin && (
          <Button size="sm" variant="secondary" onClick={() => sync.mutate()} loading={sync.isPending}>
            <ArrowPathIcon className="w-4 h-4" />
            Sync from GitHub
          </Button>
        )}
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
            placeholder="Search library…"
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <select
          value={severity}
          onChange={e => { setSeverity(e.target.value); setPage(1) }}
          className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {isLoading ? (
        <PageSpinner />
      ) : entries.length === 0 ? (
        <EmptyState
          icon={BookOpenIcon}
          title="Library is empty"
          subtitle={
            isAdmin
              ? 'Use "Sync from GitHub" to pull the latest vulnerability templates.'
              : 'The vulnerability library has not been populated yet. Ask an administrator to sync it.'
          }
          action={
            isAdmin ? (
              <Button size="sm" variant="secondary" onClick={() => sync.mutate()} loading={sync.isPending}>
                <ArrowPathIcon className="w-4 h-4" />
                Sync from GitHub
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">Name</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase hidden sm:table-cell">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase hidden lg:table-cell">CVSS</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase hidden lg:table-cell">CWE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {entries.map((v: any) => (
                <tr key={v.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-3 text-white font-medium">{v.vulnerabilityname}</td>
                  <td className="px-4 py-3 hidden sm:table-cell">{severityBadge(v.vulnerabilityseverity)}</td>
                  <td className="px-4 py-3 text-slate-400 text-xs hidden lg:table-cell">
                    {v.cvssscore != null ? v.cvssscore : '—'}
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs hidden lg:table-cell font-mono">{v.cwe || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(data?.count ?? 0) > 20 && (
        <div className="flex justify-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => setPage(p => p - 1)} disabled={page === 1}>
            Previous
          </Button>
          <span className="flex items-center text-sm text-slate-400">Page {page}</span>
          <Button variant="ghost" size="sm" onClick={() => setPage(p => p + 1)} disabled={entries.length < 20}>
            Next
          </Button>
        </div>
      )}
    </div>
  )
}
