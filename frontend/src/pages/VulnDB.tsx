import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { BookOpenIcon, ArrowPathIcon } from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/Button'
import { SearchInput } from '@/components/ui/Input'
import { PageSpinner, EmptyState } from '@/components/ui/Spinner'
import { SeverityBadge } from '@/components/ui/Badge'
import { Modal } from '@/components/ui/Modal'
import toast from 'react-hot-toast'

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info']

function DetailField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-1">{label}</p>
      {children}
    </div>
  )
}

export default function VulnDBPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.is_superuser || user?.is_staff

  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [selectedEntry, setSelectedEntry] = useState<string | number | null>(null)

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

  const { data: entryData, isLoading: entryLoading } = useQuery({
    queryKey: ['vulndb-entry', selectedEntry],
    queryFn: () => standardizedApiClient.getVulnDBEntry(selectedEntry!),
    enabled: selectedEntry !== null,
  })

  const sync = useMutation({
    mutationFn: () => standardizedApiClient.syncVulnDB(),
    onSuccess: (result: any) => {
      qc.invalidateQueries({ queryKey: ['vulndb'] })
      toast.success(`Sync complete — ${result?.created ?? 0} added, ${result?.updated ?? 0} updated`)
    },
    onError: (e: any) => toast.error(e?.message || 'Sync failed'),
  })

  const handleSearch = (val: string) => {
    setSearch(val)
    setPage(1)
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">Vulnerability Library</h1>
          <p className="text-xs text-text-muted mt-0.5">
            Pre-populated templates for common findings.{total > 0 ? ` ${total} entries.` : ''}
          </p>
        </div>
        {isAdmin && (
          <Button
            variant="outline"
            size="sm"
            icon={<ArrowPathIcon className="w-4 h-4" />}
            onClick={() => sync.mutate()}
            loading={sync.isPending}
          >
            Sync from GitHub
          </Button>
        )}
      </div>

      <div className="flex gap-2">
        <SearchInput
          value={search}
          onChange={handleSearch}
          placeholder="Search library…"
          className="flex-1"
        />
        <select
          value={severity}
          onChange={e => {
            setSeverity(e.target.value)
            setPage(1)
          }}
          className="px-3 py-2 rounded-lg bg-app-surface border border-border-default text-sm text-text-primary focus:outline-none focus:border-accent-500 focus:ring-1 focus:ring-accent-500/30"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map(s => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <PageSpinner />
      ) : entries.length === 0 ? (
        <EmptyState
          icon={BookOpenIcon}
          title={search || severity ? 'No vulnerabilities match your search.' : 'Library is empty'}
          description={
            search || severity
              ? 'Try different keywords or remove the severity filter.'
              : isAdmin
              ? 'Use "Sync from GitHub" to pull the latest vulnerability templates.'
              : 'The vulnerability library has not been populated yet. Ask an administrator to sync it.'
          }
          action={
            isAdmin && !search && !severity ? (
              <Button
                variant="outline"
                size="sm"
                icon={<ArrowPathIcon className="w-4 h-4" />}
                onClick={() => sync.mutate()}
                loading={sync.isPending}
              >
                Sync from GitHub
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="bg-app-surface border border-border-subtle rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-app-raised border-b border-border-subtle">
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">
                  Name
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider hidden sm:table-cell">
                  Severity
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider hidden lg:table-cell">
                  CVSS
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider hidden lg:table-cell">
                  CWE
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {entries.map((v: any) => (
                <tr
                  key={v.id}
                  onClick={() => setSelectedEntry(v.id)}
                  className="hover:bg-app-overlay/50 transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3">
                    <p className="text-sm font-medium text-text-primary">{v.vulnerabilityname}</p>
                    {v.vulnerabilitydescription && (
                      <p className="text-xs text-text-muted mt-0.5 line-clamp-2 max-w-md">
                        {v.vulnerabilitydescription}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3 hidden sm:table-cell">
                    <SeverityBadge severity={v.vulnerabilityseverity} />
                  </td>
                  <td className="px-4 py-3 text-text-secondary text-xs hidden lg:table-cell">
                    {v.cvssscore != null ? v.cvssscore : '—'}
                  </td>
                  <td className="px-4 py-3 text-text-muted text-xs hidden lg:table-cell font-mono">
                    {v.cwe || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(data?.count ?? 0) > 20 && (
        <div className="flex justify-center items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPage(p => p - 1)}
            disabled={page === 1}
          >
            Previous
          </Button>
          <span className="text-sm text-text-muted">Page {page}</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPage(p => p + 1)}
            disabled={entries.length < 20}
          >
            Next
          </Button>
        </div>
      )}

      <Modal
        isOpen={selectedEntry !== null}
        onClose={() => setSelectedEntry(null)}
        title={entryData?.vulnerabilityname || 'Loading…'}
        size="lg"
        footer={
          <Button variant="ghost" size="sm" onClick={() => setSelectedEntry(null)}>
            Close
          </Button>
        }
      >
        {entryLoading ? (
          <PageSpinner />
        ) : entryData ? (
          <div className="space-y-4">
            {entryData.vulnerabilityseverity && (
              <DetailField label="Severity">
                <SeverityBadge severity={entryData.vulnerabilityseverity} />
              </DetailField>
            )}
            {entryData.cvssscore != null && (
              <DetailField label="CVSS Score">
                <p className="text-sm text-text-primary">{entryData.cvssscore}</p>
              </DetailField>
            )}
            {entryData.cvssvector && (
              <DetailField label="CVSS Vector">
                <p className="text-sm text-text-secondary font-mono">{entryData.cvssvector}</p>
              </DetailField>
            )}
            {entryData.cve && (
              <DetailField label="CVE">
                <p className="text-sm text-text-primary">
                  {Array.isArray(entryData.cve) ? entryData.cve.join(', ') : entryData.cve}
                </p>
              </DetailField>
            )}
            {entryData.cwe && (
              <DetailField label="CWE">
                <p className="text-sm text-text-secondary">
                  {Array.isArray(entryData.cwe) ? entryData.cwe.join(', ') : entryData.cwe}
                </p>
              </DetailField>
            )}
            {entryData.vulnerabilitydescription && (
              <DetailField label="Description">
                <p className="text-sm text-text-secondary whitespace-pre-wrap leading-relaxed">
                  {entryData.vulnerabilitydescription}
                </p>
              </DetailField>
            )}
            {entryData.vulnerabilitysolution && (
              <DetailField label="Solution">
                <p className="text-sm text-text-secondary whitespace-pre-wrap leading-relaxed">
                  {entryData.vulnerabilitysolution}
                </p>
              </DetailField>
            )}
            {entryData.vulnerabilityreferlnk && (
              <DetailField label="References">
                <div className="space-y-0.5">
                  {String(entryData.vulnerabilityreferlnk)
                    .split(/\n+/)
                    .filter(Boolean)
                    .map((line: string, i: number) =>
                      /^https?:\/\//.test(line.trim()) ? (
                        <a
                          key={i}
                          href={line.trim()}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="block text-xs text-accent-400 hover:text-text-primary underline underline-offset-2 truncate transition-colors"
                        >
                          {line.trim()}
                        </a>
                      ) : (
                        <p key={i} className="text-xs text-text-secondary">
                          {line.trim()}
                        </p>
                      )
                    )}
                </div>
              </DetailField>
            )}
          </div>
        ) : null}
      </Modal>
    </div>
  )
}
