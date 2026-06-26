import { useState, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  PlusIcon, TrashIcon, CloudArrowUpIcon,
  DocumentArrowDownIcon, ShieldExclamationIcon, WrenchScrewdriverIcon,
  ChevronDownIcon, ChevronRightIcon, MagnifyingGlassIcon,
  ArrowLeftIcon, ArrowsUpDownIcon, CheckCircleIcon,
  ExclamationTriangleIcon, InformationCircleIcon,
} from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { Button } from '@/components/ui/Button'
import { Input, Textarea, Select } from '@/components/ui/Input'
import { Modal, ConfirmModal } from '@/components/ui/Modal'
import { PageSpinner, EmptyState } from '@/components/ui/Spinner'
import { severityBadge, Badge } from '@/components/ui/Badge'
import toast from 'react-hot-toast'

type Tab = 'vulnerabilities' | 'assets' | 'scope' | 'scanner' | 'report'

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info']
const TABS: { id: Tab; label: string }[] = [
  { id: 'vulnerabilities', label: 'Findings' },
  { id: 'assets',          label: 'Assets' },
  { id: 'scope',           label: 'Scope' },
  { id: 'scanner',         label: 'Scanner' },
  { id: 'report',          label: 'Report' },
]

const PROJECT_STATUSES = ['In Progress', 'Completed', 'Delay', 'Hold'] as const

// ── Findings ──────────────────────────────────────────────────────────────────

const VULN_STATUSES = ['Vulnerable', 'Confirm Fixed', 'Accepted Risk', 'False Positive']

function toIdList(raw: any): string {
  if (!raw) return ''
  return (Array.isArray(raw) ? raw : [raw]).join(', ')
}
function parseIdList(text: string): string[] {
  return text.split(/[,\s]+/).map(s => s.trim()).filter(Boolean)
}
function toCommaSep(val: any): string {
  if (!val) return ''
  if (Array.isArray(val)) return val.join(', ')
  return String(val)
}
function parseCommaSep(text: string): string[] {
  return text.split(',').map(s => s.trim()).filter(Boolean)
}

function VulnForm({ initial, projectId, onSave, onCancel, loading }: {
  initial?: any; projectId: string; onSave: (d: any) => void; onCancel: () => void; loading: boolean
}) {
  const [form, setForm] = useState({
    project: projectId,
    vulnerabilityname:        initial?.vulnerabilityname        || '',
    vulnerabilityseverity:    initial?.vulnerabilityseverity    || 'Medium',
    cvssscore:                initial?.cvssscore                ?? '',
    cvssvector:               initial?.cvssvector               || '',
    status:                   initial?.status                   || 'Vulnerable',
    vulnerabilitydescription: initial?.vulnerabilitydescription || '',
    vulnerabilitysolution:    initial?.vulnerabilitysolution    || '',
    POC:                      initial?.POC                      || '',
    vulnerabilityreferlnk:    initial?.vulnerabilityreferlnk    || '',
    cweText: toIdList(initial?.cwe),
    cveText: toIdList(initial?.cve),
    verified:       !!initial?.verified,
    false_positive: !!initial?.false_positive,
    suppressed:     !!initial?.suppressed,
    // Triage
    risk_acceptance:        !!initial?.risk_acceptance,
    risk_acceptance_reason: initial?.risk_acceptance_reason || '',
    // SAST
    source_file:  initial?.source_file  || '',
    source_line:  initial?.source_line  ?? '',
    sink_file:    initial?.sink_file    || '',
    sink_line:    initial?.sink_line    ?? '',
    tainted_flow: !!initial?.tainted_flow,
    // Container / Kubernetes
    cloud_platform:         initial?.cloud_platform         || '',
    kubernetes_cluster:     initial?.kubernetes_cluster     || '',
    kubernetes_namespace:   initial?.kubernetes_namespace   || '',
    kubernetes_workload:    initial?.kubernetes_workload    || '',
    container_image:        initial?.container_image        || '',
    container_image_digest: initial?.container_image_digest || '',
    // Dependency / SCA
    package_name:        initial?.package_name        || '',
    package_version:     initial?.package_version     || '',
    package_type:        initial?.package_type        || '',
    installed_version:   initial?.installed_version   || '',
    vulnerable_versions: initial?.vulnerable_versions || '',
    // Compliance (comma-separated text → array on submit)
    compliance_frameworksText: toCommaSep(initial?.compliance_frameworks),
    nist_800_53_controlsText:  toCommaSep(initial?.nist_800_53_controls),
    masvs_controlsText:        toCommaSep(initial?.masvs_controls),
    disa_stigText:             toCommaSep(initial?.disa_stig),
    // MITRE ATT&CK (comma-separated text → array on submit)
    mitre_tacticsText:    toCommaSep(initial?.mitre_tactics),
    mitre_techniquesText: toCommaSep(initial?.mitre_techniques),
  })

  const set  = (k: string) => (e: React.ChangeEvent<any>) => setForm(f => ({ ...f, [k]: e.target.value }))
  const setB = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm(f => ({ ...f, [k]: e.target.checked }))

  const handleSave = () => {
    const {
      cweText, cveText,
      compliance_frameworksText, nist_800_53_controlsText, masvs_controlsText, disa_stigText,
      mitre_tacticsText, mitre_techniquesText,
      ...rest
    } = form
    const cwe = parseIdList(cweText)
    const cve = parseIdList(cveText)
    const compliance_frameworks = parseCommaSep(compliance_frameworksText)
    const nist_800_53_controls  = parseCommaSep(nist_800_53_controlsText)
    const masvs_controls        = parseCommaSep(masvs_controlsText)
    const disa_stig             = parseCommaSep(disa_stigText)
    const mitre_tactics         = parseCommaSep(mitre_tacticsText)
    const mitre_techniques      = parseCommaSep(mitre_techniquesText)
    onSave({
      ...rest,
      ...(cwe.length               ? { cwe }                : {}),
      ...(cve.length               ? { cve }                : {}),
      ...(compliance_frameworks.length ? { compliance_frameworks } : {}),
      ...(nist_800_53_controls.length  ? { nist_800_53_controls }  : {}),
      ...(masvs_controls.length    ? { masvs_controls }    : {}),
      ...(disa_stig.length         ? { disa_stig }         : {}),
      ...(mitre_tactics.length     ? { mitre_tactics }     : {}),
      ...(mitre_techniques.length  ? { mitre_techniques }  : {}),
    })
  }

  // shared raw-input class
  const inp = 'w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500'

  return (
    <form onSubmit={e => { e.preventDefault(); handleSave() }} className="space-y-4">
      {/* ── Core identity ── */}
      <Input label="Name *" value={form.vulnerabilityname} onChange={set('vulnerabilityname')} required />

      <div className="grid grid-cols-3 gap-3">
        <Select label="Severity" value={form.vulnerabilityseverity} onChange={set('vulnerabilityseverity')}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Input label="CVSS Score" type="number" step="0.1" min="0" max="10" value={form.cvssscore} onChange={set('cvssscore')} />
        <Select label="Status" value={form.status} onChange={set('status')}>
          {VULN_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </Select>
      </div>

      <Input label="CVSS Vector" placeholder="AV:N/AC:L/Au:N/C:P/I:P/A:P" value={form.cvssvector} onChange={set('cvssvector')} />

      <div className="grid grid-cols-2 gap-3">
        <Input label="CWE IDs" placeholder="CWE-79, CWE-89…" value={form.cweText} onChange={set('cweText')} />
        <Input label="CVE IDs" placeholder="CVE-2023-1234, CVE-2024-5678…" value={form.cveText} onChange={set('cveText')} />
      </div>

      {/* ── Narrative ── */}
      <Textarea label="Description" rows={3} value={form.vulnerabilitydescription} onChange={set('vulnerabilitydescription')} />
      <Textarea label="Proof of Concept" rows={2} value={form.POC} onChange={set('POC')} />
      <Textarea label="Remediation" rows={2} value={form.vulnerabilitysolution} onChange={set('vulnerabilitysolution')} />
      <Textarea label="References / Links" placeholder="https://…" rows={2} value={form.vulnerabilityreferlnk} onChange={set('vulnerabilityreferlnk')} />

      {/* ── Workflow flags ── */}
      <div className="flex flex-wrap gap-4 pt-1">
        {[
          { key: 'verified',       label: 'Verified' },
          { key: 'false_positive', label: 'False Positive' },
          { key: 'suppressed',     label: 'Suppressed' },
        ].map(({ key, label }) => (
          <label key={key} className="flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox"
              checked={form[key as keyof typeof form] as boolean}
              onChange={setB(key)}
              className="w-3.5 h-3.5 rounded accent-indigo-500" />
            <span className="text-sm text-slate-400">{label}</span>
          </label>
        ))}
      </div>

      {/* ── Technical Details (collapsible) ── */}
      <details className="group border border-slate-700/50 rounded-lg overflow-hidden">
        <summary className="flex items-center gap-2 px-4 py-3 cursor-pointer bg-slate-800/50 hover:bg-slate-800 transition-colors list-none">
          <ChevronRightIcon className="w-3.5 h-3.5 text-slate-500 group-open:rotate-90 transition-transform shrink-0" />
          <span className="text-sm font-medium text-slate-400">Technical Details</span>
        </summary>

        <div className="px-4 pb-4 pt-3 space-y-5">

          {/* Triage */}
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Triage</p>
            <div className="space-y-3">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={form.risk_acceptance} onChange={setB('risk_acceptance')}
                  className="w-3.5 h-3.5 rounded accent-indigo-500" />
                <span className="text-sm text-slate-400">Risk Acceptance</span>
              </label>
              {form.risk_acceptance && (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Risk Acceptance Reason</label>
                  <textarea value={form.risk_acceptance_reason} onChange={set('risk_acceptance_reason')} rows={2}
                    className={inp + ' resize-none'} />
                </div>
              )}
            </div>
          </div>

          {/* SAST */}
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">SAST</p>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Source File</label>
                  <input type="text" value={form.source_file} onChange={set('source_file')}
                    placeholder="e.g. src/auth/login.py" className={inp} />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Source Line</label>
                  <input type="number" value={form.source_line} onChange={set('source_line')} className={inp} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Sink File</label>
                  <input type="text" value={form.sink_file} onChange={set('sink_file')} className={inp} />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Sink Line</label>
                  <input type="number" value={form.sink_line} onChange={set('sink_line')} className={inp} />
                </div>
              </div>
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={form.tainted_flow} onChange={setB('tainted_flow')}
                  className="w-3.5 h-3.5 rounded accent-indigo-500" />
                <span className="text-sm text-slate-400">Tainted Flow</span>
              </label>
            </div>
          </div>

          {/* Container / Kubernetes */}
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Container / Kubernetes</p>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Cloud Platform</label>
                  <input type="text" value={form.cloud_platform} onChange={set('cloud_platform')}
                    placeholder="aws / azure / gcp" className={inp} />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Kubernetes Cluster</label>
                  <input type="text" value={form.kubernetes_cluster} onChange={set('kubernetes_cluster')} className={inp} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Kubernetes Namespace</label>
                  <input type="text" value={form.kubernetes_namespace} onChange={set('kubernetes_namespace')} className={inp} />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Kubernetes Workload</label>
                  <input type="text" value={form.kubernetes_workload} onChange={set('kubernetes_workload')} className={inp} />
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Container Image</label>
                <input type="text" value={form.container_image} onChange={set('container_image')} className={inp} />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Container Image Digest</label>
                <input type="text" value={form.container_image_digest} onChange={set('container_image_digest')} className={inp} />
              </div>
            </div>
          </div>

          {/* Dependency / SCA */}
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Dependency / SCA</p>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Package Name</label>
                  <input type="text" value={form.package_name} onChange={set('package_name')} className={inp} />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Package Version</label>
                  <input type="text" value={form.package_version} onChange={set('package_version')} className={inp} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Package Type</label>
                  <input type="text" value={form.package_type} onChange={set('package_type')}
                    placeholder="npm / pip / maven / go" className={inp} />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Installed Version</label>
                  <input type="text" value={form.installed_version} onChange={set('installed_version')} className={inp} />
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Vulnerable Versions</label>
                <input type="text" value={form.vulnerable_versions} onChange={set('vulnerable_versions')}
                  placeholder="comma-separated ranges" className={inp} />
              </div>
            </div>
          </div>

          {/* Compliance */}
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Compliance</p>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Compliance Frameworks</label>
                <input type="text" value={form.compliance_frameworksText} onChange={set('compliance_frameworksText')}
                  placeholder="PCI DSS, ISO 27001" className={inp} />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">NIST 800-53 Controls</label>
                <input type="text" value={form.nist_800_53_controlsText} onChange={set('nist_800_53_controlsText')}
                  placeholder="AC-2, AC-3" className={inp} />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">MASVS Controls</label>
                <input type="text" value={form.masvs_controlsText} onChange={set('masvs_controlsText')}
                  placeholder="MASVS-STORAGE-1" className={inp} />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">DISA STIG</label>
                <input type="text" value={form.disa_stigText} onChange={set('disa_stigText')}
                  placeholder="V-123456" className={inp} />
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK */}
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">MITRE ATT&amp;CK</p>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Tactics</label>
                <input type="text" value={form.mitre_tacticsText} onChange={set('mitre_tacticsText')}
                  placeholder="TA0001, TA0002" className={inp} />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Techniques</label>
                <input type="text" value={form.mitre_techniquesText} onChange={set('mitre_techniquesText')}
                  placeholder="T1190, T1059" className={inp} />
              </div>
            </div>
          </div>

        </div>
      </details>

      <div className="flex justify-end gap-2 pt-1">
        <Button variant="secondary" size="sm" type="button" onClick={onCancel} disabled={loading}>Cancel</Button>
        <Button size="sm" type="submit" loading={loading}>Save</Button>
      </div>
    </form>
  )
}

const SEVERITY_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4, Informational: 4, None: 4 }
const INSTANCE_STATUSES = ['Vulnerable', 'Accepted Risk', 'False Positive', 'Resolved']

function InstancesSection({ vulnId }: { vulnId: string | number }) {
  const qc = useQueryClient()
  const [url, setUrl] = useState('')
  const [param, setParam] = useState('')
  const [instStatus, setInstStatus] = useState('Vulnerable')
  const [deleteTarget, setDeleteTarget] = useState<any>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['instances', vulnId],
    queryFn: () => standardizedApiClient.getVulnerabilityInstances(vulnId),
  })
  const instances = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []

  const add = useMutation({
    mutationFn: () => standardizedApiClient.createVulnerabilityInstance(vulnId, { URL: url, Parameter: param, status: instStatus }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['instances', vulnId] }); setUrl(''); setParam(''); toast.success('Asset added') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteVulnerabilityInstance(vulnId, deleteTarget.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['instances', vulnId] }); setDeleteTarget(null); toast.success('Removed') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  return (
    <div className="mt-4 pt-4 border-t border-slate-700/50">
      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Affected Assets</p>
      {isLoading ? <p className="text-xs text-slate-600">Loading…</p> : instances.length > 0 && (
        <div className="space-y-1 mb-3">
          {instances.map((inst: any) => (
            <div key={inst.id} className="flex items-center gap-2 bg-slate-900/60 rounded-lg px-3 py-2 text-xs">
              <span className="font-mono text-slate-300 flex-1 truncate">{inst.URL || '—'}</span>
              {inst.Parameter && <span className="text-slate-500 font-mono truncate max-w-[120px]">{inst.Parameter}</span>}
              <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                inst.status === 'Vulnerable' ? 'bg-red-900/40 text-red-300' :
                inst.status === 'Resolved'   ? 'bg-green-900/40 text-green-300' :
                'bg-slate-700 text-slate-400'}`}>{inst.status}</span>
              <button onClick={() => setDeleteTarget(inst)} className="text-slate-600 hover:text-red-400 shrink-0 transition-colors">
                <TrashIcon className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      )}
      <form onSubmit={e => { e.preventDefault(); if (url.trim()) add.mutate() }} className="flex gap-2">
        <input value={url} onChange={e => setUrl(e.target.value)} placeholder="URL / IP…"
          className="flex-1 min-w-0 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500" />
        <input value={param} onChange={e => setParam(e.target.value)} placeholder="Parameter (opt.)"
          className="w-32 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500" />
        <select value={instStatus} onChange={e => setInstStatus(e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500">
          {INSTANCE_STATUSES.map(s => <option key={s}>{s}</option>)}
        </select>
        <button type="submit" disabled={!url.trim() || add.isPending}
          className="shrink-0 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white text-xs rounded-lg transition-colors">
          Add
        </button>
      </form>
      <ConfirmModal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()}
        title="Remove Asset" message={`Remove "${deleteTarget?.URL}"?`} loading={del.isPending} />
    </div>
  )
}

function IdBadges({ ids, colorClass = 'bg-slate-700/60 border-slate-600/40 text-slate-400' }: { ids: any; colorClass?: string }) {
  const list = Array.isArray(ids) ? ids : ids ? [ids] : []
  if (!list.length) return null
  return (
    <div className="flex flex-wrap gap-1.5">
      {list.map((id: string) => (
        <span key={id} className={`text-[10px] font-mono px-2 py-0.5 border rounded ${colorClass}`}>{id}</span>
      ))}
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-1.5">{title}</p>
      {children}
    </div>
  )
}

function VulnRow({ v, onEdit, onDelete }: { v: any; onEdit: () => void; onDelete: () => void }) {
  const [open, setOpen] = useState(false)

  const cweList = Array.isArray(v.cwe_list) ? v.cwe_list : (Array.isArray(v.cwe) ? v.cwe : v.cwe ? [v.cwe] : [])
  const cveList = Array.isArray(v.cve_list) ? v.cve_list : (Array.isArray(v.cve) ? v.cve : v.cve ? [v.cve] : [])
  const refs    = v.vulnerabilityreferlnk?.trim()
  const poc     = v.POC?.trim()
  const vector  = v.cvssvector?.trim()

  // Build extended-details key-value pairs (Task 4)
  const extDetails = ([
    ['Risk Acceptance',        v.risk_acceptance ? 'Yes' : null],
    ['Risk Acceptance Reason', v.risk_acceptance_reason || null],
    ['Source File',            v.source_file || null],
    ['Source Line',            v.source_line != null && v.source_line !== '' ? String(v.source_line) : null],
    ['Sink File',              v.sink_file || null],
    ['Sink Line',              v.sink_line != null && v.sink_line !== '' ? String(v.sink_line) : null],
    ['Tainted Flow',           v.tainted_flow ? 'Yes' : null],
    ['Cloud Platform',         v.cloud_platform || null],
    ['Kubernetes Cluster',     v.kubernetes_cluster || null],
    ['Kubernetes Namespace',   v.kubernetes_namespace || null],
    ['Kubernetes Workload',    v.kubernetes_workload || null],
    ['Container Image',        v.container_image || null],
    ['Container Image Digest', v.container_image_digest || null],
    ['Package Name',           v.package_name || null],
    ['Package Version',        v.package_version || null],
    ['Package Type',           v.package_type || null],
    ['Installed Version',      v.installed_version || null],
    ['Vulnerable Versions',    v.vulnerable_versions || null],
    ['Compliance Frameworks',  v.compliance_frameworks?.length ? toCommaSep(v.compliance_frameworks) : null],
    ['NIST 800-53 Controls',   v.nist_800_53_controls?.length ? toCommaSep(v.nist_800_53_controls) : null],
    ['MASVS Controls',         v.masvs_controls?.length ? toCommaSep(v.masvs_controls) : null],
    ['DISA STIG',              v.disa_stig?.length ? toCommaSep(v.disa_stig) : null],
    ['MITRE Tactics',          v.mitre_tactics?.length ? toCommaSep(v.mitre_tactics) : null],
    ['MITRE Techniques',       v.mitre_techniques?.length ? toCommaSep(v.mitre_techniques) : null],
  ] as [string, string | null][]).filter(([, val]) => val != null) as [string, string][]

  const hasExtendedDetails = extDetails.length > 0

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-lg overflow-hidden">
      {/* ── Row header ── */}
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-slate-800 transition-colors"
        onClick={() => setOpen(o => !o)}>
        <span className="text-slate-600 shrink-0">
          {open ? <ChevronDownIcon className="w-3.5 h-3.5" /> : <ChevronRightIcon className="w-3.5 h-3.5" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <p className="text-sm text-white font-medium truncate">{v.vulnerabilityname}</p>
            {v.verified        && <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-900/40 text-green-400 border border-green-800/40 font-medium shrink-0">Verified</span>}
            {v.false_positive  && <span className="text-[9px] px-1.5 py-0.5 rounded bg-yellow-900/40 text-yellow-400 border border-yellow-800/40 font-medium shrink-0">FP</span>}
            {v.suppressed      && <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-400 border border-slate-600 font-medium shrink-0">Suppressed</span>}
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            {v.cvssscore > 0 && <span className="text-xs text-slate-500">CVSS {v.cvssscore}</span>}
            {v.instance_count > 0 && <span className="text-xs text-slate-600">{v.instance_count} asset{v.instance_count !== 1 ? 's' : ''}</span>}
            {v.has_exploit && <span className="text-xs text-orange-400">⚡ Exploit known</span>}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0" onClick={e => e.stopPropagation()}>
          {severityBadge(v.vulnerabilityseverity)}
          <button onClick={onEdit} className="text-xs text-slate-500 hover:text-white px-1.5 py-0.5 hover:bg-slate-700 rounded transition-colors">Edit</button>
          <button onClick={onDelete} className="p-1 text-slate-600 hover:text-red-400 rounded transition-colors"><TrashIcon className="w-3.5 h-3.5" /></button>
        </div>
      </div>

      {/* ── Expanded panel ── */}
      {open && (
        <div className="px-4 pb-4 border-t border-slate-700/40 pt-4 space-y-4">

          {/* IDs row */}
          {(cweList.length > 0 || cveList.length > 0) && (
            <div className="flex flex-wrap gap-4">
              {cweList.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-1">CWE</p>
                  <IdBadges ids={cweList} />
                </div>
              )}
              {cveList.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-1">CVE</p>
                  <IdBadges ids={cveList} colorClass="bg-orange-900/30 border-orange-800/40 text-orange-300" />
                </div>
              )}
            </div>
          )}

          {/* CVSS vector */}
          {vector && (
            <Section title="CVSS Vector">
              <p className="text-xs font-mono text-slate-400 bg-slate-900/50 px-3 py-1.5 rounded-lg">{vector}</p>
            </Section>
          )}

          {/* Known exploit (only — dead intel fields removed) */}
          {v.has_exploit && (
            <Section title="Threat Intelligence">
              <div className="flex flex-wrap gap-2">
                <span className="text-xs px-2.5 py-1 rounded-full bg-orange-900/40 border border-orange-800/40 text-orange-300">
                  ⚡ Known Exploit
                </span>
              </div>
            </Section>
          )}

          {/* Description */}
          {v.vulnerabilitydescription && (
            <Section title="Description">
              <p className="text-sm text-slate-300 whitespace-pre-wrap leading-relaxed">{v.vulnerabilitydescription}</p>
            </Section>
          )}

          {/* PoC */}
          {poc && (
            <Section title="Proof of Concept">
              <pre className="text-xs text-slate-300 bg-slate-900/60 rounded-lg px-3 py-2.5 overflow-x-auto whitespace-pre-wrap leading-relaxed font-mono">{poc}</pre>
            </Section>
          )}

          {/* Remediation */}
          {v.vulnerabilitysolution && (
            <Section title="Remediation">
              <p className="text-sm text-slate-300 whitespace-pre-wrap leading-relaxed">{v.vulnerabilitysolution}</p>
            </Section>
          )}

          {/* References */}
          {refs && (
            <Section title="References">
              <div className="space-y-0.5">
                {refs.split(/\n+/).filter(Boolean).map((line: string, i: number) => (
                  /^https?:\/\//.test(line.trim()) ? (
                    <a key={i} href={line.trim()} target="_blank" rel="noopener noreferrer"
                      className="block text-xs text-indigo-400 hover:text-indigo-300 underline underline-offset-2 truncate transition-colors">
                      {line.trim()}
                    </a>
                  ) : (
                    <p key={i} className="text-xs text-slate-400">{line.trim()}</p>
                  )
                ))}
              </div>
            </Section>
          )}

          {/* Technical Details (Task 4) */}
          {hasExtendedDetails && (
            <Section title="Technical Details">
              <div className="grid grid-cols-2 gap-x-6 gap-y-2">
                {extDetails.map(([label, value]) => (
                  <div key={label}>
                    <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">{label}</p>
                    <p className="text-xs text-white mt-0.5 break-words">{value}</p>
                  </div>
                ))}
              </div>
            </Section>
          )}

          <InstancesSection vulnId={v.id} />
        </div>
      )}
    </div>
  )
}

function FindingsTab({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editTarget, setEditTarget] = useState<any>(null)
  const [deleteTarget, setDeleteTarget] = useState<any>(null)
  const [search, setSearch] = useState('')
  const [filterSev, setFilterSev] = useState('All')
  const [sortBy, setSortBy] = useState<'severity' | 'cvss' | 'name'>('severity')

  const { data, isLoading } = useQuery({
    queryKey: ['vulns', projectId],
    queryFn: () => standardizedApiClient.getProjectVulnerabilities(projectId, { page_size: 500 }),
  })
  const vulns = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []

  const { data: stats } = useQuery({
    queryKey: ['vuln-stats', projectId],
    queryFn: () => standardizedApiClient.getVulnerabilityStats(projectId),
    enabled: vulns.length > 0,
  })

  const filtered = useMemo(() => {
    let list = [...vulns]
    if (search) list = list.filter((v: any) => v.vulnerabilityname?.toLowerCase().includes(search.toLowerCase()))
    if (filterSev !== 'All') list = list.filter((v: any) => v.vulnerabilityseverity === filterSev)
    if (sortBy === 'severity') list.sort((a: any, b: any) => (SEVERITY_ORDER[a.vulnerabilityseverity] ?? 5) - (SEVERITY_ORDER[b.vulnerabilityseverity] ?? 5))
    else if (sortBy === 'cvss') list.sort((a: any, b: any) => (b.cvssscore ?? 0) - (a.cvssscore ?? 0))
    else list.sort((a: any, b: any) => (a.vulnerabilityname ?? '').localeCompare(b.vulnerabilityname ?? ''))
    return list
  }, [vulns, search, filterSev, sortBy])

  const create = useMutation({
    mutationFn: (d: any) => standardizedApiClient.createVulnerability(d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['vulns', projectId] }); setShowCreate(false); toast.success('Finding added') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const update = useMutation({
    mutationFn: (d: any) => standardizedApiClient.updateVulnerability(editTarget.id, d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['vulns', projectId] }); setEditTarget(null); toast.success('Updated') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteVulnerability(deleteTarget.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['vulns', projectId] }); setDeleteTarget(null); toast.success('Deleted') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  const sevCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    vulns.forEach((v: any) => { counts[v.vulnerabilityseverity] = (counts[v.vulnerabilityseverity] || 0) + 1 })
    return counts
  }, [vulns])

  const SEV_COLORS: Record<string, string> = {
    Critical: 'bg-red-900/50 text-red-300 border-red-800/50',
    High:     'bg-orange-900/50 text-orange-300 border-orange-800/50',
    Medium:   'bg-yellow-900/50 text-yellow-300 border-yellow-800/50',
    Low:      'bg-blue-900/50 text-blue-300 border-blue-800/50',
    Info:     'bg-slate-700/50 text-slate-400 border-slate-600/50',
  }

  return (
    <>
      {/* Stats bar */}
      {stats && vulns.length > 0 && (
        <div className="grid grid-cols-3 gap-2 mb-5">
          {[
            { label: 'Total', value: stats.total_vulnerabilities ?? vulns.length, color: 'text-white' },
            { label: 'Open', value: stats.open_vulnerabilities ?? 0, color: 'text-red-400' },
            { label: 'Fixed', value: stats.status_counts?.['Confirm Fixed'] ?? 0, color: 'text-green-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-slate-800/50 border border-slate-700/50 rounded-xl px-4 py-3 text-center">
              <p className={`text-xl font-bold ${color}`}>{value}</p>
              <p className="text-xs text-slate-500 mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Severity summary chips */}
      {vulns.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-4">
          {SEVERITIES.filter(s => sevCounts[s]).map(s => (
            <button key={s} onClick={() => setFilterSev(filterSev === s ? 'All' : s)}
              className={`text-xs px-2.5 py-1 rounded-full border font-medium transition-all ${
                SEV_COLORS[s] || 'bg-slate-700 text-slate-400 border-slate-600'
              } ${filterSev === s ? 'ring-2 ring-white/20' : 'opacity-80 hover:opacity-100'}`}>
              {s} · {sevCounts[s]}
            </button>
          ))}
          {filterSev !== 'All' && (
            <button onClick={() => setFilterSev('All')} className="text-xs px-2.5 py-1 text-slate-500 hover:text-white transition-colors">
              Clear ×
            </button>
          )}
        </div>
      )}

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 mb-4">
        <div className="relative flex-1 min-w-[180px]">
          <MagnifyingGlassIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search findings…"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500" />
        </div>
        <div className="relative">
          <ArrowsUpDownIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
          <select value={sortBy} onChange={e => setSortBy(e.target.value as any)}
            className="bg-slate-800 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500 appearance-none">
            <option value="severity">Severity</option>
            <option value="cvss">CVSS Score</option>
            <option value="name">Name A–Z</option>
          </select>
        </div>
        <p className="text-xs text-slate-600">{filtered.length !== vulns.length && `${filtered.length} of `}{vulns.length} finding{vulns.length !== 1 ? 's' : ''}</p>
        <Button size="sm" onClick={() => setShowCreate(true)} className="ml-auto">
          <PlusIcon className="w-4 h-4" /> Add Finding
        </Button>
      </div>

      {isLoading ? <PageSpinner /> : vulns.length === 0 ? (
        <EmptyState icon={ShieldExclamationIcon} title="No findings yet" subtitle="Add manually or import a scan file from the Scanner tab." />
      ) : filtered.length === 0 ? (
        <EmptyState title="No matches" subtitle="Try a different search or filter." />
      ) : (
        <div className="space-y-1.5">
          {filtered.map((v: any) => (
            <VulnRow key={v.id} v={v}
              onEdit={() => setEditTarget(v)}
              onDelete={() => setDeleteTarget(v)} />
          ))}
        </div>
      )}

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Add Finding" size="lg">
        <VulnForm projectId={projectId} onSave={d => create.mutate(d)} onCancel={() => setShowCreate(false)} loading={create.isPending} />
      </Modal>
      <Modal open={!!editTarget} onClose={() => setEditTarget(null)} title="Edit Finding" size="lg">
        <VulnForm initial={editTarget} projectId={projectId} onSave={d => update.mutate(d)} onCancel={() => setEditTarget(null)} loading={update.isPending} />
      </Modal>
      <ConfirmModal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()}
        title="Delete Finding" message={`Delete "${deleteTarget?.vulnerabilityname}"?`} loading={del.isPending} />
    </>
  )
}

// ── Scope ─────────────────────────────────────────────────────────────────────

function ScopeTab({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const [newScope, setNewScope] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [editTarget, setEditTarget] = useState<any>(null)
  const [editScope, setEditScope] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<any>(null)
  const [nmapFile, setNmapFile] = useState<File | null>(null)
  const [nmapResult, setNmapResult] = useState<any>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['scopes', projectId],
    queryFn: () => standardizedApiClient.getProjectScopes(projectId),
  })
  const scopes = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []

  const create = useMutation({
    mutationFn: () => standardizedApiClient.createProjectScope(projectId, { scope: newScope, description: newDesc }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scopes', projectId] }); setNewScope(''); setNewDesc(''); toast.success('Added') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const update = useMutation({
    mutationFn: () => standardizedApiClient.updateProjectScope(projectId, editTarget.id, { scope: editScope, description: editDesc }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scopes', projectId] }); setEditTarget(null); toast.success('Updated') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteProjectScope(projectId, deleteTarget.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scopes', projectId] }); setDeleteTarget(null); toast.success('Removed') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const nmapUpload = useMutation({
    mutationFn: () => {
      const fd = new FormData(); fd.append('file', nmapFile!)
      return standardizedApiClient.uploadNmapScope(projectId, fd)
    },
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['scopes', projectId] })
      setNmapResult(data); setNmapFile(null)
      toast.success(`Imported ${data.imported ?? data.added ?? 0} scope entries from Nmap`)
    },
    onError: (e: any) => toast.error(e?.message || 'Nmap import failed'),
  })

  const startEdit = (s: any) => { setEditTarget(s); setEditScope(s.scope); setEditDesc(s.description || '') }

  return (
    <>
      {isLoading ? <PageSpinner /> : scopes.length === 0 ? (
        <EmptyState title="No scope defined" subtitle="Add URLs, IP ranges, or CIDRs. At least one is required to generate a report." />
      ) : (
        <div className="space-y-1 mb-4">
          {scopes.map((s: any) => (
            editTarget?.id === s.id ? (
              <form key={s.id} onSubmit={e => { e.preventDefault(); update.mutate() }}
                className="flex gap-2 bg-slate-800 border border-indigo-500/50 rounded-lg px-3 py-2">
                <input value={editScope} onChange={e => setEditScope(e.target.value)} required autoFocus
                  className="flex-1 min-w-0 bg-transparent text-sm text-white font-mono focus:outline-none placeholder-slate-600" />
                <input value={editDesc} onChange={e => setEditDesc(e.target.value)} placeholder="Description"
                  className="w-40 bg-transparent text-sm text-slate-400 focus:outline-none placeholder-slate-600" />
                <button type="submit" disabled={!editScope.trim() || update.isPending}
                  className="text-xs text-indigo-400 hover:text-indigo-300 disabled:opacity-40 shrink-0">Save</button>
                <button type="button" onClick={() => setEditTarget(null)} className="text-xs text-slate-500 hover:text-white shrink-0">✕</button>
              </form>
            ) : (
              <div key={s.id} className="group flex items-center gap-3 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/50 rounded-lg px-4 py-2.5 transition-colors">
                <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-white font-mono truncate">{s.scope}</p>
                  {s.description && <p className="text-xs text-slate-500 mt-0.5">{s.description}</p>}
                </div>
                <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-all">
                  <button onClick={() => startEdit(s)} className="text-xs text-slate-500 hover:text-white px-1.5 py-0.5 hover:bg-slate-700 rounded transition-colors">Edit</button>
                  <button onClick={() => setDeleteTarget(s)} className="p-1 text-slate-600 hover:text-red-400 rounded transition-colors">
                    <TrashIcon className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )
          ))}
        </div>
      )}

      {/* Manual add */}
      <form onSubmit={e => { e.preventDefault(); if (newScope.trim()) create.mutate() }}
        className="flex gap-2 pt-3 border-t border-slate-800">
        <div className="relative flex-1 min-w-0">
          <PlusIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-600 pointer-events-none" />
          <input value={newScope} onChange={e => setNewScope(e.target.value)} placeholder="URL / IP / CIDR…"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500" />
        </div>
        <input value={newDesc} onChange={e => setNewDesc(e.target.value)} placeholder="Description (opt.)"
          className="w-44 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500" />
        <Button size="sm" type="submit" loading={create.isPending} disabled={!newScope.trim()}>Add</Button>
      </form>

      {/* Nmap import */}
      <details className="group mt-4">
        <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-300 transition-colors list-none flex items-center gap-1.5">
          <ChevronRightIcon className="w-3 h-3 group-open:rotate-90 transition-transform" />
          Import from Nmap XML
        </summary>
        <div className="mt-2 space-y-2">
          <div className="flex gap-2 items-center">
            <input type="file" id="nmap-file" className="hidden" accept=".xml"
              onChange={e => { setNmapFile(e.target.files?.[0] || null); setNmapResult(null) }} />
            <label htmlFor="nmap-file"
              className="cursor-pointer text-xs px-3 py-1.5 bg-slate-800 border border-slate-700 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors">
              {nmapFile ? nmapFile.name : 'Choose Nmap .xml file'}
            </label>
            {nmapFile && (
              <Button size="sm" onClick={() => nmapUpload.mutate()} loading={nmapUpload.isPending}>
                Import
              </Button>
            )}
          </div>
          {nmapResult && (
            <div className="flex items-center gap-2 text-xs text-green-300">
              <CheckCircleIcon className="w-3.5 h-3.5" />
              {nmapResult.imported ?? nmapResult.added ?? 0} hosts imported
              {nmapResult.skipped > 0 && <span className="text-slate-500">· {nmapResult.skipped} skipped</span>}
            </div>
          )}
        </div>
      </details>

      <ConfirmModal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()} title="Remove Scope" message={`Remove "${deleteTarget?.scope}"?`} loading={del.isPending} />
    </>
  )
}

// ── Assets ────────────────────────────────────────────────────────────────────

const INSTANCE_STATUS_COLORS: Record<string, string> = {
  'Vulnerable':      'bg-red-900/40 text-red-300 border-red-800/40',
  'Accepted Risk':   'bg-yellow-900/40 text-yellow-300 border-yellow-800/40',
  'False Positive':  'bg-slate-700 text-slate-400 border-slate-600',
  'Resolved':        'bg-green-900/40 text-green-300 border-green-800/40',
}

function AssetsTab({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [filterStatus, setFilterStatus] = useState('All')
  const [deleteTarget, setDeleteTarget] = useState<any>(null)
  const [editTarget, setEditTarget] = useState<any>(null)
  const [editStatus, setEditStatus] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['project-instances', projectId],
    queryFn: () => standardizedApiClient.getProjectInstances(projectId),
  })
  const instances: any[] = Array.isArray(data) ? data : []

  // Group by vulnerability
  const grouped = useMemo(() => {
    let list = instances
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(i =>
        i.URL?.toLowerCase().includes(q) ||
        i.Parameter?.toLowerCase().includes(q) ||
        i.vulnerability_name?.toLowerCase().includes(q)
      )
    }
    if (filterStatus !== 'All') list = list.filter(i => i.status === filterStatus)

    const map = new Map<string, { vuln: any; items: any[] }>()
    for (const inst of list) {
      const key = inst.vulnerability_id
      if (!map.has(key)) map.set(key, { vuln: inst, items: [] })
      map.get(key)!.items.push(inst)
    }
    return Array.from(map.values())
  }, [instances, search, filterStatus])

  const updateStatus = useMutation({
    mutationFn: ({ inst, newStatus }: { inst: any; newStatus: string }) =>
      standardizedApiClient.updateVulnerabilityInstance(inst.vulnerability_id, inst.id, { status: newStatus }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project-instances', projectId] })
      qc.invalidateQueries({ queryKey: ['instances'] })
      setEditTarget(null)
      toast.success('Status updated')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  const del = useMutation({
    mutationFn: () =>
      standardizedApiClient.deleteVulnerabilityInstance(deleteTarget.vulnerability_id, deleteTarget.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project-instances', projectId] })
      qc.invalidateQueries({ queryKey: ['instances'] })
      qc.invalidateQueries({ queryKey: ['vulns', projectId] })
      setDeleteTarget(null)
      toast.success('Asset removed')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  const totalByStatus = useMemo(() => {
    const counts: Record<string, number> = {}
    instances.forEach(i => { counts[i.status] = (counts[i.status] || 0) + 1 })
    return counts
  }, [instances])

  return (
    <>
      {/* Summary strip */}
      {instances.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-5">
          {Object.entries(totalByStatus).map(([st, count]) => (
            <button key={st} onClick={() => setFilterStatus(filterStatus === st ? 'All' : st)}
              className={`text-xs px-2.5 py-1 rounded-full border font-medium transition-all ${
                INSTANCE_STATUS_COLORS[st] || 'bg-slate-700 text-slate-400 border-slate-600'
              } ${filterStatus === st ? 'ring-2 ring-white/20' : 'opacity-80 hover:opacity-100'}`}>
              {st} · {count}
            </button>
          ))}
          {filterStatus !== 'All' && (
            <button onClick={() => setFilterStatus('All')} className="text-xs px-2.5 py-1 text-slate-500 hover:text-white transition-colors">
              Clear ×
            </button>
          )}
        </div>
      )}

      {/* Search + count */}
      <div className="flex items-center gap-2 mb-4">
        <div className="relative flex-1">
          <MagnifyingGlassIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search URL, parameter or finding…"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500" />
        </div>
        <p className="text-xs text-slate-600 shrink-0">
          {grouped.reduce((n, g) => n + g.items.length, 0)} of {instances.length} asset{instances.length !== 1 ? 's' : ''}
        </p>
      </div>

      {isLoading ? <PageSpinner /> : instances.length === 0 ? (
        <EmptyState
          icon={ShieldExclamationIcon}
          title="No assets yet"
          subtitle="Expand a finding in the Findings tab and add affected URLs or IPs under Affected Assets." />
      ) : grouped.length === 0 ? (
        <EmptyState title="No matches" subtitle="Try a different search or filter." />
      ) : (
        <div className="space-y-4">
          {grouped.map(({ vuln, items }) => (
            <div key={vuln.vulnerability_id} className="bg-slate-800/40 border border-slate-700/50 rounded-xl overflow-hidden">
              {/* Vuln header */}
              <div className="flex items-center gap-3 px-4 py-2.5 border-b border-slate-700/40 bg-slate-800/60">
                {severityBadge(vuln.vulnerability_severity)}
                <p className="text-sm font-medium text-white truncate flex-1">{vuln.vulnerability_name}</p>
                {vuln.cvssscore > 0 && <span className="text-xs text-slate-500 shrink-0">CVSS {vuln.cvssscore}</span>}
                <span className="text-xs text-slate-600 shrink-0">{items.length} asset{items.length !== 1 ? 's' : ''}</span>
              </div>

              {/* Instance rows */}
              <div className="divide-y divide-slate-700/30">
                {items.map((inst: any) => (
                  <div key={inst.id} className="group flex items-center gap-3 px-4 py-2.5 hover:bg-slate-800/40 transition-colors">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-mono text-slate-200 truncate">{inst.URL || '—'}</p>
                      {inst.Parameter && (
                        <p className="text-xs font-mono text-slate-500 mt-0.5 truncate">param: {inst.Parameter}</p>
                      )}
                    </div>

                    {/* Inline status editor or badge */}
                    {editTarget?.id === inst.id ? (
                      <div className="flex items-center gap-1.5 shrink-0">
                        <select value={editStatus} onChange={e => setEditStatus(e.target.value)} autoFocus
                          className="bg-slate-900 border border-slate-600 rounded-lg px-2 py-1 text-xs text-white focus:outline-none focus:border-indigo-500">
                          {Object.keys(INSTANCE_STATUS_COLORS).map(s => <option key={s}>{s}</option>)}
                        </select>
                        <button
                          onClick={() => updateStatus.mutate({ inst, newStatus: editStatus })}
                          disabled={updateStatus.isPending}
                          className="text-xs text-indigo-400 hover:text-indigo-300 disabled:opacity-40 px-1.5">
                          Save
                        </button>
                        <button onClick={() => setEditTarget(null)} className="text-xs text-slate-500 hover:text-white">✕</button>
                      </div>
                    ) : (
                      <button
                        onClick={() => { setEditTarget(inst); setEditStatus(inst.status) }}
                        className={`shrink-0 text-[10px] font-medium px-2 py-0.5 rounded-full border transition-all hover:opacity-100 ${
                          INSTANCE_STATUS_COLORS[inst.status] || 'bg-slate-700 text-slate-400 border-slate-600'
                        }`}>
                        {inst.status}
                      </button>
                    )}

                    <button onClick={() => setDeleteTarget(inst)}
                      className="p-1 text-slate-700 hover:text-red-400 rounded opacity-0 group-hover:opacity-100 transition-all shrink-0">
                      <TrashIcon className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => del.mutate()}
        title="Remove Asset"
        message={`Remove "${deleteTarget?.URL}" from "${deleteTarget?.vulnerability_name}"?`}
        loading={del.isPending} />
    </>
  )
}

// ── Scanner ───────────────────────────────────────────────────────────────────

function ScannerTab({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<any>(null)
  const [dragging, setDragging] = useState(false)

  const { data: scanners } = useQuery({
    queryKey: ['scanners'],
    queryFn: () => standardizedApiClient.getSupportedScanners(),
    staleTime: Infinity,
  })

  const upload = useMutation({
    mutationFn: () => {
      const fd = new FormData()
      fd.append('file', file!)
      return standardizedApiClient.uploadProjectScan(projectId, fd)
    },
    onSuccess: (data) => {
      setResult(data)
      qc.invalidateQueries({ queryKey: ['vulns', projectId] })
      toast.success(`Imported ${data.new_vulnerabilities ?? 0} new findings`)
      setFile(null)
    },
    onError: (e: any) => toast.error(e?.message || 'Upload failed'),
  })

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); setDragging(false)
    const f = e.dataTransfer.files?.[0]
    if (f) { setFile(f); setResult(null) }
  }

  const supported = scanners?.scanners ?? []

  return (
    <div className="space-y-5">
      {/* Drop zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-10 text-center transition-all ${
          dragging ? 'border-indigo-500 bg-indigo-500/5' : 'border-slate-700 hover:border-slate-600'
        }`}
      >
        <CloudArrowUpIcon className={`w-10 h-10 mx-auto mb-3 transition-colors ${dragging ? 'text-indigo-400' : 'text-slate-600'}`} />
        {file ? (
          <div className="space-y-2">
            <p className="text-sm font-medium text-white">{file.name}</p>
            <p className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB · ready to import</p>
            <button onClick={() => { setFile(null); setResult(null) }} className="text-xs text-slate-500 hover:text-red-400 transition-colors">Remove</button>
          </div>
        ) : (
          <>
            <p className="text-sm font-medium text-slate-300 mb-1">Drop a scan file here</p>
            <p className="text-xs text-slate-500 mb-4">or click to browse — .xml .nessus .json .csv .html</p>
            <input type="file" id="scan-file" className="hidden" accept=".xml,.nessus,.json,.csv,.html"
              onChange={e => { setFile(e.target.files?.[0] || null); setResult(null) }} />
            <label htmlFor="scan-file" className="cursor-pointer inline-flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm rounded-lg transition-colors">
              Choose File
            </label>
          </>
        )}
      </div>

      {file && (
        <Button onClick={() => upload.mutate()} loading={upload.isPending} className="w-full">
          <CloudArrowUpIcon className="w-4 h-4" /> Import Scan Results
        </Button>
      )}

      {result && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2">
            <CheckCircleIcon className="w-4 h-4 text-green-400 shrink-0" />
            <p className="text-sm font-semibold text-green-300">Import complete · {result.scanner_type}</p>
          </div>
          <div className="flex gap-4 text-xs text-slate-400 ml-6">
            <span className="text-green-300 font-medium">{result.new_vulnerabilities} new</span>
            <span>{result.duplicates_found} duplicates skipped</span>
            <span>{result.total_findings} total parsed</span>
          </div>
        </div>
      )}

      {supported.length > 0 && (
        <details className="group">
          <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-300 transition-colors list-none flex items-center gap-1">
            <ChevronRightIcon className="w-3 h-3 group-open:rotate-90 transition-transform" />
            {supported.length} supported scanners
          </summary>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {supported.map((s: any) => <Badge key={s.type} variant="default">{s.name || s.type}</Badge>)}
          </div>
        </details>
      )}
    </div>
  )
}

// ── Report ────────────────────────────────────────────────────────────────────

function ReportTab({ projectId, projectName }: { projectId: string; projectName: string }) {
  const [loading, setLoading] = useState(false)
  const [reportType, setReportType] = useState<'Audit' | 'Re-Audit'>('Audit')

  const downloadReport = async (format: string) => {
    setLoading(true)
    try {
      const blob = await standardizedApiClient.generateProjectReport(projectId, { format, report_type: reportType })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${projectName.replace(/\s+/g, '_')}_${reportType}_report.${format}`
      a.click()
      URL.revokeObjectURL(url)
      toast.success('Report downloaded')
    } catch (e: any) {
      toast.error(e?.message || 'Report generation failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-5">
      {/* Prerequisites notice */}
      <div className="bg-slate-800/40 border border-slate-700/50 rounded-xl p-4">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Requirements before generating</p>
        <ul className="space-y-1.5 text-sm text-slate-400">
          {[
            'At least one scope entry (Scope tab)',
            'At least one finding with an affected asset (Findings tab → expand → Affected Assets)',
          ].map(req => (
            <li key={req} className="flex items-start gap-2">
              <InformationCircleIcon className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
              {req}
            </li>
          ))}
        </ul>
      </div>

      {/* Report type toggle */}
      <div>
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Report Type</p>
        <div className="inline-flex bg-slate-800 border border-slate-700 rounded-lg p-0.5 gap-0.5">
          {(['Audit', 'Re-Audit'] as const).map(t => (
            <button key={t} onClick={() => setReportType(t)}
              className={`px-4 py-1.5 text-sm font-medium rounded-md transition-all ${
                reportType === t
                  ? 'bg-indigo-600 text-white shadow'
                  : 'text-slate-400 hover:text-white'
              }`}>
              {t}
            </button>
          ))}
        </div>
        {reportType === 'Re-Audit' && (
          <p className="text-xs text-slate-500 mt-2">Re-Audit reports include retest status and remediation tracking.</p>
        )}
      </div>

      {/* Format buttons */}
      <div>
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Download Format</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {[
            { format: 'pdf', label: 'PDF Report', sub: 'Print-ready formatted document', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
            { format: 'docx', label: 'DOCX Report', sub: 'Editable Word document', color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
          ].map(({ format, label, sub, color, bg }) => (
            <button key={format} onClick={() => downloadReport(format)} disabled={loading}
              className={`group flex items-center gap-3 border rounded-xl p-4 text-left transition-all disabled:opacity-50 hover:scale-[1.01] active:scale-[0.99] ${bg} hover:brightness-125`}>
              <div className={`w-10 h-10 rounded-lg bg-slate-900/50 flex items-center justify-center shrink-0 ${color}`}>
                <DocumentArrowDownIcon className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-white">{label}</p>
                <p className="text-xs text-slate-400 mt-0.5">{sub}</p>
              </div>
              {loading && <div className="ml-auto w-4 h-4 border-2 border-slate-500 border-t-white rounded-full animate-spin shrink-0" />}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Setup screen ──────────────────────────────────────────────────────────────

function SetupWorkspace({ onCreated }: { onCreated: (id: string) => void }) {
  const [form, setForm] = useState({
    name: '', startdate: '', enddate: '', projecttype: '',
  })
  const set = (k: string) => (e: React.ChangeEvent<any>) => setForm(f => ({ ...f, [k]: e.target.value }))

  const { data: ptData } = useQuery({
    queryKey: ['project-types'],
    queryFn: () => standardizedApiClient.getProjectTypes(),
  })
  const pts = Array.isArray(ptData?.results) ? ptData.results : Array.isArray(ptData) ? ptData : []

  const create = useMutation({
    mutationFn: () => {
      const payload: Record<string, any> = { name: form.name }
      if (form.startdate) payload.startdate = form.startdate
      if (form.enddate) payload.enddate = form.enddate
      if (form.projecttype) payload.projecttype = form.projecttype
      return standardizedApiClient.createProject(payload)
    },
    onSuccess: (newProject: any) => {
      toast.success('Workspace created')
      onCreated(String(newProject.id))
    },
    onError: (e: any) => toast.error(e?.message || 'Failed to create workspace'),
  })

  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] p-6">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-indigo-600/15 border border-indigo-500/20 flex items-center justify-center mb-4">
            <WrenchScrewdriverIcon className="w-7 h-7 text-indigo-400" />
          </div>
          <h1 className="text-lg font-semibold text-white">Set up your workspace</h1>
          <p className="text-sm text-slate-500 mt-1 text-center">Create your security assessment project to get started.</p>
        </div>

        <form onSubmit={e => { e.preventDefault(); create.mutate() }} className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <Input label="Project Name *" value={form.name} onChange={set('name')} required placeholder="e.g. ACME Corp Web App Pentest" />
          <div className="grid grid-cols-2 gap-3">
            <Input label="Start Date" type="date" value={form.startdate} onChange={set('startdate')} />
            <Input label="End Date" type="date" value={form.enddate} onChange={set('enddate')} />
          </div>
          {pts.length > 0 && (
            <Select label="Project Type" value={form.projecttype} onChange={set('projecttype')}>
              <option value="">Select type…</option>
              {pts.map((p: any) => <option key={p.id} value={p.name}>{p.name}</option>)}
            </Select>
          )}
          <Button type="submit" loading={create.isPending} disabled={!form.name.trim()} className="w-full">
            Create Project
          </Button>
        </form>
      </div>
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function WorkspacePage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>('vulnerabilities')

  const { data: project, isLoading } = useQuery({
    queryKey: ['workspace', id],
    queryFn: () => standardizedApiClient.getProject(id!),
    enabled: !!id,
  })

  const updateStatus = useMutation({
    mutationFn: (status: string) => standardizedApiClient.updateProject(id!, { status }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['workspace', id] })
      toast.success('Status updated')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed to update status'),
  })

  if (!id) {
    navigate('/projects', { replace: true })
    return null
  }

  if (isLoading) return <PageSpinner />

  if (!project) {
    return <SetupWorkspace onCreated={(newId) => navigate(`/workspace/${newId}`, { replace: true })} />
  }

  return (
    <div className="p-6 space-y-5 max-w-5xl">
      {/* Back link */}
      <button onClick={() => navigate('/projects')}
        className="inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-white transition-colors group">
        <ArrowLeftIcon className="w-3.5 h-3.5 group-hover:-translate-x-0.5 transition-transform" />
        All Projects
      </button>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-bold text-white tracking-tight truncate">{project.name}</h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1.5 text-xs text-slate-500">
            {project.startdate && (
              <span className="flex items-center gap-1">
                <span className="w-1 h-1 rounded-full bg-slate-600" />
                {project.startdate} → {project.enddate || '…'}
              </span>
            )}
            {project.projecttype && (
              <span className="flex items-center gap-1">
                <span className="w-1 h-1 rounded-full bg-slate-600" />
                {project.projecttype}
              </span>
            )}
          </div>
        </div>
        {/* Inline status select (Task 2) */}
        <select
          value={project.status || ''}
          onChange={e => updateStatus.mutate(e.target.value)}
          disabled={updateStatus.isPending}
          className="shrink-0 bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500 disabled:opacity-50 cursor-pointer"
        >
          {PROJECT_STATUSES.map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-800">
        <nav className="-mb-px flex gap-1">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-4 pb-3 text-sm font-medium border-b-2 transition-colors ${
                tab === t.id
                  ? 'border-indigo-500 text-white'
                  : 'border-transparent text-slate-500 hover:text-slate-300 hover:border-slate-600'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      <div>
        {tab === 'vulnerabilities' && <FindingsTab projectId={String(project.id)} />}
        {tab === 'assets'          && <AssetsTab projectId={String(project.id)} />}
        {tab === 'scope'           && <ScopeTab projectId={String(project.id)} />}
        {tab === 'scanner'         && <ScannerTab projectId={String(project.id)} />}
        {tab === 'report'          && <ReportTab projectId={String(project.id)} projectName={project.name} />}
      </div>
    </div>
  )
}
