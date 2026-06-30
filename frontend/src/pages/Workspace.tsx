import { useState, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  PlusIcon, TrashIcon, CloudArrowUpIcon,
  DocumentArrowDownIcon, ShieldExclamationIcon, WrenchScrewdriverIcon,
  ChevronRightIcon, ArrowLeftIcon, CheckCircleIcon,
  InformationCircleIcon, SparklesIcon, ChatBubbleLeftEllipsisIcon,
  ClockIcon, PencilIcon,
} from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/Button'
import { Input, Textarea, Select, SearchInput } from '@/components/ui/Input'
import { Modal, ConfirmModal } from '@/components/ui/Modal'
import { Drawer } from '@/components/ui/Drawer'
import { PageSpinner, EmptyState, InlineSpinner } from '@/components/ui/Spinner'
import { SeverityBadge, StatusBadge, severityColor } from '@/components/ui/Badge'
import { SeverityBar } from '@/components/ui/SeverityBar'
import { SLABadge } from '@/components/ui/SLABadge'
import { BulkBar } from '@/components/ui/BulkBar'
import toast from 'react-hot-toast'

type Tab = 'findings' | 'retests' | 'assets' | 'sla' | 'scanner' | 'report'

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info']
const TABS: { id: Tab; label: string }[] = [
  { id: 'findings',  label: 'Findings' },
  { id: 'retests',   label: 'Retests' },
  { id: 'assets',    label: 'Assets' },
  { id: 'sla',       label: 'SLA' },
  { id: 'scanner',   label: 'Scanner' },
  { id: 'report',    label: 'Report' },
]

const PROJECT_STATUSES = ['In Progress', 'Completed', 'Delay', 'Hold'] as const
const VULN_STATUSES = ['Vulnerable', 'Confirm Fixed', 'Accepted Risk', 'False Positive']
const SEVERITY_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4, Informational: 4, None: 4 }
const INSTANCE_STATUSES = ['Vulnerable', 'Accepted Risk', 'False Positive', 'Resolved']

const inp = 'w-full bg-app-surface border border-border-default rounded-lg px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-500 focus:ring-1 focus:ring-accent-500/30'

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

function SectionLabel({ title }: { title: string }) {
  return (
    <p className="text-[10px] font-semibold text-text-muted uppercase tracking-widest mb-1.5">
      {title}
    </p>
  )
}

// ── VulnForm ──────────────────────────────────────────────────────────────────

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
    risk_acceptance:        !!initial?.risk_acceptance,
    risk_acceptance_reason: initial?.risk_acceptance_reason || '',
    source_file:  initial?.source_file  || '',
    source_line:  initial?.source_line  ?? '',
    sink_file:    initial?.sink_file    || '',
    sink_line:    initial?.sink_line    ?? '',
    tainted_flow: !!initial?.tainted_flow,
    cloud_platform:         initial?.cloud_platform         || '',
    kubernetes_cluster:     initial?.kubernetes_cluster     || '',
    kubernetes_namespace:   initial?.kubernetes_namespace   || '',
    kubernetes_workload:    initial?.kubernetes_workload    || '',
    container_image:        initial?.container_image        || '',
    container_image_digest: initial?.container_image_digest || '',
    package_name:        initial?.package_name        || '',
    package_version:     initial?.package_version     || '',
    package_type:        initial?.package_type        || '',
    installed_version:   initial?.installed_version   || '',
    vulnerable_versions: initial?.vulnerable_versions || '',
    compliance_frameworksText: toCommaSep(initial?.compliance_frameworks),
    nist_800_53_controlsText:  toCommaSep(initial?.nist_800_53_controls),
    masvs_controlsText:        toCommaSep(initial?.masvs_controls),
    disa_stigText:             toCommaSep(initial?.disa_stig),
    mitre_tacticsText:    toCommaSep(initial?.mitre_tactics),
    mitre_techniquesText: toCommaSep(initial?.mitre_techniques),
  })

  const set  = (k: string) => (e: React.ChangeEvent<any>) => setForm(f => ({ ...f, [k]: e.target.value }))
  const setB = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm(f => ({ ...f, [k]: e.target.checked }))

  const handleSave = () => {
    const { cweText, cveText, compliance_frameworksText, nist_800_53_controlsText, masvs_controlsText, disa_stigText, mitre_tacticsText, mitre_techniquesText, ...rest } = form
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

  return (
    <form onSubmit={e => { e.preventDefault(); handleSave() }} className="space-y-4">
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
        <Input label="CVE IDs" placeholder="CVE-2023-1234…" value={form.cveText} onChange={set('cveText')} />
      </div>

      <Textarea label="Description" rows={3} value={form.vulnerabilitydescription} onChange={set('vulnerabilitydescription')} />
      <Textarea label="Proof of Concept" rows={2} value={form.POC} onChange={set('POC')} />
      <Textarea label="Remediation" rows={2} value={form.vulnerabilitysolution} onChange={set('vulnerabilitysolution')} />
      <Textarea label="References / Links" placeholder="https://…" rows={2} value={form.vulnerabilityreferlnk} onChange={set('vulnerabilityreferlnk')} />

      <div className="flex flex-wrap gap-4 pt-1">
        {[
          { key: 'verified',       label: 'Verified' },
          { key: 'false_positive', label: 'False Positive' },
          { key: 'suppressed',     label: 'Suppressed' },
        ].map(({ key, label }) => (
          <label key={key} className="flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox" checked={form[key as keyof typeof form] as boolean} onChange={setB(key)} className="w-3.5 h-3.5 rounded accent-accent-500" />
            <span className="text-sm text-text-secondary">{label}</span>
          </label>
        ))}
      </div>

      <details className="group border border-border-default rounded-lg overflow-hidden">
        <summary className="flex items-center gap-2 px-4 py-3 cursor-pointer bg-app-overlay hover:bg-app-overlay/80 transition-colors list-none">
          <ChevronRightIcon className="w-3.5 h-3.5 text-text-muted group-open:rotate-90 transition-transform shrink-0" />
          <span className="text-sm font-medium text-text-secondary">Technical Details</span>
        </summary>
        <div className="px-4 pb-4 pt-3 space-y-5">
          <div>
            <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Triage</p>
            <div className="space-y-3">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={form.risk_acceptance} onChange={setB('risk_acceptance')} className="w-3.5 h-3.5 rounded accent-accent-500" />
                <span className="text-sm text-text-secondary">Risk Acceptance</span>
              </label>
              {form.risk_acceptance && (
                <div>
                  <label className="block text-xs text-text-secondary mb-1">Risk Acceptance Reason</label>
                  <textarea value={form.risk_acceptance_reason} onChange={set('risk_acceptance_reason')} rows={2} className={inp + ' resize-none'} />
                </div>
              )}
            </div>
          </div>
          <div>
            <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">SAST</p>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-text-secondary mb-1">Source File</label><input type="text" value={form.source_file} onChange={set('source_file')} placeholder="src/auth/login.py" className={inp} /></div>
                <div><label className="block text-xs text-text-secondary mb-1">Source Line</label><input type="number" value={form.source_line} onChange={set('source_line')} className={inp} /></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-text-secondary mb-1">Sink File</label><input type="text" value={form.sink_file} onChange={set('sink_file')} className={inp} /></div>
                <div><label className="block text-xs text-text-secondary mb-1">Sink Line</label><input type="number" value={form.sink_line} onChange={set('sink_line')} className={inp} /></div>
              </div>
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={form.tainted_flow} onChange={setB('tainted_flow')} className="w-3.5 h-3.5 rounded accent-accent-500" />
                <span className="text-sm text-text-secondary">Tainted Flow</span>
              </label>
            </div>
          </div>
          <div>
            <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Container / Kubernetes</p>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-text-secondary mb-1">Cloud Platform</label><input type="text" value={form.cloud_platform} onChange={set('cloud_platform')} placeholder="aws / azure / gcp" className={inp} /></div>
                <div><label className="block text-xs text-text-secondary mb-1">Kubernetes Cluster</label><input type="text" value={form.kubernetes_cluster} onChange={set('kubernetes_cluster')} className={inp} /></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-text-secondary mb-1">Kubernetes Namespace</label><input type="text" value={form.kubernetes_namespace} onChange={set('kubernetes_namespace')} className={inp} /></div>
                <div><label className="block text-xs text-text-secondary mb-1">Kubernetes Workload</label><input type="text" value={form.kubernetes_workload} onChange={set('kubernetes_workload')} className={inp} /></div>
              </div>
              <div><label className="block text-xs text-text-secondary mb-1">Container Image</label><input type="text" value={form.container_image} onChange={set('container_image')} className={inp} /></div>
              <div><label className="block text-xs text-text-secondary mb-1">Container Image Digest</label><input type="text" value={form.container_image_digest} onChange={set('container_image_digest')} className={inp} /></div>
            </div>
          </div>
          <div>
            <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Dependency / SCA</p>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-text-secondary mb-1">Package Name</label><input type="text" value={form.package_name} onChange={set('package_name')} className={inp} /></div>
                <div><label className="block text-xs text-text-secondary mb-1">Package Version</label><input type="text" value={form.package_version} onChange={set('package_version')} className={inp} /></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-text-secondary mb-1">Package Type</label><input type="text" value={form.package_type} onChange={set('package_type')} placeholder="npm / pip / maven" className={inp} /></div>
                <div><label className="block text-xs text-text-secondary mb-1">Installed Version</label><input type="text" value={form.installed_version} onChange={set('installed_version')} className={inp} /></div>
              </div>
              <div><label className="block text-xs text-text-secondary mb-1">Vulnerable Versions</label><input type="text" value={form.vulnerable_versions} onChange={set('vulnerable_versions')} placeholder="comma-separated ranges" className={inp} /></div>
            </div>
          </div>
          <div>
            <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Compliance</p>
            <div className="space-y-3">
              <div><label className="block text-xs text-text-secondary mb-1">Compliance Frameworks</label><input type="text" value={form.compliance_frameworksText} onChange={set('compliance_frameworksText')} placeholder="PCI DSS, ISO 27001" className={inp} /></div>
              <div><label className="block text-xs text-text-secondary mb-1">NIST 800-53 Controls</label><input type="text" value={form.nist_800_53_controlsText} onChange={set('nist_800_53_controlsText')} placeholder="AC-2, AC-3" className={inp} /></div>
              <div><label className="block text-xs text-text-secondary mb-1">MASVS Controls</label><input type="text" value={form.masvs_controlsText} onChange={set('masvs_controlsText')} placeholder="MASVS-STORAGE-1" className={inp} /></div>
              <div><label className="block text-xs text-text-secondary mb-1">DISA STIG</label><input type="text" value={form.disa_stigText} onChange={set('disa_stigText')} placeholder="V-123456" className={inp} /></div>
            </div>
          </div>
          <div>
            <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">MITRE ATT&amp;CK</p>
            <div className="space-y-3">
              <div><label className="block text-xs text-text-secondary mb-1">Tactics</label><input type="text" value={form.mitre_tacticsText} onChange={set('mitre_tacticsText')} placeholder="TA0001, TA0002" className={inp} /></div>
              <div><label className="block text-xs text-text-secondary mb-1">Techniques</label><input type="text" value={form.mitre_techniquesText} onChange={set('mitre_techniquesText')} placeholder="T1190, T1059" className={inp} /></div>
            </div>
          </div>
        </div>
      </details>

      <div className="flex justify-end gap-2 pt-1">
        <Button variant="ghost" size="sm" type="button" onClick={onCancel} disabled={loading}>Cancel</Button>
        <Button size="sm" type="submit" loading={loading}>Save</Button>
      </div>
    </form>
  )
}

// ── InstancesSection ──────────────────────────────────────────────────────────

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

  const instStatusColor: Record<string, string> = {
    Vulnerable:      'bg-critical/15 text-critical border border-critical/30',
    Resolved:        'bg-low/15 text-low border border-low/30',
    'Accepted Risk': 'bg-medium/15 text-medium border border-medium/30',
    'False Positive': 'bg-border-default/50 text-text-muted border border-border-default',
  }

  return (
    <div className="mt-4 pt-4 border-t border-border-subtle">
      <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">Affected Assets</p>
      {isLoading ? <p className="text-xs text-text-muted">Loading…</p> : instances.length > 0 && (
        <div className="space-y-1 mb-3">
          {instances.map((inst: any) => (
            <div key={inst.id} className="flex items-center gap-2 bg-app-bg/60 rounded-lg px-3 py-2 text-xs">
              <span className="font-mono text-text-secondary flex-1 truncate">{inst.URL || '—'}</span>
              {inst.Parameter && <span className="text-text-muted font-mono truncate max-w-[120px]">{inst.Parameter}</span>}
              <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-medium ${instStatusColor[inst.status] || 'bg-app-overlay text-text-muted border border-border-default'}`}>{inst.status}</span>
              <button onClick={() => setDeleteTarget(inst)} className="text-text-muted hover:text-critical shrink-0 transition-colors">
                <TrashIcon className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      )}
      <form onSubmit={e => { e.preventDefault(); if (url.trim()) add.mutate() }} className="flex gap-2">
        <input value={url} onChange={e => setUrl(e.target.value)} placeholder="URL / IP…" className={inp.replace('py-2', 'py-1.5').replace('text-sm', 'text-xs') + ' flex-1 min-w-0'} />
        <input value={param} onChange={e => setParam(e.target.value)} placeholder="Parameter (opt.)" className={inp.replace('py-2', 'py-1.5').replace('text-sm', 'text-xs') + ' w-32'} />
        <select value={instStatus} onChange={e => setInstStatus(e.target.value)} className={inp.replace('py-2', 'py-1.5').replace('text-sm', 'text-xs')}>
          {INSTANCE_STATUSES.map(s => <option key={s}>{s}</option>)}
        </select>
        <button type="submit" disabled={!url.trim() || add.isPending} className="shrink-0 px-3 py-1.5 bg-accent-500 hover:bg-accent-600 disabled:opacity-40 text-white text-xs rounded-lg transition-colors">
          Add
        </button>
      </form>
      <ConfirmModal isOpen={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()} title="Remove Asset" message={`Remove "${deleteTarget?.URL}"?`} loading={del.isPending} />
    </div>
  )
}

// ── CommentsSection (used in FindingDrawer) ───────────────────────────────────

function CommentsSection({ vulnId }: { vulnId: string }) {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isStaff = user?.is_staff || user?.is_superuser
  const [body, setBody] = useState('')
  const [isInternal, setIsInternal] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [editBody, setEditBody] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<any>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['comments', vulnId],
    queryFn: () => standardizedApiClient.getComments(vulnId),
  })
  const comments = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []

  const create = useMutation({
    mutationFn: () => standardizedApiClient.createComment(vulnId, { body, is_internal: isInternal }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['comments', vulnId] }); setBody(''); setIsInternal(false); toast.success('Comment posted') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const updateComment = useMutation({
    mutationFn: () => standardizedApiClient.updateComment(vulnId, editId!, { body: editBody }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['comments', vulnId] }); setEditId(null); toast.success('Updated') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteComment(vulnId, deleteTarget.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['comments', vulnId] }); setDeleteTarget(null); toast.success('Deleted') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  const fmt = (dt: string) => {
    try { return new Date(dt).toLocaleString() } catch { return dt }
  }

  return (
    <div className="space-y-3">
      {isLoading ? <InlineSpinner /> : comments.length === 0 ? (
        <p className="text-xs text-text-muted py-2">No comments yet.</p>
      ) : (
        <div className="space-y-3">
          {comments.map((c: any) => (
            <div key={c.id} className={`rounded-lg p-3 ${c.is_internal ? 'bg-medium/5 border border-medium/20' : 'bg-app-overlay border border-border-subtle'}`}>
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-text-primary">{c.author_email || c.author || 'Unknown'}</span>
                  {c.is_internal && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-medium/15 text-medium border border-medium/30 font-medium">Internal</span>
                  )}
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-text-muted">{fmt(c.created_at || c.created)}</span>
                  {(c.author === user?.id || c.author_email === user?.email) && (
                    <>
                      <button onClick={() => { setEditId(c.id); setEditBody(c.body) }} className="text-text-muted hover:text-accent-400 transition-colors p-0.5">
                        <PencilIcon className="w-3 h-3" />
                      </button>
                      <button onClick={() => setDeleteTarget(c)} className="text-text-muted hover:text-critical transition-colors p-0.5">
                        <TrashIcon className="w-3 h-3" />
                      </button>
                    </>
                  )}
                </div>
              </div>
              {editId === c.id ? (
                <div className="space-y-2">
                  <textarea value={editBody} onChange={e => setEditBody(e.target.value)} rows={2} className={inp + ' resize-none text-xs'} />
                  <div className="flex gap-2">
                    <button onClick={() => updateComment.mutate()} disabled={updateComment.isPending || !editBody.trim()} className="text-xs text-accent-400 hover:text-text-primary disabled:opacity-40">Save</button>
                    <button onClick={() => setEditId(null)} className="text-xs text-text-muted hover:text-text-secondary">Cancel</button>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-text-secondary whitespace-pre-wrap">{c.body}</p>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="pt-2 border-t border-border-subtle space-y-2">
        <textarea value={body} onChange={e => setBody(e.target.value)} rows={2} placeholder="Write a comment…" className={inp + ' resize-none'} />
        <div className="flex items-center justify-between gap-2">
          {isStaff && (
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input type="checkbox" checked={isInternal} onChange={e => setIsInternal(e.target.checked)} className="w-3.5 h-3.5 rounded accent-accent-500" />
              <span className="text-xs text-text-muted">Mark as internal</span>
            </label>
          )}
          <Button size="sm" onClick={() => create.mutate()} disabled={!body.trim()} loading={create.isPending} className="ml-auto">
            Post
          </Button>
        </div>
      </div>

      <ConfirmModal isOpen={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()} title="Delete Comment" message="Delete this comment?" loading={del.isPending} />
    </div>
  )
}

// ── RetestsSection (used in FindingDrawer) ────────────────────────────────────

const RETEST_RESULTS = ['Passed', 'Failed', 'Partial']
const retestColor: Record<string, string> = {
  Passed:  'bg-low/15 text-low border border-low/30',
  Failed:  'bg-critical/15 text-critical border border-critical/30',
  Partial: 'bg-medium/15 text-medium border border-medium/30',
}

function RetestsSection({ vulnId }: { vulnId: string }) {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ date: '', result: 'Passed', notes: '' })
  const [deleteTarget, setDeleteTarget] = useState<any>(null)
  const set = (k: string) => (e: React.ChangeEvent<any>) => setForm(f => ({ ...f, [k]: e.target.value }))

  const { data, isLoading } = useQuery({
    queryKey: ['retests', vulnId],
    queryFn: () => standardizedApiClient.getRetests(vulnId),
  })
  const retests = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []

  const create = useMutation({
    mutationFn: () => standardizedApiClient.createRetest(vulnId, form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['retests', vulnId] })
      setForm({ date: '', result: 'Passed', notes: '' })
      setShowForm(false)
      toast.success('Retest added')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteRetest(vulnId, deleteTarget.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['retests', vulnId] }); setDeleteTarget(null); toast.success('Removed') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  const fmt = (dt: string) => { try { return new Date(dt).toLocaleDateString() } catch { return dt } }

  return (
    <div className="space-y-3">
      {isLoading ? <InlineSpinner /> : retests.length === 0 ? (
        <p className="text-xs text-text-muted py-2">No retests recorded.</p>
      ) : (
        <div className="space-y-2">
          {retests.map((rt: any) => (
            <div key={rt.id} className="flex items-start gap-3 bg-app-overlay border border-border-subtle rounded-lg px-3 py-2.5">
              <div className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ backgroundColor: rt.result === 'Passed' ? '#22c55e' : rt.result === 'Failed' ? '#ef4444' : '#eab308' }} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${retestColor[rt.result] || 'bg-app-overlay text-text-muted border-border-default'}`}>
                    {rt.result}
                  </span>
                  <span className="text-xs text-text-muted">{fmt(rt.date || rt.created)}</span>
                  {rt.tester && <span className="text-xs text-text-muted">· {rt.tester}</span>}
                </div>
                {rt.notes && <p className="text-xs text-text-secondary mt-0.5">{rt.notes}</p>}
              </div>
              <button onClick={() => setDeleteTarget(rt)} className="text-text-muted hover:text-critical transition-colors shrink-0">
                <TrashIcon className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}

      {showForm ? (
        <div className="border border-border-default rounded-lg p-3 space-y-3 bg-app-overlay">
          <div className="grid grid-cols-2 gap-3">
            <div><label className="block text-xs text-text-secondary mb-1">Date</label><input type="date" value={form.date} onChange={set('date')} className={inp} /></div>
            <div>
              <label className="block text-xs text-text-secondary mb-1">Result</label>
              <select value={form.result} onChange={set('result')} className={inp}>
                {RETEST_RESULTS.map(r => <option key={r}>{r}</option>)}
              </select>
            </div>
          </div>
          <div><label className="block text-xs text-text-secondary mb-1">Notes</label><textarea value={form.notes} onChange={set('notes')} rows={2} className={inp + ' resize-none'} /></div>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => create.mutate()} loading={create.isPending} disabled={!form.date}>Save Retest</Button>
            <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
          </div>
        </div>
      ) : (
        <Button size="sm" variant="outline" icon={<PlusIcon className="w-4 h-4" />} onClick={() => setShowForm(true)}>
          Add Retest
        </Button>
      )}

      <ConfirmModal isOpen={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()} title="Remove Retest" message="Remove this retest record?" loading={del.isPending} />
    </div>
  )
}

// ── FindingDrawer ─────────────────────────────────────────────────────────────

function FindingDrawer({ vuln, projectId, onClose, onEdit }: { vuln: any; projectId: string; onClose: () => void; onEdit: () => void }) {
  const qc = useQueryClient()
  const cweList = Array.isArray(vuln.cwe_list) ? vuln.cwe_list : (Array.isArray(vuln.cwe) ? vuln.cwe : vuln.cwe ? [vuln.cwe] : [])
  const cveList = Array.isArray(vuln.cve_list) ? vuln.cve_list : (Array.isArray(vuln.cve) ? vuln.cve : vuln.cve ? [vuln.cve] : [])
  const hasCve = cveList.length > 0
  const isEnriched = vuln.cve_enrichment_status === 'enriched'

  const enrich = useMutation({
    mutationFn: () => standardizedApiClient.enrichVulnerability(String(vuln.id)),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['vulns', projectId] }); toast.success('CVE enrichment queued') },
    onError: (e: any) => toast.error(e?.message || 'Enrichment failed'),
  })

  const extDetails = ([
    ['Risk Acceptance',        vuln.risk_acceptance ? 'Yes' : null],
    ['Risk Acceptance Reason', vuln.risk_acceptance_reason || null],
    ['Source File',            vuln.source_file || null],
    ['Source Line',            vuln.source_line != null && vuln.source_line !== '' ? String(vuln.source_line) : null],
    ['Sink File',              vuln.sink_file || null],
    ['Sink Line',              vuln.sink_line != null && vuln.sink_line !== '' ? String(vuln.sink_line) : null],
    ['Tainted Flow',           vuln.tainted_flow ? 'Yes' : null],
    ['Cloud Platform',         vuln.cloud_platform || null],
    ['Kubernetes Cluster',     vuln.kubernetes_cluster || null],
    ['Kubernetes Namespace',   vuln.kubernetes_namespace || null],
    ['Kubernetes Workload',    vuln.kubernetes_workload || null],
    ['Container Image',        vuln.container_image || null],
    ['Package Name',           vuln.package_name || null],
    ['Package Version',        vuln.package_version || null],
    ['Compliance Frameworks',  vuln.compliance_frameworks?.length ? toCommaSep(vuln.compliance_frameworks) : null],
    ['NIST 800-53 Controls',   vuln.nist_800_53_controls?.length ? toCommaSep(vuln.nist_800_53_controls) : null],
    ['MITRE Tactics',          vuln.mitre_tactics?.length ? toCommaSep(vuln.mitre_tactics) : null],
    ['MITRE Techniques',       vuln.mitre_techniques?.length ? toCommaSep(vuln.mitre_techniques) : null],
  ] as [string, string | null][]).filter(([, v]) => v != null) as [string, string][]

  return (
    <Drawer isOpen={!!vuln} onClose={onClose} title={vuln.vulnerabilityname} subtitle={`${vuln.vulnerabilityseverity} · ${vuln.status}`} width="xl">
      <div className="space-y-6">
        {/* Header badges + edit */}
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={vuln.vulnerabilityseverity} />
          <StatusBadge status={vuln.status} />
          {vuln.cvssscore > 0 && <span className="text-xs text-text-muted">CVSS {vuln.cvssscore}</span>}
          {vuln.verified && <span className="text-[9px] px-1.5 py-0.5 rounded bg-low/15 text-low border border-low/30 font-medium">Verified</span>}
          {vuln.false_positive && <span className="text-[9px] px-1.5 py-0.5 rounded bg-medium/15 text-medium border border-medium/30 font-medium">FP</span>}
          {vuln.sla_status && <SLABadge sla_status={vuln.sla_status} days_remaining={vuln.days_remaining} />}
          <Button size="sm" variant="outline" icon={<PencilIcon className="w-3.5 h-3.5" />} onClick={onEdit} className="ml-auto">
            Edit
          </Button>
        </div>

        {/* IDs */}
        {(cweList.length > 0 || cveList.length > 0) && (
          <div className="flex flex-wrap gap-4">
            {cweList.length > 0 && (
              <div>
                <SectionLabel title="CWE" />
                <div className="flex flex-wrap gap-1">
                  {cweList.map((id: string) => <span key={id} className="text-[10px] font-mono px-2 py-0.5 border rounded bg-app-overlay border-border-default text-text-secondary">{id}</span>)}
                </div>
              </div>
            )}
            {cveList.length > 0 && (
              <div>
                <SectionLabel title="CVE" />
                <div className="flex flex-wrap gap-1">
                  {cveList.map((id: string) => <span key={id} className="text-[10px] font-mono px-2 py-0.5 border rounded bg-high/10 border-high/30 text-high">{id}</span>)}
                </div>
              </div>
            )}
          </div>
        )}

        {/* CVE enrichment */}
        {hasCve && (
          isEnriched ? (
            <div className="bg-info/5 border border-info/20 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 mb-2">
                <SparklesIcon className="w-4 h-4 text-info" />
                <p className="text-xs font-semibold text-info uppercase tracking-wider">CVE Enrichment</p>
              </div>
              {vuln.epss_score != null && (
                <div className="flex items-center gap-4">
                  <div><p className="text-[10px] text-text-muted uppercase tracking-wider">EPSS Score</p><p className="text-sm font-semibold text-text-primary">{(vuln.epss_score * 100).toFixed(2)}%</p></div>
                  {vuln.epss_percentile != null && <div><p className="text-[10px] text-text-muted uppercase tracking-wider">Percentile</p><p className="text-sm font-semibold text-text-primary">{vuln.epss_percentile}th</p></div>}
                </div>
              )}
              {vuln.nvd_description && <p className="text-xs text-text-secondary leading-relaxed">{vuln.nvd_description}</p>}
            </div>
          ) : (
            <div className="flex items-center justify-between gap-3 bg-app-overlay border border-border-default rounded-xl px-4 py-3">
              <div className="flex items-center gap-2">
                <SparklesIcon className="w-4 h-4 text-accent-400" />
                <p className="text-sm text-text-secondary">Enrich with EPSS score and NVD description.</p>
              </div>
              <Button size="sm" variant="outline" icon={<SparklesIcon className="w-3.5 h-3.5" />} onClick={() => enrich.mutate()} loading={enrich.isPending}>
                Enrich CVE
              </Button>
            </div>
          )
        )}

        {/* Description */}
        {vuln.vulnerabilitydescription && (
          <div>
            <SectionLabel title="Description" />
            <p className="text-sm text-text-secondary whitespace-pre-wrap leading-relaxed">{vuln.vulnerabilitydescription}</p>
          </div>
        )}

        {/* PoC */}
        {vuln.POC?.trim() && (
          <div>
            <SectionLabel title="Proof of Concept" />
            <pre className="text-xs text-text-secondary bg-app-bg/60 rounded-lg px-3 py-2.5 overflow-x-auto whitespace-pre-wrap leading-relaxed font-mono">{vuln.POC}</pre>
          </div>
        )}

        {/* Remediation */}
        {vuln.vulnerabilitysolution && (
          <div>
            <SectionLabel title="Remediation" />
            <p className="text-sm text-text-secondary whitespace-pre-wrap leading-relaxed">{vuln.vulnerabilitysolution}</p>
          </div>
        )}

        {/* References */}
        {vuln.vulnerabilityreferlnk?.trim() && (
          <div>
            <SectionLabel title="References" />
            <div className="space-y-0.5">
              {vuln.vulnerabilityreferlnk.split(/\n+/).filter(Boolean).map((line: string, i: number) =>
                /^https?:\/\//.test(line.trim()) ? (
                  <a key={i} href={line.trim()} target="_blank" rel="noopener noreferrer" className="block text-xs text-accent-400 hover:text-text-primary underline underline-offset-2 truncate transition-colors">{line.trim()}</a>
                ) : (
                  <p key={i} className="text-xs text-text-secondary">{line.trim()}</p>
                )
              )}
            </div>
          </div>
        )}

        {/* CVSS vector */}
        {vuln.cvssvector?.trim() && (
          <div>
            <SectionLabel title="CVSS Vector" />
            <p className="text-xs font-mono text-text-secondary bg-app-bg/60 px-3 py-1.5 rounded-lg">{vuln.cvssvector}</p>
          </div>
        )}

        {/* Technical details */}
        {extDetails.length > 0 && (
          <div>
            <SectionLabel title="Technical Details" />
            <div className="grid grid-cols-2 gap-x-6 gap-y-2">
              {extDetails.map(([label, value]) => (
                <div key={label}>
                  <p className="text-[10px] font-semibold text-text-muted uppercase tracking-wider">{label}</p>
                  <p className="text-xs text-text-primary mt-0.5 break-words">{value}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Affected assets */}
        <InstancesSection vulnId={vuln.id} />

        {/* Retests */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <ClockIcon className="w-4 h-4 text-text-muted" />
            <p className="text-sm font-semibold text-text-primary">Retests</p>
          </div>
          <RetestsSection vulnId={String(vuln.id)} />
        </div>

        {/* Comments */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <ChatBubbleLeftEllipsisIcon className="w-4 h-4 text-text-muted" />
            <p className="text-sm font-semibold text-text-primary">Comments</p>
          </div>
          <CommentsSection vulnId={String(vuln.id)} />
        </div>
      </div>
    </Drawer>
  )
}

// ── FindingsTab ───────────────────────────────────────────────────────────────

function FindingsTab({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editTarget, setEditTarget] = useState<any>(null)
  const [deleteTarget, setDeleteTarget] = useState<any>(null)
  const [drawerVuln, setDrawerVuln] = useState<any>(null)
  const [search, setSearch] = useState('')
  const [filterSev, setFilterSev] = useState('All')
  const [filterStatus, setFilterStatus] = useState('All')
  const [bulkMode, setBulkMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [bulkStatusModal, setBulkStatusModal] = useState(false)
  const [bulkSevModal, setBulkSevModal] = useState(false)
  const [bulkNewStatus, setBulkNewStatus] = useState(VULN_STATUSES[0])
  const [bulkNewSev, setBulkNewSev] = useState(SEVERITIES[0])
  const [bulkDeleteModal, setBulkDeleteModal] = useState(false)

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
    if (filterStatus !== 'All') list = list.filter((v: any) => v.status === filterStatus)
    list.sort((a: any, b: any) => (SEVERITY_ORDER[a.vulnerabilityseverity] ?? 5) - (SEVERITY_ORDER[b.vulnerabilityseverity] ?? 5))
    return list
  }, [vulns, search, filterSev, filterStatus])

  const create = useMutation({
    mutationFn: (d: any) => standardizedApiClient.createVulnerability(d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['vulns', projectId] }); setShowCreate(false); toast.success('Finding added') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const update = useMutation({
    mutationFn: (d: any) => standardizedApiClient.updateVulnerability(editTarget.id, d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vulns', projectId] })
      setEditTarget(null)
      if (drawerVuln?.id === editTarget?.id) setDrawerVuln(null)
      toast.success('Updated')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteVulnerability(deleteTarget.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vulns', projectId] })
      if (drawerVuln?.id === deleteTarget?.id) setDrawerVuln(null)
      setDeleteTarget(null)
      toast.success('Deleted')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  const bulkUpdate = useMutation({
    mutationFn: async (payload: Record<string, any>) => {
      await Promise.all([...selectedIds].map(id => standardizedApiClient.updateVulnerability(id, payload)))
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vulns', projectId] })
      setSelectedIds(new Set())
      setBulkStatusModal(false)
      setBulkSevModal(false)
      toast.success(`Updated ${selectedIds.size} findings`)
    },
    onError: (e: any) => toast.error(e?.message || 'Bulk update failed'),
  })
  const bulkDelete = useMutation({
    mutationFn: async () => {
      await Promise.all([...selectedIds].map(id => standardizedApiClient.deleteVulnerability(id)))
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vulns', projectId] })
      setSelectedIds(new Set())
      setBulkDeleteModal(false)
      toast.success('Findings deleted')
    },
    onError: (e: any) => toast.error(e?.message || 'Bulk delete failed'),
  })

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }
  const selectAll = () => setSelectedIds(new Set(filtered.map((v: any) => v.id)))
  const clearSelection = () => setSelectedIds(new Set())

  const sevCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    vulns.forEach((v: any) => { counts[v.vulnerabilityseverity] = (counts[v.vulnerabilityseverity] || 0) + 1 })
    return counts
  }, [vulns])

  return (
    <>
      {stats && vulns.length > 0 && (
        <div className="mb-5">
          <SeverityBar
            critical={stats.severity_counts?.Critical ?? sevCounts['Critical'] ?? 0}
            high={stats.severity_counts?.High ?? sevCounts['High'] ?? 0}
            medium={stats.severity_counts?.Medium ?? sevCounts['Medium'] ?? 0}
            low={stats.severity_counts?.Low ?? sevCounts['Low'] ?? 0}
            info={stats.severity_counts?.Info ?? sevCounts['Info'] ?? 0}
          />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 mb-4">
        <SearchInput value={search} onChange={setSearch} placeholder="Search findings…" className="flex-1 min-w-[180px]" />
        <select value={filterSev} onChange={e => setFilterSev(e.target.value)} className={inp.replace('py-2', 'py-1.5').replace('text-sm', 'text-xs')}>
          <option value="All">All Severities</option>
          {SEVERITIES.map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} className={inp.replace('py-2', 'py-1.5').replace('text-sm', 'text-xs')}>
          <option value="All">All Statuses</option>
          {VULN_STATUSES.map(s => <option key={s}>{s}</option>)}
        </select>
        <Button size="sm" variant={bulkMode ? 'outline' : 'ghost'} onClick={() => { setBulkMode(m => !m); clearSelection() }}>
          {bulkMode ? 'Done' : 'Bulk'}
        </Button>
        <Button size="sm" icon={<PlusIcon className="w-4 h-4" />} onClick={() => setShowCreate(true)} className="ml-auto">
          Add Finding
        </Button>
      </div>

      {isLoading ? (
        <PageSpinner />
      ) : vulns.length === 0 ? (
        <EmptyState icon={ShieldExclamationIcon} title="No findings yet" description="Add manually or import a scan file from the Scanner tab." />
      ) : filtered.length === 0 ? (
        <EmptyState title="No matching findings" description="Try a different search or filter." />
      ) : (
        <div className="bg-app-surface border border-border-subtle rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-app-raised border-b border-border-subtle">
                {bulkMode && (
                  <th className="px-4 py-3 w-8">
                    <input type="checkbox" checked={selectedIds.size === filtered.length && filtered.length > 0} onChange={e => e.target.checked ? selectAll() : clearSelection()} className="w-3.5 h-3.5 rounded accent-accent-500" />
                  </th>
                )}
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Finding</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider hidden md:table-cell">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider hidden lg:table-cell">CVE</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider hidden lg:table-cell">SLA</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-text-muted uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {filtered.map((v: any) => (
                <tr
                  key={v.id}
                  onClick={() => !bulkMode && setDrawerVuln(v)}
                  className={`hover:bg-app-overlay/50 transition-colors ${!bulkMode ? 'cursor-pointer' : ''} ${selectedIds.has(v.id) ? 'bg-accent-500/5' : ''}`}
                >
                  {bulkMode && (
                    <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                      <input type="checkbox" checked={selectedIds.has(v.id)} onChange={() => toggleSelect(v.id)} className="w-3.5 h-3.5 rounded accent-accent-500" />
                    </td>
                  )}
                  <td className="px-4 py-3 shrink-0">
                    <SeverityBadge severity={v.vulnerabilityseverity} />
                  </td>
                  <td className="px-4 py-3 min-w-0">
                    <p className="text-sm font-medium text-text-primary truncate max-w-xs">{v.vulnerabilityname}</p>
                    {v.cvssscore > 0 && <p className="text-xs text-text-muted mt-0.5">CVSS {v.cvssscore}</p>}
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <StatusBadge status={v.status} />
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell">
                    {v.cve?.length > 0 || (v.cve && typeof v.cve === 'string') ? (
                      <span className="text-xs font-mono text-text-secondary truncate block max-w-[100px]">
                        {Array.isArray(v.cve) ? v.cve[0] : v.cve}
                      </span>
                    ) : <span className="text-xs text-text-muted">—</span>}
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell">
                    {v.sla_status ? <SLABadge sla_status={v.sla_status} days_remaining={v.days_remaining} /> : <span className="text-xs text-text-muted">—</span>}
                  </td>
                  <td className="px-4 py-3 text-right" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1">
                      <button onClick={() => setEditTarget(v)} className="p-1 text-text-muted hover:text-accent-400 rounded transition-colors">
                        <PencilIcon className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => setDeleteTarget(v)} className="p-1 text-text-muted hover:text-critical rounded transition-colors">
                        <TrashIcon className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {drawerVuln && (
        <FindingDrawer
          vuln={drawerVuln}
          projectId={projectId}
          onClose={() => setDrawerVuln(null)}
          onEdit={() => { setEditTarget(drawerVuln); setDrawerVuln(null) }}
        />
      )}

      {bulkMode && selectedIds.size > 0 && (
        <BulkBar
          selectedCount={selectedIds.size}
          onClear={clearSelection}
          actions={[
            { label: 'Change Status', onClick: () => setBulkStatusModal(true) },
            { label: 'Change Severity', onClick: () => setBulkSevModal(true) },
            { label: 'Delete', danger: true, onClick: () => setBulkDeleteModal(true), icon: <TrashIcon className="w-4 h-4" /> },
          ]}
        />
      )}

      <Modal isOpen={showCreate} onClose={() => setShowCreate(false)} title="Add Finding" size="xl">
        <VulnForm projectId={projectId} onSave={d => create.mutate(d)} onCancel={() => setShowCreate(false)} loading={create.isPending} />
      </Modal>
      <Modal isOpen={!!editTarget} onClose={() => setEditTarget(null)} title="Edit Finding" size="xl">
        {editTarget && <VulnForm initial={editTarget} projectId={projectId} onSave={d => update.mutate(d)} onCancel={() => setEditTarget(null)} loading={update.isPending} />}
      </Modal>
      <ConfirmModal isOpen={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()} title="Delete Finding" message={`Delete "${deleteTarget?.vulnerabilityname}"?`} loading={del.isPending} />

      <Modal isOpen={bulkStatusModal} onClose={() => setBulkStatusModal(false)} title="Change Status" size="sm">
        <div className="space-y-4">
          <Select label="New Status" value={bulkNewStatus} onChange={e => setBulkNewStatus(e.target.value)}>
            {VULN_STATUSES.map(s => <option key={s}>{s}</option>)}
          </Select>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setBulkStatusModal(false)}>Cancel</Button>
            <Button size="sm" loading={bulkUpdate.isPending} onClick={() => bulkUpdate.mutate({ status: bulkNewStatus })}>
              Apply to {selectedIds.size} findings
            </Button>
          </div>
        </div>
      </Modal>

      <Modal isOpen={bulkSevModal} onClose={() => setBulkSevModal(false)} title="Change Severity" size="sm">
        <div className="space-y-4">
          <Select label="New Severity" value={bulkNewSev} onChange={e => setBulkNewSev(e.target.value)}>
            {SEVERITIES.map(s => <option key={s}>{s}</option>)}
          </Select>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setBulkSevModal(false)}>Cancel</Button>
            <Button size="sm" loading={bulkUpdate.isPending} onClick={() => bulkUpdate.mutate({ vulnerabilityseverity: bulkNewSev })}>
              Apply to {selectedIds.size} findings
            </Button>
          </div>
        </div>
      </Modal>

      <ConfirmModal isOpen={bulkDeleteModal} onClose={() => setBulkDeleteModal(false)} onConfirm={() => bulkDelete.mutate()} title="Delete Findings" message={`Delete ${selectedIds.size} selected findings? This cannot be undone.`} loading={bulkDelete.isPending} />
    </>
  )
}

// ── RetestsTab ────────────────────────────────────────────────────────────────

function VulnRetestCard({ vuln }: { vuln: any }) {
  const { data } = useQuery({
    queryKey: ['retests', String(vuln.id)],
    queryFn: () => standardizedApiClient.getRetests(String(vuln.id)),
    staleTime: 30_000,
  })
  const retests = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []
  if (retests.length === 0) return null

  return (
    <div className="bg-app-surface border border-border-subtle rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-border-subtle bg-app-raised">
        <SeverityBadge severity={vuln.vulnerabilityseverity} />
        <p className="text-sm font-medium text-text-primary truncate flex-1">{vuln.vulnerabilityname}</p>
        <span className="text-xs text-text-muted shrink-0">{retests.length} retest{retests.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="divide-y divide-border-subtle">
        {retests.map((rt: any) => (
          <div key={rt.id} className="flex items-center gap-3 px-4 py-2.5">
            <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${retestColor[rt.result] || 'bg-app-overlay text-text-muted border-border-default'}`}>{rt.result}</span>
            <span className="text-xs text-text-muted">{rt.date ? new Date(rt.date).toLocaleDateString() : '—'}</span>
            {rt.tester && <span className="text-xs text-text-muted">· {rt.tester}</span>}
            {rt.notes && <span className="text-xs text-text-secondary truncate">{rt.notes}</span>}
          </div>
        ))}
      </div>
    </div>
  )
}

function RetestsTab({ projectId }: { projectId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['vulns', projectId],
    queryFn: () => standardizedApiClient.getProjectVulnerabilities(projectId, { page_size: 500 }),
  })
  const vulns = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []

  if (isLoading) return <PageSpinner />
  if (vulns.length === 0) return <EmptyState icon={ClockIcon} title="No findings to retest" description="Add findings first, then record retests from within each finding." />

  return (
    <div className="space-y-3">
      <p className="text-xs text-text-muted">Retest records grouped by finding. Open a finding from the Findings tab to add retests.</p>
      {vulns.map((v: any) => <VulnRetestCard key={v.id} vuln={v} />)}
    </div>
  )
}

// ── AssetsTab ─────────────────────────────────────────────────────────────────

const INSTANCE_STATUS_COLORS: Record<string, string> = {
  'Vulnerable':      'bg-critical/15 text-critical border border-critical/30',
  'Accepted Risk':   'bg-medium/15 text-medium border border-medium/30',
  'False Positive':  'bg-border-default/50 text-text-muted border border-border-default',
  'Resolved':        'bg-low/15 text-low border border-low/30',
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

  const grouped = useMemo(() => {
    let list = instances
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(i => i.URL?.toLowerCase().includes(q) || i.Parameter?.toLowerCase().includes(q) || i.vulnerability_name?.toLowerCase().includes(q))
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

  const totalByStatus = useMemo(() => {
    const counts: Record<string, number> = {}
    instances.forEach(i => { counts[i.status] = (counts[i.status] || 0) + 1 })
    return counts
  }, [instances])

  const updateStatus = useMutation({
    mutationFn: ({ inst, newStatus }: { inst: any; newStatus: string }) =>
      standardizedApiClient.updateVulnerabilityInstance(inst.vulnerability_id, inst.id, { status: newStatus }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['project-instances', projectId] }); qc.invalidateQueries({ queryKey: ['instances'] }); setEditTarget(null); toast.success('Status updated') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })
  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteVulnerabilityInstance(deleteTarget.vulnerability_id, deleteTarget.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['project-instances', projectId] }); qc.invalidateQueries({ queryKey: ['instances'] }); qc.invalidateQueries({ queryKey: ['vulns', projectId] }); setDeleteTarget(null); toast.success('Asset removed') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  return (
    <>
      {instances.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-5">
          {Object.entries(totalByStatus).map(([st, count]) => (
            <button key={st} onClick={() => setFilterStatus(filterStatus === st ? 'All' : st)}
              className={`text-xs px-2.5 py-1 rounded-full border font-medium transition-all ${INSTANCE_STATUS_COLORS[st] || 'bg-app-overlay text-text-muted border-border-default'} ${filterStatus === st ? 'ring-2 ring-accent-500/30' : 'opacity-80 hover:opacity-100'}`}>
              {st} · {count}
            </button>
          ))}
          {filterStatus !== 'All' && <button onClick={() => setFilterStatus('All')} className="text-xs px-2.5 py-1 text-text-muted hover:text-text-primary transition-colors">Clear ×</button>}
        </div>
      )}

      <div className="flex items-center gap-2 mb-4">
        <SearchInput value={search} onChange={setSearch} placeholder="Search URL, parameter or finding…" className="flex-1" />
        <p className="text-xs text-text-muted shrink-0">{grouped.reduce((n, g) => n + g.items.length, 0)} of {instances.length} asset{instances.length !== 1 ? 's' : ''}</p>
      </div>

      {isLoading ? <PageSpinner /> : instances.length === 0 ? (
        <EmptyState icon={ShieldExclamationIcon} title="No affected assets recorded" description="Open a finding and add affected URLs or IPs to track affected assets here." />
      ) : grouped.length === 0 ? (
        <EmptyState title="No matches" description="Try a different search or filter." />
      ) : (
        <div className="space-y-4">
          {grouped.map(({ vuln, items }) => (
            <div key={vuln.vulnerability_id} className="bg-app-surface border border-border-subtle rounded-xl overflow-hidden">
              <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border-subtle bg-app-raised">
                <SeverityBadge severity={vuln.vulnerability_severity} />
                <p className="text-sm font-medium text-text-primary truncate flex-1">{vuln.vulnerability_name}</p>
                {vuln.cvssscore > 0 && <span className="text-xs text-text-muted shrink-0">CVSS {vuln.cvssscore}</span>}
                <span className="text-xs text-text-muted shrink-0">{items.length} asset{items.length !== 1 ? 's' : ''}</span>
              </div>
              <div className="divide-y divide-border-subtle">
                {items.map((inst: any) => (
                  <div key={inst.id} className="group flex items-center gap-3 px-4 py-2.5 hover:bg-app-overlay/50 transition-colors">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-mono text-text-primary truncate">{inst.URL || '—'}</p>
                      {inst.Parameter && <p className="text-xs font-mono text-text-muted mt-0.5 truncate">param: {inst.Parameter}</p>}
                    </div>
                    {editTarget?.id === inst.id ? (
                      <div className="flex items-center gap-1.5 shrink-0">
                        <select value={editStatus} onChange={e => setEditStatus(e.target.value)} autoFocus className={inp.replace('py-2', 'py-1').replace('text-sm', 'text-xs')}>
                          {Object.keys(INSTANCE_STATUS_COLORS).map(s => <option key={s}>{s}</option>)}
                        </select>
                        <button onClick={() => updateStatus.mutate({ inst, newStatus: editStatus })} disabled={updateStatus.isPending} className="text-xs text-accent-400 hover:text-text-primary disabled:opacity-40 px-1.5">Save</button>
                        <button onClick={() => setEditTarget(null)} className="text-xs text-text-muted hover:text-text-primary">✕</button>
                      </div>
                    ) : (
                      <button onClick={() => { setEditTarget(inst); setEditStatus(inst.status) }}
                        className={`shrink-0 text-[10px] font-medium px-2 py-0.5 rounded-full border transition-all hover:opacity-100 ${INSTANCE_STATUS_COLORS[inst.status] || 'bg-app-overlay text-text-muted border-border-default'}`}>
                        {inst.status}
                      </button>
                    )}
                    <button onClick={() => setDeleteTarget(inst)} className="p-1 text-text-muted hover:text-critical rounded opacity-0 group-hover:opacity-100 transition-all shrink-0">
                      <TrashIcon className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      <ConfirmModal isOpen={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()} title="Remove Asset" message={`Remove "${deleteTarget?.URL}" from "${deleteTarget?.vulnerability_name}"?`} loading={del.isPending} />
    </>
  )
}

// ── SLATab ────────────────────────────────────────────────────────────────────

function SLATab({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.is_staff || user?.is_superuser
  const [editPolicy, setEditPolicy] = useState(false)
  const [policyForm, setPolicyForm] = useState<Record<string, number>>({})

  const { data: policy } = useQuery({
    queryKey: ['sla-policy'],
    queryFn: () => standardizedApiClient.getSLAPolicy(),
  })
  const { data: breached, isLoading: breachLoading } = useQuery({
    queryKey: ['sla-breached'],
    queryFn: () => standardizedApiClient.getSLABreached(),
    staleTime: 60_000,
  })

  const savePolicy = useMutation({
    mutationFn: (d: any) => standardizedApiClient.updateSLAPolicy(d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sla-policy'] }); setEditPolicy(false); toast.success('SLA policy updated') },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  const allBreached = Array.isArray(breached) ? breached : []
  const projectBreached = allBreached.filter((v: any) => String(v.project) === projectId || String(v.project_id) === projectId)
  const breachedFindings = projectBreached.filter((v: any) => v.sla_status === 'breached')
  const dueSoonFindings  = projectBreached.filter((v: any) => v.sla_status === 'due_soon')

  const policyValues = Object.keys(policyForm).length > 0 ? policyForm : policy

  return (
    <div className="space-y-6">
      <div className="bg-app-surface border border-border-subtle rounded-xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border-subtle">
          <h3 className="text-sm font-semibold text-text-primary">SLA Policy</h3>
          {isAdmin && !editPolicy && <Button size="sm" variant="outline" icon={<PencilIcon className="w-3.5 h-3.5" />} onClick={() => { setEditPolicy(true); setPolicyForm(policy || {}) }}>Edit</Button>}
        </div>
        <div className="px-5 py-4">
          {editPolicy ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {[['critical_days','Critical'],['high_days','High'],['medium_days','Medium'],['low_days','Low'],['informational_days','Info']].map(([k, label]) => (
                  <div key={k} className="flex items-center gap-2">
                    <label className="text-xs text-text-secondary w-20 shrink-0">{label}</label>
                    <input type="number" min={1} max={3650} value={policyValues?.[k] ?? ''} onChange={e => setPolicyForm(f => ({ ...f, [k]: Number(e.target.value) }))} className={inp + ' w-20'} />
                    <span className="text-xs text-text-muted">days</span>
                  </div>
                ))}
              </div>
              <div className="flex gap-2">
                <Button size="sm" loading={savePolicy.isPending} onClick={() => savePolicy.mutate(policyForm)}>Save</Button>
                <Button size="sm" variant="ghost" onClick={() => setEditPolicy(false)}>Cancel</Button>
              </div>
            </div>
          ) : policy ? (
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
              {[['Critical','critical_days'],['High','high_days'],['Medium','medium_days'],['Low','low_days'],['Info','informational_days']].map(([label, key]) => (
                <div key={key} className="text-center">
                  <p className={`text-lg font-bold ${severityColor(label).split(' ')[1]}`}>{policy[key] ?? '—'}</p>
                  <p className="text-xs text-text-muted">{label}</p>
                  <p className="text-[10px] text-text-muted">days</p>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-text-muted">No SLA policy configured.</p>}
        </div>
      </div>

      {breachLoading ? <PageSpinner /> : (
        <>
          {breachedFindings.length > 0 && (
            <div className="bg-app-surface border border-border-subtle rounded-xl">
              <div className="px-5 py-4 border-b border-border-subtle flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-critical animate-pulse" />
                <h3 className="text-sm font-semibold text-text-primary">SLA Breached ({breachedFindings.length})</h3>
              </div>
              <div className="divide-y divide-border-subtle">
                {breachedFindings.map((v: any) => (
                  <div key={v.id} className="flex items-center gap-3 px-5 py-3">
                    <SeverityBadge severity={v.vulnerabilityseverity} />
                    <p className="text-sm text-text-primary flex-1 truncate">{v.vulnerabilityname}</p>
                    <SLABadge sla_status="breached" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {dueSoonFindings.length > 0 && (
            <div className="bg-app-surface border border-border-subtle rounded-xl">
              <div className="px-5 py-4 border-b border-border-subtle">
                <h3 className="text-sm font-semibold text-text-primary">Due Soon ({dueSoonFindings.length})</h3>
              </div>
              <div className="divide-y divide-border-subtle">
                {dueSoonFindings.map((v: any) => (
                  <div key={v.id} className="flex items-center gap-3 px-5 py-3">
                    <SeverityBadge severity={v.vulnerabilityseverity} />
                    <p className="text-sm text-text-primary flex-1 truncate">{v.vulnerabilityname}</p>
                    <SLABadge sla_status="due_soon" days_remaining={v.days_remaining} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {breachedFindings.length === 0 && dueSoonFindings.length === 0 && (
            <EmptyState icon={CheckCircleIcon} title="All findings within SLA" description="No findings are breached or due soon." />
          )}
        </>
      )}
    </div>
  )
}

// ── ScopeSection (embedded in ScannerTab) ─────────────────────────────────────

function ScopeSection({ projectId }: { projectId: string }) {
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
  const updateScope = useMutation({
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
    mutationFn: () => { const fd = new FormData(); fd.append('file', nmapFile!); return standardizedApiClient.uploadNmapScope(projectId, fd) },
    onSuccess: (data) => { qc.invalidateQueries({ queryKey: ['scopes', projectId] }); setNmapResult(data); setNmapFile(null); toast.success(`Imported ${data.imported ?? data.added ?? 0} scope entries from Nmap`) },
    onError: (e: any) => toast.error(e?.message || 'Nmap import failed'),
  })

  const startEdit = (s: any) => { setEditTarget(s); setEditScope(s.scope); setEditDesc(s.description || '') }

  return (
    <div className="space-y-3">
      {isLoading ? <PageSpinner /> : scopes.length === 0 ? (
        <EmptyState title="No scope defined" description="Add URLs, IP ranges, or CIDRs. At least one scope entry is required to generate a report." />
      ) : (
        <div className="space-y-1">
          {scopes.map((s: any) => (
            editTarget?.id === s.id ? (
              <form key={s.id} onSubmit={e => { e.preventDefault(); updateScope.mutate() }}
                className="flex gap-2 bg-app-overlay border border-accent-500/50 rounded-lg px-3 py-2">
                <input value={editScope} onChange={e => setEditScope(e.target.value)} required autoFocus className="flex-1 min-w-0 bg-transparent text-sm text-text-primary font-mono focus:outline-none" />
                <input value={editDesc} onChange={e => setEditDesc(e.target.value)} placeholder="Description" className="w-40 bg-transparent text-sm text-text-secondary focus:outline-none" />
                <button type="submit" disabled={!editScope.trim() || updateScope.isPending} className="text-xs text-accent-400 hover:text-text-primary disabled:opacity-40 shrink-0">Save</button>
                <button type="button" onClick={() => setEditTarget(null)} className="text-xs text-text-muted hover:text-text-primary shrink-0">✕</button>
              </form>
            ) : (
              <div key={s.id} className="group flex items-center gap-3 bg-app-overlay hover:bg-app-overlay/80 border border-border-subtle rounded-lg px-4 py-2.5 transition-colors">
                <span className="w-1.5 h-1.5 rounded-full bg-accent-500 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-text-primary font-mono truncate">{s.scope}</p>
                  {s.description && <p className="text-xs text-text-muted mt-0.5">{s.description}</p>}
                </div>
                <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-all">
                  <button onClick={() => startEdit(s)} className="text-xs text-text-muted hover:text-text-primary px-1.5 py-0.5 hover:bg-app-overlay rounded transition-colors">Edit</button>
                  <button onClick={() => setDeleteTarget(s)} className="p-1 text-text-muted hover:text-critical rounded transition-colors"><TrashIcon className="w-3.5 h-3.5" /></button>
                </div>
              </div>
            )
          ))}
        </div>
      )}

      <form onSubmit={e => { e.preventDefault(); if (newScope.trim()) create.mutate() }} className="flex gap-2 pt-2 border-t border-border-subtle">
        <div className="relative flex-1 min-w-0">
          <PlusIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted pointer-events-none" />
          <input value={newScope} onChange={e => setNewScope(e.target.value)} placeholder="URL / IP / CIDR…" className={inp.replace('px-3', 'pl-8 pr-3').replace('py-2', 'py-1.5')} />
        </div>
        <input value={newDesc} onChange={e => setNewDesc(e.target.value)} placeholder="Description (opt.)" className={inp.replace('py-2', 'py-1.5') + ' w-44'} />
        <Button size="sm" type="submit" loading={create.isPending} disabled={!newScope.trim()}>Add</Button>
      </form>

      <details className="group">
        <summary className="text-xs text-text-muted cursor-pointer hover:text-text-secondary transition-colors list-none flex items-center gap-1.5">
          <ChevronRightIcon className="w-3 h-3 group-open:rotate-90 transition-transform" />
          Import from Nmap XML
        </summary>
        <div className="mt-2 space-y-2">
          <div className="flex gap-2 items-center">
            <input type="file" id="nmap-file" className="hidden" accept=".xml" onChange={e => { setNmapFile(e.target.files?.[0] || null); setNmapResult(null) }} />
            <label htmlFor="nmap-file" className="cursor-pointer text-xs px-3 py-1.5 bg-app-overlay border border-border-default hover:bg-app-surface text-text-secondary rounded-lg transition-colors">
              {nmapFile ? nmapFile.name : 'Choose Nmap .xml file'}
            </label>
            {nmapFile && <Button size="sm" onClick={() => nmapUpload.mutate()} loading={nmapUpload.isPending}>Import</Button>}
          </div>
          {nmapResult && (
            <div className="flex items-center gap-2 text-xs text-low">
              <CheckCircleIcon className="w-3.5 h-3.5" />
              {nmapResult.imported ?? nmapResult.added ?? 0} hosts imported
              {nmapResult.skipped > 0 && <span className="text-text-muted">· {nmapResult.skipped} skipped</span>}
            </div>
          )}
        </div>
      </details>

      <ConfirmModal isOpen={!!deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={() => del.mutate()} title="Remove Scope" message={`Remove "${deleteTarget?.scope}"?`} loading={del.isPending} />
    </div>
  )
}

// ── ScannerTab ────────────────────────────────────────────────────────────────

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
    mutationFn: () => { const fd = new FormData(); fd.append('file', file!); return standardizedApiClient.uploadProjectScan(projectId, fd) },
    onSuccess: (data) => { setResult(data); qc.invalidateQueries({ queryKey: ['vulns', projectId] }); toast.success(`Imported ${data.new_vulnerabilities ?? 0} new findings`); setFile(null) },
    onError: (e: any) => toast.error(e?.message || 'Upload failed'),
  })

  const handleDrop = (e: React.DragEvent) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files?.[0]; if (f) { setFile(f); setResult(null) } }
  const supported = scanners?.scanners ?? []

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <h3 className="text-sm font-semibold text-text-primary">Import Scan File</h3>
        <div
          onDragOver={e => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-xl p-10 text-center transition-all ${dragging ? 'border-accent-500 bg-accent-500/5' : 'border-border-strong hover:border-border-default'}`}
        >
          <CloudArrowUpIcon className={`w-10 h-10 mx-auto mb-3 transition-colors ${dragging ? 'text-accent-400' : 'text-text-muted'}`} />
          {file ? (
            <div className="space-y-2">
              <p className="text-sm font-medium text-text-primary">{file.name}</p>
              <p className="text-xs text-text-muted">{(file.size / 1024).toFixed(1)} KB · ready to import</p>
              <button onClick={() => { setFile(null); setResult(null) }} className="text-xs text-text-muted hover:text-critical transition-colors">Remove</button>
            </div>
          ) : (
            <>
              <p className="text-sm font-medium text-text-secondary mb-1">Drop a scan file here</p>
              <p className="text-xs text-text-muted mb-4">or click to browse — .xml .nessus .json .csv .html</p>
              <input type="file" id="scan-file" className="hidden" accept=".xml,.nessus,.json,.csv,.html" onChange={e => { setFile(e.target.files?.[0] || null); setResult(null) }} />
              <label htmlFor="scan-file" className="cursor-pointer inline-flex items-center gap-2 px-4 py-2 bg-app-overlay border border-border-default hover:bg-app-surface text-text-secondary text-sm rounded-lg transition-colors">
                Choose File
              </label>
            </>
          )}
        </div>

        {file && <Button onClick={() => upload.mutate()} loading={upload.isPending} className="w-full" icon={<CloudArrowUpIcon className="w-4 h-4" />}>Import Scan Results</Button>}

        {result && (
          <div className="bg-low/10 border border-low/20 rounded-xl p-4 space-y-1">
            <div className="flex items-center gap-2">
              <CheckCircleIcon className="w-4 h-4 text-low shrink-0" />
              <p className="text-sm font-semibold text-low">Import complete · {result.scanner_type}</p>
            </div>
            <div className="flex gap-4 text-xs text-text-secondary ml-6">
              <span className="text-low font-medium">{result.new_vulnerabilities} new</span>
              <span>{result.duplicates_found} duplicates skipped</span>
              <span>{result.total_findings} total parsed</span>
            </div>
          </div>
        )}

        {supported.length > 0 && (
          <details className="group">
            <summary className="text-xs text-text-muted cursor-pointer hover:text-text-secondary transition-colors list-none flex items-center gap-1">
              <ChevronRightIcon className="w-3 h-3 group-open:rotate-90 transition-transform" />
              {supported.length} supported scanners
            </summary>
            <div className="flex flex-wrap gap-1.5 mt-2">
              {supported.map((s: any) => (
                <span key={s.type} className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-app-overlay border border-border-default text-text-muted">{s.name || s.type}</span>
              ))}
            </div>
          </details>
        )}
      </div>

      <div className="border-t border-border-subtle pt-6 space-y-4">
        <h3 className="text-sm font-semibold text-text-primary">Scope</h3>
        <ScopeSection projectId={projectId} />
      </div>
    </div>
  )
}

// ── ReportTab ─────────────────────────────────────────────────────────────────

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
      <div className="bg-app-overlay border border-border-subtle rounded-xl p-4">
        <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">Requirements before generating</p>
        <ul className="space-y-1.5 text-sm text-text-secondary">
          {[
            'At least one scope entry (Scanner tab → Scope section)',
            'At least one finding with an affected asset (open a finding → Affected Assets)',
          ].map(req => (
            <li key={req} className="flex items-start gap-2">
              <InformationCircleIcon className="w-4 h-4 text-accent-400 shrink-0 mt-0.5" />
              {req}
            </li>
          ))}
        </ul>
      </div>

      <div>
        <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Report Type</p>
        <div className="inline-flex bg-app-overlay border border-border-default rounded-lg p-0.5 gap-0.5">
          {(['Audit', 'Re-Audit'] as const).map(t => (
            <button key={t} onClick={() => setReportType(t)}
              className={`px-4 py-1.5 text-sm font-medium rounded-md transition-all ${reportType === t ? 'bg-accent-500 text-white shadow' : 'text-text-secondary hover:text-text-primary'}`}>
              {t}
            </button>
          ))}
        </div>
        {reportType === 'Re-Audit' && <p className="text-xs text-text-muted mt-2">Re-Audit reports include retest status and remediation tracking.</p>}
      </div>

      <div>
        <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Download Format</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {[
            { format: 'pdf',  label: 'PDF Report',  sub: 'Print-ready formatted document', colorClass: 'text-critical', bgClass: 'bg-critical/10 border-critical/20' },
            { format: 'docx', label: 'DOCX Report', sub: 'Editable Word document',          colorClass: 'text-info',     bgClass: 'bg-info/10 border-info/20' },
          ].map(({ format, label, sub, colorClass, bgClass }) => (
            <button key={format} onClick={() => downloadReport(format)} disabled={loading}
              className={`group flex items-center gap-3 border rounded-xl p-4 text-left transition-all disabled:opacity-50 hover:scale-[1.01] active:scale-[0.99] ${bgClass} hover:brightness-125`}>
              <div className={`w-10 h-10 rounded-lg bg-app-bg/50 flex items-center justify-center shrink-0 ${colorClass}`}>
                <DocumentArrowDownIcon className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-text-primary">{label}</p>
                <p className="text-xs text-text-secondary mt-0.5">{sub}</p>
              </div>
              {loading && <div className="ml-auto w-4 h-4 border-2 border-border-default border-t-text-primary rounded-full animate-spin shrink-0" />}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── SetupWorkspace ────────────────────────────────────────────────────────────

function SetupWorkspace({ onCreated }: { onCreated: (id: string) => void }) {
  const [form, setForm] = useState({ name: '', startdate: '', enddate: '', projecttype: '' })
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
    onSuccess: (newProject: any) => { toast.success('Workspace created'); onCreated(String(newProject.id)) },
    onError: (e: any) => toast.error(e?.message || 'Failed to create workspace'),
  })

  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] p-6">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-accent-500/15 border border-accent-500/20 flex items-center justify-center mb-4">
            <WrenchScrewdriverIcon className="w-7 h-7 text-accent-400" />
          </div>
          <h1 className="text-lg font-semibold text-text-primary">Set up your workspace</h1>
          <p className="text-sm text-text-muted mt-1 text-center">Create your security assessment project to get started.</p>
        </div>
        <form onSubmit={e => { e.preventDefault(); create.mutate() }} className="bg-app-surface border border-border-subtle rounded-xl p-6 space-y-4">
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

// ── WorkspacePage ─────────────────────────────────────────────────────────────

export default function WorkspacePage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>('findings')

  const { data: project, isLoading } = useQuery({
    queryKey: ['workspace', id],
    queryFn: () => standardizedApiClient.getProject(id!),
    enabled: !!id,
  })

  const updateStatus = useMutation({
    mutationFn: (status: string) => standardizedApiClient.updateProject(id!, { status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['workspace', id] }); toast.success('Status updated') },
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
      <button onClick={() => navigate('/projects')} className="inline-flex items-center gap-1.5 text-xs text-text-muted hover:text-text-primary transition-colors group">
        <ArrowLeftIcon className="w-3.5 h-3.5 group-hover:-translate-x-0.5 transition-transform" />
        All Projects
      </button>

      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-bold text-text-primary tracking-tight truncate">{project.name}</h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1.5 text-xs text-text-muted">
            {project.startdate && (
              <span className="flex items-center gap-1">
                <span className="w-1 h-1 rounded-full bg-border-strong" />
                {project.startdate} → {project.enddate || '…'}
              </span>
            )}
            {project.projecttype && (
              <span className="flex items-center gap-1">
                <span className="w-1 h-1 rounded-full bg-border-strong" />
                {project.projecttype}
              </span>
            )}
          </div>
        </div>
        <select
          value={project.status || ''}
          onChange={e => updateStatus.mutate(e.target.value)}
          disabled={updateStatus.isPending}
          className="shrink-0 bg-app-surface border border-border-default rounded-lg px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-accent-500 disabled:opacity-50 cursor-pointer"
        >
          {PROJECT_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div className="border-b border-border-subtle">
        <nav className="-mb-px flex gap-1 overflow-x-auto">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-4 pb-3 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                tab === t.id
                  ? 'border-accent-500 text-accent-400'
                  : 'border-transparent text-text-muted hover:text-text-secondary hover:border-border-default'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      <div>
        {tab === 'findings' && <FindingsTab projectId={String(project.id)} />}
        {tab === 'retests'  && <RetestsTab  projectId={String(project.id)} />}
        {tab === 'assets'   && <AssetsTab   projectId={String(project.id)} />}
        {tab === 'sla'      && <SLATab      projectId={String(project.id)} />}
        {tab === 'scanner'  && <ScannerTab  projectId={String(project.id)} />}
        {tab === 'report'   && <ReportTab   projectId={String(project.id)} projectName={project.name} />}
      </div>
    </div>
  )
}
