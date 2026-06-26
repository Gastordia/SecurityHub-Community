import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { PlusIcon, TrashIcon, FolderOpenIcon } from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { Button } from '@/components/ui/Button'
import { Input, Select } from '@/components/ui/Input'
import { Modal, ConfirmModal } from '@/components/ui/Modal'
import { PageSpinner, EmptyState } from '@/components/ui/Spinner'
import { statusBadge } from '@/components/ui/Badge'
import toast from 'react-hot-toast'

function ProjectForm({ onSave, onCancel, loading }: {
  onSave: (d: any) => void; onCancel: () => void; loading: boolean
}) {
  const [form, setForm] = useState({ name: '', startdate: '', enddate: '', projecttype: '' })
  const set = (k: string) => (e: React.ChangeEvent<any>) => setForm(f => ({ ...f, [k]: e.target.value }))

  const { data: ptData } = useQuery({
    queryKey: ['project-types'],
    queryFn: () => standardizedApiClient.getProjectTypes(),
  })
  const pts = Array.isArray(ptData?.results) ? ptData.results : Array.isArray(ptData) ? ptData : []

  return (
    <form onSubmit={e => { e.preventDefault(); onSave(form) }} className="space-y-3">
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
      <div className="flex justify-end gap-2 pt-2">
        <Button variant="secondary" size="sm" type="button" onClick={onCancel} disabled={loading}>Cancel</Button>
        <Button size="sm" type="submit" loading={loading} disabled={!form.name.trim()}>Create Project</Button>
      </div>
    </form>
  )
}

export default function ProjectsPage() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<any>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: () => standardizedApiClient.getProjects({ page_size: 100 }),
  })
  const projects = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []

  const create = useMutation({
    mutationFn: (d: any) => {
      const payload: Record<string, any> = { name: d.name }
      if (d.startdate) payload.startdate = d.startdate
      if (d.enddate) payload.enddate = d.enddate
      if (d.projecttype) payload.projecttype = d.projecttype
      return standardizedApiClient.createProject(payload)
    },
    onSuccess: (newProject: any) => {
      qc.invalidateQueries({ queryKey: ['projects'] })
      setShowCreate(false)
      toast.success('Project created')
      navigate(`/workspace/${newProject.id}`)
    },
    onError: (e: any) => toast.error(e?.message || 'Failed to create project'),
  })

  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteProject(deleteTarget.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['projects'] })
      setDeleteTarget(null)
      toast.success('Project deleted')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed to delete project'),
  })

  return (
    <div className="p-6 space-y-5 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-white">Projects</h1>
          <p className="text-xs text-slate-500 mt-0.5">{projects.length} project{projects.length !== 1 ? 's' : ''}</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <PlusIcon className="w-4 h-4" /> New Project
        </Button>
      </div>

      {isLoading ? <PageSpinner /> : projects.length === 0 ? (
        <EmptyState
          icon={FolderOpenIcon}
          title="No projects yet"
          subtitle="Create your first security assessment project to get started."
        />
      ) : (
        <div className="space-y-2">
          {projects.map((p: any) => (
            <div
              key={p.id}
              onClick={() => navigate(`/workspace/${p.id}`)}
              className="flex items-center justify-between bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl px-5 py-4 cursor-pointer transition-colors group"
            >
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-white group-hover:text-indigo-300 transition-colors truncate">{p.name}</p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {p.projecttype && <span>{p.projecttype}</span>}
                  {p.projecttype && p.startdate && <span> · </span>}
                  {p.startdate && <span>{p.startdate} – {p.enddate}</span>}
                </p>
              </div>
              <div className="flex items-center gap-3 ml-4 shrink-0">
                {statusBadge(p.status)}
                <button
                  onClick={e => { e.stopPropagation(); setDeleteTarget(p) }}
                  className="p-1 text-slate-600 hover:text-red-400 rounded transition-colors opacity-0 group-hover:opacity-100"
                >
                  <TrashIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="New Project" size="lg">
        <ProjectForm onSave={d => create.mutate(d)} onCancel={() => setShowCreate(false)} loading={create.isPending} />
      </Modal>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => del.mutate()}
        title="Delete Project"
        message={`Delete "${deleteTarget?.name}"? This will permanently remove all findings, scope, and reports for this project.`}
        loading={del.isPending}
      />
    </div>
  )
}
