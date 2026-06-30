import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { PlusIcon, TrashIcon, FolderOpenIcon, PencilIcon } from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { Button } from '@/components/ui/Button'
import { Input, Select, SearchInput } from '@/components/ui/Input'
import { Modal, ConfirmModal } from '@/components/ui/Modal'
import { PageSpinner, EmptyState } from '@/components/ui/Spinner'
import { StatusBadge } from '@/components/ui/Badge'
import { SeverityBar } from '@/components/ui/SeverityBar'
import toast from 'react-hot-toast'

const STATUS_OPTIONS = ['In Progress', 'Completed', 'Delay', 'Hold', 'On Hold']

function ProjectForm({
  initial,
  onSave,
  onCancel,
  loading,
}: {
  initial?: any
  onSave: (d: any) => void
  onCancel: () => void
  loading: boolean
}) {
  const [form, setForm] = useState({
    name: initial?.name || '',
    startdate: initial?.startdate || '',
    enddate: initial?.enddate || '',
    projecttype: initial?.projecttype || '',
    status: initial?.status || '',
    description: initial?.description || '',
  })
  const set = (k: string) => (e: React.ChangeEvent<any>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  const { data: ptData } = useQuery({
    queryKey: ['project-types'],
    queryFn: () => standardizedApiClient.getProjectTypes(),
  })
  const pts = Array.isArray(ptData?.results) ? ptData.results : Array.isArray(ptData) ? ptData : []

  return (
    <form
      onSubmit={e => {
        e.preventDefault()
        onSave(form)
      }}
      className="space-y-3"
    >
      <Input
        label="Project Name *"
        value={form.name}
        onChange={set('name')}
        required
        placeholder="e.g. ACME Corp Web App Pentest"
      />
      <div className="grid grid-cols-2 gap-3">
        <Input label="Start Date" type="date" value={form.startdate} onChange={set('startdate')} />
        <Input label="End Date" type="date" value={form.enddate} onChange={set('enddate')} />
      </div>
      {pts.length > 0 && (
        <Select label="Project Type" value={form.projecttype} onChange={set('projecttype')}>
          <option value="">Select type…</option>
          {pts.map((p: any) => (
            <option key={p.id} value={p.name}>
              {p.name}
            </option>
          ))}
        </Select>
      )}
      {initial && (
        <Select label="Status" value={form.status} onChange={set('status')}>
          <option value="">Select status…</option>
          {STATUS_OPTIONS.map(s => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
      )}
      <div className="flex justify-end gap-2 pt-2">
        <Button variant="ghost" size="sm" type="button" onClick={onCancel} disabled={loading}>
          Cancel
        </Button>
        <Button size="sm" type="submit" loading={loading} disabled={!form.name.trim()}>
          {initial ? 'Save Changes' : 'Create Project'}
        </Button>
      </div>
    </form>
  )
}

function ProjectCard({
  project,
  onEdit,
  onDelete,
}: {
  project: any
  onEdit: () => void
  onDelete: () => void
}) {
  const navigate = useNavigate()
  const { data: stats } = useQuery({
    queryKey: ['vuln-stats', project.id],
    queryFn: () => standardizedApiClient.getVulnerabilityStats(project.id),
    staleTime: 60_000,
  })

  return (
    <div className="bg-app-surface border border-border-subtle rounded-xl p-5 hover:border-border-default transition-all group flex flex-col gap-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-text-primary truncate group-hover:text-accent-400 transition-colors">
            {project.name}
          </p>
          <p className="text-xs text-text-muted mt-0.5">
            {project.projecttype && <span>{project.projecttype}</span>}
            {project.projecttype && project.startdate && <span> · </span>}
            {project.startdate && (
              <span>
                {project.startdate} – {project.enddate || '…'}
              </span>
            )}
          </p>
        </div>
        <StatusBadge status={project.status || 'In Progress'} />
      </div>

      <SeverityBar
        critical={stats?.severity_counts?.Critical ?? 0}
        high={stats?.severity_counts?.High ?? 0}
        medium={stats?.severity_counts?.Medium ?? 0}
        low={stats?.severity_counts?.Low ?? 0}
        info={stats?.severity_counts?.Info ?? 0}
      />

      <div className="flex items-center justify-between pt-1">
        <button
          onClick={() => navigate(`/workspace/${project.id}`)}
          className="text-xs text-accent-400 hover:text-text-primary transition-colors"
        >
          Open workspace →
        </button>
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            onClick={e => {
              e.stopPropagation()
              onEdit()
            }}
            className="p-1 text-text-muted hover:text-accent-400 rounded transition-colors"
            aria-label="Edit project"
          >
            <PencilIcon className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={e => {
              e.stopPropagation()
              onDelete()
            }}
            className="p-1 text-text-muted hover:text-critical rounded transition-colors"
            aria-label="Delete project"
          >
            <TrashIcon className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  )
}

export default function ProjectsPage() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<any>(null)
  const [editingProject, setEditingProject] = useState<any>(null)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: () => standardizedApiClient.getProjects({ page_size: 100 }),
  })
  const allProjects: any[] = Array.isArray(data?.results)
    ? data.results
    : Array.isArray(data)
    ? data
    : []

  const projects = useMemo(() => {
    let list = allProjects
    if (search) {
      const q = search.toLowerCase()
      list = list.filter((p: any) => p.name?.toLowerCase().includes(q))
    }
    if (statusFilter) {
      list = list.filter((p: any) => p.status === statusFilter)
    }
    return list
  }, [allProjects, search, statusFilter])

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

  const update = useMutation({
    mutationFn: (d: any) => standardizedApiClient.updateProject(editingProject.id, d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['projects'] })
      setEditingProject(null)
      toast.success('Project updated')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed to update project'),
  })

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">Projects</h1>
          <p className="text-xs text-text-muted mt-0.5">
            {allProjects.length} project{allProjects.length !== 1 ? 's' : ''}
          </p>
        </div>
        <Button size="sm" icon={<PlusIcon className="w-4 h-4" />} onClick={() => setShowCreate(true)}>
          New Project
        </Button>
      </div>

      <div className="flex gap-2">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search projects…"
          className="flex-1"
        />
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="px-3 py-2 rounded-lg bg-app-surface border border-border-default text-sm text-text-primary focus:outline-none focus:border-accent-500 focus:ring-1 focus:ring-accent-500/30"
        >
          <option value="">All Statuses</option>
          {STATUS_OPTIONS.map(s => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <PageSpinner />
      ) : allProjects.length === 0 ? (
        <EmptyState
          icon={FolderOpenIcon}
          title="No projects yet"
          description="Create your first assessment to get started."
          action={
            <Button size="sm" icon={<PlusIcon className="w-4 h-4" />} onClick={() => setShowCreate(true)}>
              New Project
            </Button>
          }
        />
      ) : projects.length === 0 ? (
        <EmptyState
          title="No matching projects"
          description="Try adjusting your search or filter."
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {projects.map((p: any) => (
            <ProjectCard
              key={p.id}
              project={p}
              onEdit={() => setEditingProject(p)}
              onDelete={() => setDeleteTarget(p)}
            />
          ))}
        </div>
      )}

      <Modal isOpen={showCreate} onClose={() => setShowCreate(false)} title="New Project" size="lg">
        <ProjectForm
          onSave={d => create.mutate(d)}
          onCancel={() => setShowCreate(false)}
          loading={create.isPending}
        />
      </Modal>

      <Modal
        isOpen={!!editingProject}
        onClose={() => setEditingProject(null)}
        title="Edit Project"
        size="lg"
      >
        {editingProject && (
          <ProjectForm
            initial={editingProject}
            onSave={d => update.mutate(d)}
            onCancel={() => setEditingProject(null)}
            loading={update.isPending}
          />
        )}
      </Modal>

      <ConfirmModal
        isOpen={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => del.mutate()}
        title="Delete Project"
        message={`Delete "${deleteTarget?.name}"? This will permanently remove all findings, scope, and reports for this project.`}
        loading={del.isPending}
      />
    </div>
  )
}
