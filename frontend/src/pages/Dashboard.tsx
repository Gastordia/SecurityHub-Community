import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  BriefcaseIcon,
  ExclamationCircleIcon,
} from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { PageSpinner, EmptyState } from '@/components/ui/Spinner'
import { StatusBadge } from '@/components/ui/Badge'
import { SeverityBar } from '@/components/ui/SeverityBar'
import { Button } from '@/components/ui/Button'

function StatCard({
  label,
  value,
  icon: Icon,
  iconClass,
}: {
  label: string
  value: number | string
  icon: React.ComponentType<{ className?: string }>
  iconClass: string
}) {
  return (
    <div className="bg-app-surface border border-border-subtle rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-medium text-text-muted uppercase tracking-wider">{label}</p>
        <div className={`p-2 rounded-lg ${iconClass}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <p className="text-2xl font-bold text-text-primary">{value ?? '—'}</p>
    </div>
  )
}

function ProjectCard({ project }: { project: any }) {
  const { data: stats } = useQuery({
    queryKey: ['vuln-stats', project.id],
    queryFn: () => standardizedApiClient.getVulnerabilityStats(project.id),
    staleTime: 60_000,
  })

  return (
    <Link
      to={`/workspace/${project.id}`}
      className="bg-app-surface border border-border-subtle rounded-xl p-5 hover:border-border-default hover:bg-app-overlay/50 transition-all block"
    >
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-text-primary truncate">{project.name}</p>
          {(project.startdate || project.projecttype) && (
            <p className="text-xs text-text-muted mt-0.5">
              {project.projecttype && <span>{project.projecttype}</span>}
              {project.projecttype && project.startdate && <span> · </span>}
              {project.startdate && (
                <span>
                  {project.startdate} – {project.enddate || '…'}
                </span>
              )}
            </p>
          )}
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
    </Link>
  )
}

export default function DashboardPage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => standardizedApiClient.getDashboardSummary(),
  })

  const { data: projectData, isLoading: projLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: () => standardizedApiClient.getProjects({ page_size: 6 }),
  })

  const { data: slaBreached } = useQuery({
    queryKey: ['sla-breached'],
    queryFn: () => standardizedApiClient.getSLABreached(),
    staleTime: 60_000,
  })

  if (isLoading) return <PageSpinner />

  const s = stats || {}
  const projects = Array.isArray(projectData?.results)
    ? projectData.results
    : Array.isArray(projectData)
    ? projectData
    : []
  const breachedList = Array.isArray(slaBreached) ? slaBreached : []
  const breachedCount = breachedList.length

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Overview</h1>
        <p className="text-xs text-text-muted mt-0.5">Your security posture at a glance.</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Findings"
          value={s.total_vulnerabilities ?? s.open_vulnerabilities ?? '—'}
          icon={ExclamationTriangleIcon}
          iconClass="bg-medium/10 text-medium"
        />
        <StatCard
          label="Critical"
          value={
            s.critical_vulnerabilities ??
            s.severity_counts?.Critical ??
            s.critical ??
            '—'
          }
          icon={ShieldExclamationIcon}
          iconClass="bg-critical/10 text-critical"
        />
        <StatCard
          label="High"
          value={
            s.high_vulnerabilities ??
            s.severity_counts?.High ??
            s.high ??
            '—'
          }
          icon={ExclamationTriangleIcon}
          iconClass="bg-high/10 text-high"
        />
        <StatCard
          label="Resolved"
          value={
            s.resolved_vulnerabilities ??
            s.fixed_vulnerabilities ??
            s.fixed ??
            '—'
          }
          icon={CheckCircleIcon}
          iconClass="bg-low/10 text-low"
        />
      </div>

      {breachedCount > 0 && (
        <div className="flex items-center justify-between gap-4 bg-medium/10 border border-medium/30 rounded-xl px-5 py-3">
          <div className="flex items-center gap-3">
            <ExclamationCircleIcon className="w-5 h-5 text-medium shrink-0" />
            <p className="text-sm text-text-primary">
              <span className="font-semibold text-medium">
                {breachedCount} finding{breachedCount !== 1 ? 's' : ''}
              </span>{' '}
              have breached their SLA deadline.
            </p>
          </div>
          <Link
            to="/projects"
            className="text-xs font-medium text-medium hover:text-text-primary transition-colors whitespace-nowrap shrink-0"
          >
            Review →
          </Link>
        </div>
      )}

      <div className="bg-app-surface border border-border-subtle rounded-xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border-subtle">
          <h2 className="text-sm font-semibold text-text-primary">Recent Projects</h2>
          <Link
            to="/projects"
            className="text-xs text-accent-400 hover:text-text-primary transition-colors"
          >
            View all →
          </Link>
        </div>

        {projLoading ? (
          <div className="p-6">
            <PageSpinner />
          </div>
        ) : projects.length === 0 ? (
          <EmptyState
            icon={BriefcaseIcon}
            title="No projects yet"
            description="Create your first security assessment to get started."
            action={
              <Link to="/projects">
                <Button size="sm">New Project</Button>
              </Link>
            }
          />
        ) : (
          <div className="p-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {projects.slice(0, 6).map((p: any) => (
              <ProjectCard key={p.id} project={p} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
