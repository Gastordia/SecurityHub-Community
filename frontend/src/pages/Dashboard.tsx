import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  BriefcaseIcon,
} from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { PageSpinner } from '@/components/ui/Spinner'
import { Badge } from '@/components/ui/Badge'

function StatCard({ label, value, icon: Icon, color }: {
  label: string; value: number | string; icon: React.ComponentType<{ className?: string }>; color: string
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">{label}</p>
        <div className={`p-2 rounded-lg ${color}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <p className="text-2xl font-bold text-white">{value ?? '—'}</p>
    </div>
  )
}

export default function DashboardPage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => standardizedApiClient.getDashboardSummary(),
  })

  const { data: projectData, isLoading: projLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: () => standardizedApiClient.getProjects({ page_size: 5 }),
  })

  if (isLoading) return <PageSpinner />

  const s = stats || {}
  const projects = Array.isArray(projectData?.results) ? projectData.results : Array.isArray(projectData) ? projectData : []

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <div>
        <h1 className="text-lg font-semibold text-white">Dashboard</h1>
        <p className="text-xs text-slate-500 mt-0.5">Security assessment overview</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Findings"
          value={s.total_vulnerabilities ?? s.open_vulnerabilities ?? '—'}
          icon={ExclamationTriangleIcon}
          color="bg-yellow-500/10 text-yellow-400"
        />
        <StatCard
          label="Critical"
          value={s.critical_vulnerabilities ?? s.critical ?? '—'}
          icon={ShieldExclamationIcon}
          color="bg-red-500/10 text-red-400"
        />
        <StatCard
          label="High"
          value={s.high_vulnerabilities ?? s.high ?? '—'}
          icon={ExclamationTriangleIcon}
          color="bg-orange-500/10 text-orange-400"
        />
        <StatCard
          label="Resolved"
          value={s.resolved_vulnerabilities ?? s.fixed ?? '—'}
          icon={CheckCircleIcon}
          color="bg-green-500/10 text-green-400"
        />
      </div>

      {/* Workspace card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <h2 className="text-sm font-semibold text-white">Projects</h2>
          <Link to="/projects" className="text-xs text-indigo-400 hover:text-indigo-300 transition-colors">
            View all →
          </Link>
        </div>
        {projLoading ? (
          <div className="p-6"><PageSpinner /></div>
        ) : projects.length === 0 ? (
          <div className="px-5 py-10 text-center">
            <BriefcaseIcon className="w-8 h-8 text-slate-700 mx-auto mb-3" />
            <p className="text-sm text-slate-500 mb-3">No projects yet.</p>
            <Link to="/projects"
              className="inline-flex items-center gap-1.5 px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors">
              Create a project
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {projects.map((project: any) => (
              <Link key={project.id} to={`/workspace/${project.id}`} className="flex items-center justify-between px-5 py-4 hover:bg-slate-800/50 transition-colors">
                <div>
                  <p className="text-sm font-medium text-white">{project.name}</p>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {project.projecttype && <span>{project.projecttype} · </span>}
                    {project.startdate && <span>{project.startdate} – {project.enddate}</span>}
                  </p>
                </div>
                <Badge variant={
                  project.status?.toLowerCase() === 'completed' ? 'success' :
                  project.status?.toLowerCase() === 'in progress' ? 'info' :
                  project.status?.toLowerCase() === 'on hold' ? 'warning' : 'default'
                }>
                  {project.status || 'Active'}
                </Badge>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
