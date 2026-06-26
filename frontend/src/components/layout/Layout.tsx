import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth-store'
import {
  HomeIcon,
  BriefcaseIcon,
  BookOpenIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
  UserCircleIcon,
  ChevronLeftIcon,
  Bars3Icon,
  ShieldExclamationIcon,
} from '@heroicons/react/24/outline'
import { clsx } from 'clsx'
import toast from 'react-hot-toast'

const nav = [
  { to: '/',         label: 'Dashboard',  icon: HomeIcon },
  { to: '/projects', label: 'Projects',   icon: BriefcaseIcon },
  { to: '/vulndb',   label: 'Vuln Library', icon: BookOpenIcon },
]

const adminNav = [
  { to: '/settings',  label: 'Settings',   icon: Cog6ToothIcon },
]

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)

  const handleLogout = async () => {
    try { await logout() } catch { /* best-effort */ }
    navigate('/login')
  }

  const isAdmin = user?.is_superuser || user?.is_staff

  return (
    <div className="flex h-screen bg-slate-950 text-white overflow-hidden">
      {/* Sidebar */}
      <aside className={clsx(
        'flex flex-col bg-slate-900 border-r border-slate-800 transition-all duration-200 shrink-0',
        collapsed ? 'w-14' : 'w-52'
      )}>
        {/* Logo */}
        <div className="flex items-center justify-between px-3 py-4 border-b border-slate-800">
          {!collapsed && (
            <Link to="/" className="flex items-center gap-2 min-w-0">
              <ShieldExclamationIcon className="w-5 h-5 text-indigo-500 shrink-0" />
              <span className="text-sm font-semibold text-white tracking-tight truncate">SecurityHub</span>
            </Link>
          )}
          {collapsed && <ShieldExclamationIcon className="w-5 h-5 text-indigo-500 mx-auto" />}
          <button onClick={() => setCollapsed(c => !c)}
            className="ml-auto text-slate-600 hover:text-slate-400 transition-colors p-1 shrink-0">
            {collapsed ? <Bars3Icon className="w-4 h-4" /> : <ChevronLeftIcon className="w-4 h-4" />}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === '/'}
              className={({ isActive }) => clsx(
                'flex items-center gap-3 rounded-lg px-2.5 py-2 text-sm transition-colors',
                isActive ? 'bg-indigo-600/15 text-indigo-400' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
              )}
              title={collapsed ? label : undefined}
            >
              <Icon className="w-4.5 h-4.5 w-[18px] h-[18px] shrink-0" />
              {!collapsed && <span className="truncate">{label}</span>}
            </NavLink>
          ))}

          {isAdmin && (
            <>
              <div className={clsx('my-2 border-t border-slate-800', collapsed && 'mx-1')} />
              {adminNav.map(({ to, label, icon: Icon }) => (
                <NavLink key={to} to={to}
                  className={({ isActive }) => clsx(
                    'flex items-center gap-3 rounded-lg px-2.5 py-2 text-sm transition-colors',
                    isActive ? 'bg-indigo-600/15 text-indigo-400' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                  )}
                  title={collapsed ? label : undefined}
                >
                  <Icon className="w-[18px] h-[18px] shrink-0" />
                  {!collapsed && <span className="truncate">{label}</span>}
                </NavLink>
              ))}
            </>
          )}
        </nav>

        {/* User footer */}
        <div className="px-2 py-3 border-t border-slate-800 space-y-0.5">
          <NavLink to="/profile"
            className={({ isActive }) => clsx(
              'flex items-center gap-3 rounded-lg px-2.5 py-2 text-sm transition-colors',
              isActive ? 'bg-slate-800 text-white' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            )}
            title={collapsed ? 'Profile' : undefined}
          >
            <UserCircleIcon className="w-[18px] h-[18px] shrink-0" />
            {!collapsed && <span className="truncate text-xs">{user?.username || 'Profile'}</span>}
          </NavLink>
          <button onClick={handleLogout}
            className="flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors"
            title={collapsed ? 'Sign out' : undefined}
          >
            <ArrowRightOnRectangleIcon className="w-[18px] h-[18px] shrink-0" />
            {!collapsed && <span className="text-xs">Sign out</span>}
          </button>
        </div>
      </aside>

      {/* Main */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <main className="flex-1 overflow-y-auto bg-slate-950">
          {children}
        </main>
      </div>
    </div>
  )
}
