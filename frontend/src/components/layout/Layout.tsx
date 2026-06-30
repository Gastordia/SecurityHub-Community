import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth-store'
import {
  HomeIcon,
  BriefcaseIcon,
  BookOpenIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
  ChevronLeftIcon,
  Bars3Icon,
} from '@heroicons/react/24/outline'
import { clsx } from 'clsx'

// ── Hex logo mark ─────────────────────────────────────────────────────────────

function HexLogo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id="hex-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#8b82ff" />
          <stop offset="100%" stopColor="#6d63ff" />
        </linearGradient>
      </defs>
      {/* Hexagon */}
      <path
        d="M14 2L24.39 8V20L14 26L3.61 20V8L14 2Z"
        fill="url(#hex-grad)"
        fillOpacity="0.18"
        stroke="url(#hex-grad)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      {/* Shield check inside */}
      <path
        d="M14 7.5L9.5 9.5V14C9.5 17 11.5 19.5 14 20.5C16.5 19.5 18.5 17 18.5 14V9.5L14 7.5Z"
        fill="url(#hex-grad)"
        fillOpacity="0.4"
        stroke="url(#hex-grad)"
        strokeWidth="1"
        strokeLinejoin="round"
      />
      <path
        d="M11.5 13.5L13.2 15.3L16.5 11.5"
        stroke="#8b82ff"
        strokeWidth="1.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// ── Nav config ─────────────────────────────────────────────────────────────────

const nav = [
  { to: '/',         label: 'Dashboard',    icon: HomeIcon },
  { to: '/projects', label: 'Projects',     icon: BriefcaseIcon },
  { to: '/vulndb',   label: 'Vuln Library', icon: BookOpenIcon },
]

const adminNav = [
  { to: '/settings', label: 'Settings', icon: Cog6ToothIcon },
]

// ── User avatar (initials) ────────────────────────────────────────────────────

function UserAvatar({ name }: { name: string }) {
  const initials = name
    .split(/[\s_.-]+/)
    .slice(0, 2)
    .map(w => w[0]?.toUpperCase() ?? '')
    .join('')
  return (
    <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-accent-500/20 border border-accent-500/40 text-accent-400 text-xs font-semibold shrink-0 select-none">
      {initials || '?'}
    </span>
  )
}

// ── Layout ─────────────────────────────────────────────────────────────────────

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)

  const handleLogout = async () => {
    try { await logout() } catch { /* best-effort */ }
    navigate('/login')
  }

  const isAdmin = user?.is_superuser || user?.is_staff
  const username = user?.username ?? ''

  return (
    <div className="flex h-screen bg-app-bg text-text-primary overflow-hidden">
      {/* ── Sidebar ── */}
      <aside
        className={clsx(
          'flex flex-col bg-app-surface border-r border-border-subtle transition-all duration-200 shrink-0',
          collapsed ? 'w-14' : 'w-[220px]'
        )}
      >
        {/* Logo section */}
        <div className="flex items-center px-3 py-[14px] border-b border-border-subtle min-h-[52px]">
          {collapsed ? (
            <div className="flex w-full items-center justify-center">
              <HexLogo size={26} />
            </div>
          ) : (
            <Link to="/" className="flex items-center gap-2.5 min-w-0 flex-1">
              <HexLogo size={26} />
              <span className="text-sm font-semibold text-text-primary tracking-tight truncate">
                SecurityHub
              </span>
            </Link>
          )}
          <button
            onClick={() => setCollapsed(c => !c)}
            className={clsx(
              'text-text-muted hover:text-text-secondary transition-colors p-1 rounded shrink-0',
              collapsed && 'mx-auto mt-1 block'
            )}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed
              ? <Bars3Icon className="w-4 h-4" />
              : <ChevronLeftIcon className="w-4 h-4" />}
          </button>
        </div>

        {/* Nav items */}
        <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              title={collapsed ? label : undefined}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 rounded-lg px-2.5 py-2 text-sm transition-all',
                  collapsed && 'justify-center',
                  isActive
                    ? 'bg-accent-500/10 text-accent-400 font-medium'
                    : 'text-text-muted hover:text-text-secondary hover:bg-app-overlay'
                )
              }
            >
              <Icon className="w-[18px] h-[18px] shrink-0" />
              {!collapsed && <span className="truncate">{label}</span>}
            </NavLink>
          ))}

          {isAdmin && (
            <>
              <div className={clsx('my-2 border-t border-border-subtle', collapsed && 'mx-1')} />
              {adminNav.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  title={collapsed ? label : undefined}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center gap-3 rounded-lg px-2.5 py-2 text-sm transition-all',
                      collapsed && 'justify-center',
                      isActive
                        ? 'bg-accent-500/10 text-accent-400 font-medium'
                        : 'text-text-muted hover:text-text-secondary hover:bg-app-overlay'
                    )
                  }
                >
                  <Icon className="w-[18px] h-[18px] shrink-0" />
                  {!collapsed && <span className="truncate">{label}</span>}
                </NavLink>
              ))}
            </>
          )}
        </nav>

        {/* User footer */}
        <div className="px-2 py-3 border-t border-border-subtle space-y-0.5">
          {/* Avatar + username */}
          <NavLink
            to="/profile"
            title={collapsed ? (username || 'Profile') : undefined}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-all',
                collapsed && 'justify-center',
                isActive
                  ? 'bg-app-overlay text-text-primary'
                  : 'text-text-muted hover:text-text-secondary hover:bg-app-overlay'
              )
            }
          >
            <UserAvatar name={username} />
            {!collapsed && (
              <span className="truncate text-xs text-text-secondary">{username || 'Profile'}</span>
            )}
          </NavLink>

          {/* Logout */}
          <button
            onClick={handleLogout}
            title={collapsed ? 'Sign out' : undefined}
            className={clsx(
              'flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-all',
              'text-text-muted hover:text-text-secondary hover:bg-app-overlay',
              collapsed && 'justify-center'
            )}
          >
            <ArrowRightOnRectangleIcon className="w-[18px] h-[18px] shrink-0" />
            {!collapsed && <span className="text-xs">Sign out</span>}
          </button>
        </div>
      </aside>

      {/* ── Main area ── */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="h-12 shrink-0 border-b border-border-subtle bg-app-surface/80 backdrop-blur-sm flex items-center px-4 gap-3">
          {/* Breadcrumb / page title area — pages inject via portal or context if needed */}
          <div id="topbar-title" className="flex-1 min-w-0" />
          {/* Right side user pill */}
          <div className="flex items-center gap-2 shrink-0">
            <UserAvatar name={username} />
            {username && (
              <span className="text-xs text-text-secondary hidden sm:block">{username}</span>
            )}
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-y-auto bg-app-bg">
          {children}
        </main>
      </div>
    </div>
  )
}
