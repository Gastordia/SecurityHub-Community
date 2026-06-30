import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'react-hot-toast'
import { Layout } from './components/layout/Layout'
import { AuthGuard, AdminGuard } from './components/auth/AuthGuard'
import LoginPage from './pages/Login'
import DashboardPage from './pages/Dashboard'
import WorkspacePage from './pages/Workspace'
import ProjectsPage from './pages/Projects'
import VulnDBPage from './pages/VulnDB'
import SettingsPage from './pages/Settings'
import ProfilePage from './pages/Profile'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, retry: 1 },
  },
})

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <AuthGuard>
            <Layout>
              <Routes>
                <Route path="/"                element={<DashboardPage />} />
                <Route path="/projects"        element={<ProjectsPage />} />
                <Route path="/workspace/:id"   element={<WorkspacePage />} />
                <Route path="/vulndb"          element={<VulnDBPage />} />
                <Route path="/profile"   element={<ProfilePage />} />
                <Route
                  path="/settings"
                  element={<AdminGuard><SettingsPage /></AdminGuard>}
                />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          </AuthGuard>
        }
      />
    </Routes>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppRoutes />
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#171b2a',
              color: '#edf0f7',
              border: '1px solid #252b3d',
              fontSize: '13px',
            },
          }}
        />
      </BrowserRouter>
    </QueryClientProvider>
  )
}
