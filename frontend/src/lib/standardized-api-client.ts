import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios'
import { getApiBaseUrl } from './api-base-url'
import { handleSessionExpired } from './session-expiration'
import { formatErrorForUser } from './api-response-handler'
import { useAuthStore } from '../stores/auth-store'

const API_BASE_URL = getApiBaseUrl()

type RetryableAxiosConfig = AxiosRequestConfig & {
  _authRetry?: boolean
}

const rawAxios = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

let refreshAccessPromise: Promise<string | null> | null = null

async function refreshAccessTokenOnce(): Promise<string | null> {
  if (refreshAccessPromise) return refreshAccessPromise
  refreshAccessPromise = (async () => {
    try {
      const { useAuthStore } = await import('../stores/auth-store')
      const store = useAuthStore.getState()
      // Send refresh token in body when available in memory; the backend also accepts
      // the httpOnly refresh_token cookie so this succeeds even after a page reload.
      const body = store.refreshToken ? { refresh: store.refreshToken } : {}
      const { data } = await rawAxios.post<{ access: string; refresh?: string }>(
        '/api/auth/token/refresh/',
        body
      )
      const newAccess = data.access
      const newRefresh = data.refresh ?? store.refreshToken ?? ''
      store.setTokens(newAccess, newRefresh)
      return newAccess
    } catch {
      return null
    } finally {
      refreshAccessPromise = null
    }
  })()
  return refreshAccessPromise
}

const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) config.headers['Authorization'] = `Bearer ${token}`
  return config
})

apiClient.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const config = error.config as RetryableAxiosConfig
    if (error.response?.status === 401 && !config?._authRetry) {
      config._authRetry = true
      const newToken = await refreshAccessTokenOnce()
      if (newToken) {
        config.headers = config.headers || {}
        config.headers['Authorization'] = `Bearer ${newToken}`
        return apiClient(config)
      }
      handleSessionExpired()
    }
    const formatted = formatErrorForUser(error)
    if (formatted) {
      try {
        Object.defineProperty(error, 'message', { configurable: true, writable: true, value: formatted })
      } catch {
        ;(error as Error).message = formatted
      }
    }
    return Promise.reject(error)
  }
)

export const standardizedApiClient = {
  // ── Auth ────────────────────────────────────────────────────────────────
  async login(username: string, password: string) {
    const response = await apiClient.post('/api/auth/login/', { username, password })
    return response.data
  },
  async logout() {
    const response = await apiClient.post('/api/auth/logout/')
    return response.data
  },
  // Single-flight refresh — safe to call from multiple places concurrently
  async refreshToken(): Promise<string | null> {
    return refreshAccessTokenOnce()
  },
  async getCurrentUser() {
    const response = await apiClient.get('/api/auth/me/')
    return response.data
  },
  async updateProfile(data: Record<string, any>) {
    const response = await apiClient.patch('/api/auth/profile/', data)
    return response.data
  },

  // ── Projects ─────────────────────────────────────────────────────────────
  async getProjects(params?: Record<string, any>) {
    const response = await apiClient.get('/api/project/projects/', { params })
    return response.data
  },
  async getProject(id: string | number) {
    const response = await apiClient.get(`/api/project/projects/${id}/`)
    return response.data
  },
  async createProject(data: Record<string, any>) {
    const response = await apiClient.post('/api/project/projects/', data)
    return response.data
  },
  async deleteProject(id: string | number) {
    const response = await apiClient.delete(`/api/project/projects/${id}/`)
    return response.data
  },
  async getDashboardSummary() {
    const response = await apiClient.get('/api/project/dashboard/summary/')
    return response.data
  },
  async generateProjectReport(id: string | number, data?: Record<string, any>) {
    const response = await apiClient.post(`/api/project/projects/${id}/report/`, data ?? {}, {
      responseType: 'blob',
    })
    return response.data as Blob
  },

  // ── Scopes ───────────────────────────────────────────────────────────────
  async getProjectScopes(projectId: string | number, params?: Record<string, any>) {
    const response = await apiClient.get(`/api/project/projects/${projectId}/scopes/`, { params })
    return response.data
  },
  async createProjectScope(projectId: string | number, data: Record<string, any>) {
    const response = await apiClient.post(`/api/project/projects/${projectId}/scopes/`, data)
    return response.data
  },
  async deleteProjectScope(projectId: string | number, scopeId: string | number) {
    const response = await apiClient.delete(`/api/project/projects/${projectId}/scopes/${scopeId}/`)
    return response.data
  },

  // ── Vulnerabilities ──────────────────────────────────────────────────────
  async getProjectVulnerabilities(projectId: string | number, params?: Record<string, any>) {
    const response = await apiClient.get(`/api/project/projects/${projectId}/vulnerabilities/`, { params })
    return response.data
  },
  async createVulnerability(data: Record<string, any>) {
    const projectId = data.project
    const response = await apiClient.post(`/api/project/projects/${projectId}/vulnerabilities/`, data)
    return response.data
  },
  async updateVulnerability(id: string | number, data: Record<string, any>) {
    const response = await apiClient.patch(`/api/project/vulnerabilities/${id}/`, data)
    return response.data
  },
  async deleteVulnerability(id: string | number) {
    const response = await apiClient.delete(`/api/project/vulnerabilities/${id}/`)
    return response.data
  },

  // ── Vulnerable Instances (affected assets per vuln) ──────────────────────
  async getVulnerabilityInstances(vulnId: string | number) {
    const response = await apiClient.get(`/api/project/vulnerabilities/${vulnId}/instances/`)
    return response.data
  },
  async createVulnerabilityInstance(vulnId: string | number, data: Record<string, any>) {
    const response = await apiClient.post(`/api/project/vulnerabilities/${vulnId}/instances/`, data)
    return response.data
  },
  async updateVulnerabilityInstance(vulnId: string | number, instanceId: string | number, data: Record<string, any>) {
    const response = await apiClient.patch(`/api/project/vulnerabilities/${vulnId}/instances/${instanceId}/`, data)
    return response.data
  },
  async deleteVulnerabilityInstance(vulnId: string | number, instanceId: string | number) {
    const response = await apiClient.delete(`/api/project/vulnerabilities/${vulnId}/instances/${instanceId}/`)
    return response.data
  },

  // ── Project-level instances (all assets) ─────────────────────────────────
  async getProjectInstances(projectId: string | number) {
    const response = await apiClient.get(`/api/project/projects/${projectId}/instances/`)
    return response.data
  },

  // ── Scope editing & Nmap upload ──────────────────────────────────────────
  async updateProjectScope(projectId: string | number, scopeId: string | number, data: Record<string, any>) {
    const response = await apiClient.patch(`/api/project/projects/${projectId}/scopes/${scopeId}/`, data)
    return response.data
  },
  async uploadNmapScope(projectId: string | number, formData: FormData) {
    const response = await apiClient.post(
      `/api/project/projects/${projectId}/scopes/upload-nmap/`,
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' } }
    )
    return response.data
  },

  // ── Vulnerability stats ───────────────────────────────────────────────────
  async getVulnerabilityStats(projectId: string | number) {
    const response = await apiClient.get(`/api/project/projects/${projectId}/vulnerabilities/statistics/`)
    return response.data
  },

  // ── Vulnerability Library (read-only; populated via GitHub sync) ────────
  async getVulnDB(params?: Record<string, any>) {
    const { search, page, page_size, ...rest } = params || {}
    const limit = page_size || 20
    const offset = page && page > 1 ? (page - 1) * limit : 0
    const query: Record<string, any> = { ...rest, limit, offset }
    if (search) query.vulnerabilityname = search
    const response = await apiClient.get('/api/vulndb/vulnerabilities/database/filter/', { params: query })
    return response.data
  },
  async syncVulnDB() {
    const response = await apiClient.post('/api/vulndb/vulnerabilities/database/sync/')
    return response.data
  },

  // ── Scanner ──────────────────────────────────────────────────────────────
  async getSupportedScanners() {
    const response = await apiClient.get('/api/project/parser/scanners/')
    return response.data
  },
  async uploadProjectScan(projectId: string | number, formData: FormData) {
    const response = await apiClient.post(
      `/api/project/projects/${projectId}/parser/upload/`,
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' } }
    )
    return response.data
  },

  // ── Config (read-only; populated via GitHub sync) ───────────────────────
  async getProjectTypes(params?: Record<string, any>) {
    const response = await apiClient.get('/api/config/project-types/', { params })
    return response.data
  },
  async syncProjectTypes() {
    const response = await apiClient.post('/api/config/project-types/sync/')
    return response.data
  },
  async getReportStandards(params?: Record<string, any>) {
    const response = await apiClient.get('/api/config/report-standards/', { params })
    return response.data
  },
  async syncReportStandards() {
    const response = await apiClient.post('/api/config/report-standards/sync/')
    return response.data
  },
}

export const api = apiClient
export default standardizedApiClient
