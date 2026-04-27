import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || ''

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
})

// Inject JWT token on every request
api.interceptors.request.use(config => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Auto-refresh on 401
api.interceptors.response.use(
  r => r,
  async error => {
    if (error.response?.status === 401) {
      const refresh = localStorage.getItem('refresh_token')
      if (refresh) {
        try {
          const { data } = await axios.post(`${API_BASE}/api/auth/refresh`, { refresh_token: refresh })
          localStorage.setItem('access_token', data.access_token)
          localStorage.setItem('refresh_token', data.refresh_token)
          error.config.headers.Authorization = `Bearer ${data.access_token}`
          return axios(error.config)
        } catch {
          localStorage.clear()
          window.location.href = '/login'
        }
      } else {
        localStorage.clear()
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

// ── Auth ──
export const authAPI = {
  login: (data) => api.post('/api/auth/login', data),
  register: (data) => api.post('/api/auth/register', data),
  me: () => api.get('/api/auth/me'),
  setupTOTP: () => api.post('/api/auth/totp/setup'),
  verifyTOTP: (token) => api.post('/api/auth/totp/verify', { token }),
  disableTOTP: (token) => api.delete('/api/auth/totp/disable', { data: { token } }),
  changePassword: (data) => api.post('/api/auth/change-password', data),
}

// ── Dashboard ──
export const dashboardAPI = {
  // Generic passthrough so components can do dashboardAPI.get('/path')
  get:  (path, config) => api.get(`/api${path}`, config),
  post: (path, data)   => api.post(`/api${path}`, data),

  // Named helpers
  overview: () => api.get('/api/dashboard/overview'),
  alerts: (params) => api.get('/api/alerts', { params }),
  acknowledgeAlert: (id) => api.patch(`/api/alerts/${id}/acknowledge`),
  resolveAlert: (id) => api.patch(`/api/alerts/${id}/resolve`),
  forecast: () => api.get('/api/ai/forecast'),
  insights: () => api.get('/api/ai/insights'),
  connections: () => api.get('/api/network/connections'),
  blockedIPs: () => api.get('/api/blocked-ips'),
  blockIP: (ip, reason) => api.post('/api/blocked-ips', { ip_address: ip, reason }),
  unblockIP: (id) => api.delete(`/api/blocked-ips/${id}`),
  auditLog: () => api.get('/api/audit-log'),

  // FIM
  fimStatus:     () => api.get('/api/fim/status'),
  fimEvents:     (limit = 100) => api.get(`/api/fim/events?limit=${limit}`),
  fimScan:       () => api.post('/api/fim/scan'),
  fimRebaseline: () => api.post('/api/fim/rebaseline'),

  // Vulnerabilities
  vulnSummary:   () => api.get('/api/vulns/summary'),
  vulnFindings:  (params) => api.get('/api/vulns/findings', { params }),
  vulnScan:      () => api.post('/api/vulns/scan'),

  // Hardening
  hardeningSummary: () => api.get('/api/hardening/summary'),
  hardeningReport:  () => api.get('/api/hardening/report'),
  hardeningAudit:   () => api.post('/api/hardening/audit'),

  // Honeypot
  honeypotStats:     () => api.get('/api/honeypot/stats'),
  honeypotProbes:    (limit = 50) => api.get(`/api/honeypot/probes?limit=${limit}`),
  honeypotClusters:  () => api.get('/api/honeypot/clusters'),
  honeypotAttackers: (limit = 10) => api.get(`/api/honeypot/attackers?limit=${limit}`),

  // Federated Learning
  federatedStatus: () => api.get('/api/federated/status'),
  federatedEnable: (enabled) => api.post('/api/federated/enable', { enabled }),

  // System update — longer timeout: response can take a few seconds while
  // the server runs pre-flight chmod steps before releasing the event loop.
  systemVersion: () => api.get('/api/system/version'),
  systemUpdate:  () => api.post('/api/system/update', null, { timeout: 30000 }),
}

// ── WebSocket ──
export function createWebSocket(onMessage, onError) {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${window.location.host}/api/ws`)
  ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)) } catch {} }
  ws.onerror = onError || (() => {})
  ws.onclose = () => setTimeout(() => createWebSocket(onMessage, onError), 3000)
  return ws
}

// ── Helpers ──
export const formatBytes = (bytes, decimals = 1) => {
  if (!bytes) return '0 B'
  const k = 1024, dm = decimals < 0 ? 0 : decimals
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}

export const formatBytesPerSec = (bps) => `${formatBytes(bps)}/s`
