import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use((config) => {
  // First check axios defaults (set by authStore on login)
  if (api.defaults.headers.common['Authorization']) {
    config.headers.Authorization = api.defaults.headers.common['Authorization']
    return config
  }
  
  // Fallback: read from localStorage
  const authData = localStorage.getItem('netmonitor-auth')
  if (authData) {
    try {
      const { state } = JSON.parse(authData)
      if (state?.token) {
        config.headers.Authorization = `Bearer ${state.token}`
        console.debug('[API] Using token from localStorage')
      }
    } catch (e) {
      console.warn('[API] Failed to parse auth data')
    }
  }
  return config
})

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.warn('[API] 401 Unauthorized - clearing auth state')
      // Clear stored auth
      localStorage.removeItem('netmonitor-auth')
      delete api.defaults.headers.common['Authorization']
      // Redirect to login if not already there
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export default api

// Auth API
export const authApi = {
  login: (username: string, password: string) => 
    api.post('/auth/token', new URLSearchParams({ username, password }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }),
  me: () => api.get('/auth/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post('/auth/change-password', { current_password: currentPassword, new_password: newPassword }),
}

// API functions
export const dashboardApi = {
  getSummary: () => api.get('/dashboard/summary'),
  getTrafficStats: () => api.get('/dashboard/traffic-stats'),
  getTopTalkers: (limit = 10) => api.get(`/dashboard/top-talkers?limit=${limit}`),
  getRecentActivity: (limit = 20) => api.get(`/dashboard/recent-activity?limit=${limit}`),
  getSecurityScore: () => api.get('/dashboard/security-score'),
}

export const packetsApi = {
  getInterfaces: () => api.get('/packets/interfaces'),
  startCapture: (data: { interface?: string; bpf_filter?: string }) => 
    api.post('/packets/start', data),
  stopCapture: () => api.post('/packets/stop'),
  getStatus: () => api.get('/packets/status'),
  getPackets: (params: { limit?: number; protocol?: string; source_ip?: string }) => 
    api.get('/packets/packets', { params }),
  getStats: () => api.get('/packets/stats'),
  getProtocols: () => api.get('/packets/protocols'),
  clearBuffer: () => api.post('/packets/clear'),
}

export const scannerApi = {
  startScan: (data: { target: string; scan_type: string; ports?: string }) =>
    api.post('/scanner/scan', data),
  getScan: (scanId: string) => api.get(`/scanner/scan/${scanId}`),
  getScanStatus: (scanId: string) => api.get(`/scanner/scan/${scanId}`),
  listScans: (status?: string) => api.get('/scanner/scans', { params: { status } }),
  cancelScan: (scanId: string) => api.post(`/scanner/scan/${scanId}/cancel`),
  stopScan: (scanId: string) => api.post(`/scanner/scan/${scanId}/cancel`),
  getScanTypes: () => api.get('/scanner/scan-types'),
  getCommonPorts: () => api.get('/scanner/common-ports'),
  validateTarget: (target: string) => api.get('/scanner/validate-target', { params: { target } }),
}

export const alertsApi = {
  getAlerts: (params: { 
    limit?: number; 
    severity?: string; 
    acknowledged?: boolean;
    source_ip?: string;
  }) => api.get('/alerts/', { params }),
  getAlert: (alertId: number) => api.get(`/alerts/${alertId}`),
  getStats: () => api.get('/alerts/stats'),
  getSummary: (hours = 24) => api.get(`/alerts/summary?hours=${hours}`),
  acknowledge: (alertId: number) => api.post(`/alerts/${alertId}/acknowledge`),
  acknowledgeAll: (severity?: string) => api.post('/alerts/acknowledge-all', { severity }),
  deleteAlert: (alertId: number) => api.delete(`/alerts/${alertId}`),
  clearAlerts: (acknowledgedOnly = true) => 
    api.post(`/alerts/clear?acknowledged_only=${acknowledgedOnly}`),
  getRules: () => api.get('/alerts/rules/list'),
  updateRule: (ruleId: string, data: { is_enabled?: boolean; threshold?: number }) =>
    api.patch(`/alerts/rules/${ruleId}`, data),
}

export const networkApi = {
  getHosts: () => api.get('/network/hosts'),
  getDiscoveredHosts: () => api.get('/network/hosts'),
  getArpCache: () => api.get('/network/arp-cache'),
  getConnections: () => api.get('/network/connections'),
  getTopology: () => api.get('/network/topology'),
  getLocalInfo: () => api.get('/network/local-info'),
}
