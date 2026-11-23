import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import api from '../services/api'

interface User {
  username: string
  isAdmin: boolean
}

interface AuthState {
  token: string | null
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
  login: (username: string, password: string) => Promise<boolean>
  logout: () => void
  clearError: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      login: async (username: string, password: string) => {
        set({ isLoading: true, error: null })
        
        try {
          const formData = new URLSearchParams()
          formData.append('username', username)
          formData.append('password', password)
          
          const response = await api.post('/auth/token', formData, {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
          })
          
          const { access_token, username: user, is_admin } = response.data
          
          set({
            token: access_token,
            user: { username: user, isAdmin: is_admin },
            isAuthenticated: true,
            isLoading: false,
          })
          
          // Set default auth header
          api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`
          
          return true
        } catch (error: any) {
          const message = error.response?.data?.detail || 'Login failed'
          set({ error: message, isLoading: false })
          return false
        }
      },

      logout: () => {
        set({
          token: null,
          user: null,
          isAuthenticated: false,
        })
        delete api.defaults.headers.common['Authorization']
      },

      clearError: () => set({ error: null }),
    }),
    {
      name: 'netmonitor-auth',
      partialize: (state) => ({
        token: state.token,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)

// Initialize auth header on app load
const initializeAuth = () => {
  const stored = localStorage.getItem('netmonitor-auth')
  if (stored) {
    try {
      const { state } = JSON.parse(stored)
      if (state?.token) {
        // Check if token is expired (JWT exp claim)
        try {
          const payload = JSON.parse(atob(state.token.split('.')[1]))
          const expiry = payload.exp * 1000
          if (Date.now() > expiry) {
            console.warn('[Auth] Token expired, clearing auth state')
            localStorage.removeItem('netmonitor-auth')
            return
          }
        } catch {
          // Can't parse token, clear it
          console.warn('[Auth] Invalid token format, clearing auth state')
          localStorage.removeItem('netmonitor-auth')
          return
        }
        
        console.log('[Auth] Initializing with stored token')
        api.defaults.headers.common['Authorization'] = `Bearer ${state.token}`
      }
    } catch (e) {
      console.warn('[Auth] Failed to parse stored auth data')
      localStorage.removeItem('netmonitor-auth')
    }
  }
}

initializeAuth()
