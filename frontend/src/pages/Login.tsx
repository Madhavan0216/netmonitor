import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'
import { Shield, AlertCircle, Eye, EyeOff } from 'lucide-react'
import { authApi } from '../services/api'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showDisclaimer, setShowDisclaimer] = useState(true)
  const [validatingToken, setValidatingToken] = useState(true)
  
  const { login, isLoading, error, isAuthenticated, clearError, logout } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    // Validate existing token before auto-redirecting
    const validateAndRedirect = async () => {
      if (isAuthenticated) {
        try {
          await authApi.me()
          // Token is valid, redirect to dashboard
          navigate('/')
        } catch {
          // Token is invalid, clear auth state
          logout()
        }
      }
      setValidatingToken(false)
    }
    
    validateAndRedirect()
  }, []) // Only run once on mount

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const success = await login(username, password)
    if (success) {
      navigate('/')
    }
  }

  // Show loading while validating token
  if (validatingToken) {
    return (
      <div className="min-h-screen bg-dark-bg flex items-center justify-center">
        <div className="text-gray-400">Loading...</div>
      </div>
    )
  }

  if (showDisclaimer) {
    return (
      <div className="min-h-screen bg-dark-bg flex items-center justify-center p-4">
        <div className="max-w-xl w-full bg-dark-card rounded-xl border border-dark-border p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-yellow-600 rounded-lg">
              <AlertCircle className="w-6 h-6 text-white" />
            </div>
            <h1 className="text-xl font-bold text-white">Legal & Ethical Disclaimer</h1>
          </div>

          <div className="space-y-4 text-gray-300 mb-8">
            <p>
              <strong className="text-white">Important:</strong> This tool is for{' '}
              <span className="text-blue-400">defensive and educational purposes only</span>.
            </p>
            
            <div className="bg-dark-bg rounded-lg p-4 border border-dark-border">
              <h3 className="font-medium text-white mb-2">Acceptable Use:</h3>
              <ul className="list-disc list-inside space-y-1 text-sm">
                <li>Monitoring your own home or business network</li>
                <li>Security auditing with written authorization</li>
                <li>Educational purposes in controlled lab environments</li>
                <li>Incident response on authorized systems</li>
              </ul>
            </div>

            <div className="bg-red-900/20 rounded-lg p-4 border border-red-900/50">
              <h3 className="font-medium text-red-400 mb-2">Prohibited Use:</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-red-300">
                <li>Monitoring networks without authorization</li>
                <li>Attacking or exploiting discovered vulnerabilities</li>
                <li>Intercepting private communications</li>
                <li>Any illegal activities</li>
              </ul>
            </div>

            <p className="text-sm text-gray-400">
              Unauthorized network monitoring may violate local, state, and federal laws 
              (CFAA, GDPR, etc.). Users are solely responsible for ensuring compliance 
              with all applicable laws and regulations.
            </p>
          </div>

          <button
            onClick={() => setShowDisclaimer(false)}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
          >
            I Understand and Accept
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-dark-bg flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center p-3 bg-blue-600 rounded-xl mb-4">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">NetMonitor</h1>
          <p className="text-gray-400 mt-1">Network Safety Monitoring Tool</p>
        </div>

        {/* Login form */}
        <div className="bg-dark-card rounded-xl border border-dark-border p-6">
          <h2 className="text-lg font-semibold text-white mb-6">Sign in to your account</h2>

          {error && (
            <div className="mb-4 p-3 bg-red-900/20 border border-red-900/50 rounded-lg flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-red-400" />
              <span className="text-sm text-red-400">{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value)
                  clearError()
                }}
                className="w-full px-4 py-2.5 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
                placeholder="Enter your username"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value)
                    clearError()
                  }}
                  className="w-full px-4 py-2.5 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors pr-10"
                  placeholder="Enter your password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <span className="spinner" />
                  Signing in...
                </>
              ) : (
                'Sign in'
              )}
            </button>
          </form>

          <div className="mt-6 pt-6 border-t border-dark-border">
            <p className="text-sm text-gray-400 text-center">
              Default credentials:{' '}
              <code className="px-1.5 py-0.5 bg-dark-bg rounded text-blue-400">admin</code> /{' '}
              <code className="px-1.5 py-0.5 bg-dark-bg rounded text-blue-400">changeme123</code>
            </p>
          </div>
        </div>

        <p className="text-center text-xs text-gray-500 mt-4">
          For defensive and educational purposes only
        </p>
      </div>
    </div>
  )
}
