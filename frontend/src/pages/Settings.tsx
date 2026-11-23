import { useState, useEffect } from 'react'
import { authApi, alertsApi } from '../services/api'
import { useAuthStore } from '../stores/authStore'
import {
  User,
  Shield,
  Bell,
  Key,
  Save,
  Eye,
  EyeOff,
  Check,
  AlertTriangle,
  Info
} from 'lucide-react'

interface DetectionRule {
  id: string
  name: string
  description: string
  severity: string
  is_enabled: boolean
  threshold: number | null
  time_window: number | null
}

export default function Settings() {
  const { user } = useAuthStore()
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'detection'>('profile')
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // Password change form
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPasswords, setShowPasswords] = useState(false)

  useEffect(() => {
    if (activeTab === 'detection') {
      fetchRules()
    }
  }, [activeTab])

  const fetchRules = async () => {
    try {
      const res = await alertsApi.getRules()
      // API returns { rules: [...] }
      const rulesData = res.data?.rules || res.data || []
      setRules(Array.isArray(rulesData) ? rulesData : [])
    } catch (error) {
      console.error('Failed to fetch rules:', error)
      setRules([])
    }
  }

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    setMessage(null)

    if (newPassword !== confirmPassword) {
      setMessage({ type: 'error', text: 'New passwords do not match' })
      return
    }

    if (newPassword.length < 8) {
      setMessage({ type: 'error', text: 'Password must be at least 8 characters' })
      return
    }

    setLoading(true)
    try {
      await authApi.changePassword(currentPassword, newPassword)
      setMessage({ type: 'success', text: 'Password changed successfully' })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (error: any) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Failed to change password' 
      })
    } finally {
      setLoading(false)
    }
  }

  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      await alertsApi.updateRule(ruleId, { is_enabled: enabled })
      setRules(rules.map(r => 
        r.id === ruleId ? { ...r, is_enabled: enabled } : r
      ))
    } catch (error) {
      console.error('Failed to update rule:', error)
    }
  }

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Key },
    { id: 'detection', label: 'Detection Rules', icon: Shield },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-400 mt-1">Manage your account and application preferences</p>
      </div>

      <div className="flex gap-6">
        {/* Sidebar */}
        <div className="w-48 flex-shrink-0">
          <nav className="space-y-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-left transition-colors ${
                  activeTab === tab.id
                    ? 'bg-blue-600/20 text-blue-400'
                    : 'text-gray-400 hover:bg-dark-hover hover:text-white'
                }`}
              >
                <tab.icon className="w-5 h-5" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1">
          {activeTab === 'profile' && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h2 className="text-lg font-medium text-white mb-6 flex items-center gap-2">
                <User className="w-5 h-5 text-blue-400" />
                Profile Information
              </h2>

              <div className="space-y-4 max-w-md">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Username</label>
                  <input
                    type="text"
                    value={user?.username || ''}
                    disabled
                    className="w-full px-4 py-2 bg-dark-hover border border-dark-border rounded-lg text-gray-400"
                  />
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1">Role</label>
                  <div className="flex items-center gap-2">
                    <span className={`px-3 py-1.5 rounded-lg text-sm ${
                      user?.isAdmin 
                        ? 'bg-blue-500/20 text-blue-400' 
                        : 'bg-gray-500/20 text-gray-400'
                    }`}>
                      {user?.isAdmin ? 'Administrator' : 'Viewer'}
                    </span>
                  </div>
                </div>

                <div className="pt-4 border-t border-dark-border">
                  <div className="flex items-start gap-3 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                    <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-blue-400 font-medium">About Roles</p>
                      <p className="text-sm text-gray-400 mt-1">
                        <strong>Admin:</strong> Full access to all features including packet capture, 
                        network scanning, and configuration changes.
                      </p>
                      <p className="text-sm text-gray-400 mt-1">
                        <strong>Viewer:</strong> Read-only access to dashboard, alerts, and historical data.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h2 className="text-lg font-medium text-white mb-6 flex items-center gap-2">
                <Key className="w-5 h-5 text-blue-400" />
                Change Password
              </h2>

              {message && (
                <div className={`mb-4 p-4 rounded-lg flex items-center gap-3 ${
                  message.type === 'success' 
                    ? 'bg-green-500/10 border border-green-500/30' 
                    : 'bg-red-500/10 border border-red-500/30'
                }`}>
                  {message.type === 'success' ? (
                    <Check className="w-5 h-5 text-green-400" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                  )}
                  <span className={message.type === 'success' ? 'text-green-400' : 'text-red-400'}>
                    {message.text}
                  </span>
                </div>
              )}

              <form onSubmit={handlePasswordChange} className="space-y-4 max-w-md">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Current Password</label>
                  <div className="relative">
                    <input
                      type={showPasswords ? 'text' : 'password'}
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      required
                      className="w-full px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1">New Password</label>
                  <input
                    type={showPasswords ? 'text' : 'password'}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    minLength={8}
                    className="w-full px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1">Confirm New Password</label>
                  <div className="relative">
                    <input
                      type={showPasswords ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                      className="w-full px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:outline-none focus:border-blue-500"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswords(!showPasswords)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"
                    >
                      {showPasswords ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  <Save className="w-4 h-4" />
                  {loading ? 'Saving...' : 'Change Password'}
                </button>
              </form>

              <div className="mt-6 pt-6 border-t border-dark-border">
                <div className="flex items-start gap-3 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                  <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm text-yellow-400 font-medium">Security Reminder</p>
                    <p className="text-sm text-gray-400 mt-1">
                      Use a strong, unique password with at least 8 characters including 
                      uppercase, lowercase, numbers, and special characters.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'detection' && (
            <div className="bg-dark-card rounded-xl border border-dark-border p-6">
              <h2 className="text-lg font-medium text-white mb-2 flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-400" />
                Detection Rules
              </h2>
              <p className="text-sm text-gray-400 mb-6">
                Configure which security threats to monitor and alert on
              </p>

              <div className="space-y-4">
                {rules.length === 0 ? (
                  <p className="text-gray-400 text-center py-8">Loading rules...</p>
                ) : (
                  rules.map((rule) => (
                    <div
                      key={rule.id}
                      className={`p-4 rounded-lg border transition-colors ${
                        rule.is_enabled 
                          ? 'bg-dark-hover border-dark-border' 
                          : 'bg-dark-bg border-dark-border opacity-60'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3">
                            <h3 className="font-medium text-white">{rule.name}</h3>
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                              rule.severity === 'critical' 
                                ? 'bg-red-500/20 text-red-400'
                                : rule.severity === 'warning'
                                  ? 'bg-yellow-500/20 text-yellow-400'
                                  : 'bg-blue-500/20 text-blue-400'
                            }`}>
                              {rule.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-gray-400 mt-1">{rule.description}</p>
                          {(rule.threshold || rule.time_window) && (
                            <div className="flex gap-4 mt-2 text-xs text-gray-500">
                              {rule.threshold && (
                                <span>Threshold: {rule.threshold}</span>
                              )}
                              {rule.time_window && (
                                <span>Window: {rule.time_window}s</span>
                              )}
                            </div>
                          )}
                        </div>
                        
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={rule.is_enabled}
                            onChange={(e) => handleToggleRule(rule.id, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-11 h-6 bg-dark-border peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                        </label>
                      </div>
                    </div>
                  ))
                )}
              </div>

              <div className="mt-6 pt-6 border-t border-dark-border">
                <div className="flex items-start gap-3 p-4 bg-dark-hover rounded-lg">
                  <Bell className="w-5 h-5 text-gray-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm text-gray-300 font-medium">Alert Behavior</p>
                    <p className="text-sm text-gray-400 mt-1">
                      When a rule is triggered, an alert will be created with a detailed 
                      explanation of what was detected and why it might be suspicious. 
                      Alerts include rate limiting to prevent flooding during sustained attacks.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
