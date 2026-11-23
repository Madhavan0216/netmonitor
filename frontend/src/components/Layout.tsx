/**
 * Layout - Professional SOC-style Application Shell
 * 
 * Features:
 * - Collapsible sidebar with keyboard shortcut
 * - Beginner/Expert mode toggle
 * - Real-time system status indicator
 * - Keyboard shortcuts display (expert mode)
 * - Clean, professional navigation
 * - Legal consent banner (first use)
 */

import { useState, useEffect, useCallback } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'
import { useUIStore } from '../stores/uiStore'
import LegalConsentBanner from './LegalConsentBanner'
import {
  LayoutDashboard,
  Radio,
  Search,
  AlertTriangle,
  Network,
  Settings,
  LogOut,
  Menu,
  Shield,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Keyboard,
  GraduationCap,
  Zap,
  X
} from 'lucide-react'
import { clsx } from 'clsx'

// ============================================================================
// NAVIGATION CONFIG
// ============================================================================

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, shortcut: 'g d' },
  { name: 'Packet Explorer', href: '/packets', icon: Radio, shortcut: 'g p' },
  { name: 'Network Scanner', href: '/scanner', icon: Search, shortcut: 'g s' },
  { name: 'Alert Center', href: '/alerts', icon: AlertTriangle, shortcut: 'g a' },
  { name: 'Network Map', href: '/network', icon: Network, shortcut: 'g n' },
  { name: 'Settings', href: '/settings', icon: Settings, shortcut: 'g ,' },
]

// ============================================================================
// KEYBOARD SHORTCUTS
// ============================================================================

const GLOBAL_SHORTCUTS = [
  { keys: ['g', 'd'], description: 'Go to Dashboard' },
  { keys: ['g', 'p'], description: 'Go to Packet Explorer' },
  { keys: ['g', 's'], description: 'Go to Scanner' },
  { keys: ['g', 'a'], description: 'Go to Alerts' },
  { keys: ['g', 'n'], description: 'Go to Network Map' },
  { keys: ['?'], description: 'Show keyboard shortcuts' },
  { keys: ['b'], description: 'Toggle sidebar' },
  { keys: ['m'], description: 'Toggle mode (beginner/expert)' },
]

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Layout() {
  // State
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [showShortcuts, setShowShortcuts] = useState(false)
  const [pendingKey, setPendingKey] = useState<string | null>(null)
  
  // Stores
  const { user, logout } = useAuthStore()
  const { mode, setMode, sidebarCollapsed, setSidebarCollapsed } = useUIStore()
  const navigate = useNavigate()

  // ============================================================================
  // KEYBOARD SHORTCUTS
  // ============================================================================

  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    // Ignore if typing in an input
    if (
      event.target instanceof HTMLInputElement ||
      event.target instanceof HTMLTextAreaElement ||
      event.target instanceof HTMLSelectElement
    ) {
      return
    }

    const key = event.key.toLowerCase()
    
    // Handle '?' for shortcuts help
    if (key === '?' || (event.shiftKey && key === '/')) {
      event.preventDefault()
      setShowShortcuts(prev => !prev)
      return
    }
    
    // Handle 'b' for sidebar toggle
    if (key === 'b' && !pendingKey) {
      event.preventDefault()
      setSidebarCollapsed(!sidebarCollapsed)
      return
    }
    
    // Handle 'm' for mode toggle
    if (key === 'm' && !pendingKey) {
      event.preventDefault()
      setMode(mode === 'beginner' ? 'expert' : 'beginner')
      return
    }
    
    // Handle 'g' prefix for navigation
    if (key === 'g' && !pendingKey) {
      event.preventDefault()
      setPendingKey('g')
      setTimeout(() => setPendingKey(null), 1500)
      return
    }
    
    // Handle navigation shortcuts
    if (pendingKey === 'g') {
      event.preventDefault()
      setPendingKey(null)
      
      switch (key) {
        case 'd': navigate('/'); break
        case 'p': navigate('/packets'); break
        case 's': navigate('/scanner'); break
        case 'a': navigate('/alerts'); break
        case 'n': navigate('/network'); break
        case ',': navigate('/settings'); break
      }
    }
  }, [pendingKey, sidebarCollapsed, mode, navigate, setMode, setSidebarCollapsed])

  useEffect(() => {
    if (mode === 'expert') {
      window.addEventListener('keydown', handleKeyDown)
      return () => window.removeEventListener('keydown', handleKeyDown)
    }
  }, [mode, handleKeyDown])

  // ============================================================================
  // HANDLERS
  // ============================================================================

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const toggleMode = () => {
    setMode(mode === 'beginner' ? 'expert' : 'beginner')
  }

  // ============================================================================
  // RENDER
  // ============================================================================

  return (
    <div className="min-h-screen bg-[#0a0a0a]">
      {/* Legal Consent Banner - shows on first use */}
      <LegalConsentBanner />
      
      {/* Mobile sidebar backdrop */}
      {!sidebarCollapsed && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarCollapsed(true)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          'fixed inset-y-0 left-0 z-50 bg-[#0f0f0f] border-r border-[#1a1a1a] transform transition-all duration-200',
          sidebarCollapsed ? 'w-16' : 'w-64',
          'lg:translate-x-0',
          !sidebarCollapsed ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        )}
      >
        {/* Logo */}
        <div className={clsx(
          'flex items-center gap-3 border-b border-[#1a1a1a] transition-all',
          sidebarCollapsed ? 'px-3 py-4 justify-center' : 'px-5 py-4'
        )}>
          <div className="p-2 bg-gradient-to-br from-blue-600 to-blue-700 rounded-lg flex-shrink-0">
            <Shield className="w-5 h-5 text-white" />
          </div>
          {!sidebarCollapsed && (
            <div className="overflow-hidden">
              <h1 className="text-base font-semibold text-white">NetMonitor</h1>
              <p className="text-xs text-gray-500">Network Defense</p>
            </div>
          )}
        </div>

        {/* Mode toggle */}
        <div className={clsx(
          'border-b border-[#1a1a1a]',
          sidebarCollapsed ? 'p-2' : 'p-3'
        )}>
          <button
            onClick={toggleMode}
            className={clsx(
              'flex items-center gap-2 w-full rounded-lg transition-colors',
              sidebarCollapsed ? 'p-2 justify-center' : 'px-3 py-2',
              mode === 'beginner'
                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
            )}
            title={sidebarCollapsed ? `${mode === 'beginner' ? 'Beginner' : 'Expert'} Mode` : undefined}
          >
            {mode === 'beginner' ? (
              <GraduationCap className="w-4 h-4 flex-shrink-0" />
            ) : (
              <Zap className="w-4 h-4 flex-shrink-0" />
            )}
            {!sidebarCollapsed && (
              <span className="text-sm font-medium capitalize">{mode} Mode</span>
            )}
          </button>
        </div>

        {/* Navigation */}
        <nav className={clsx('py-4 space-y-1', sidebarCollapsed ? 'px-2' : 'px-3')}>
          {navigation.map((item) => (
            <NavLink
              key={item.name}
              to={item.href}
              onClick={() => {
                if (window.innerWidth < 1024) setSidebarCollapsed(true)
              }}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 rounded-lg transition-colors group relative',
                  sidebarCollapsed ? 'p-2.5 justify-center' : 'px-3 py-2.5',
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                    : 'text-gray-400 hover:bg-[#1a1a1a] hover:text-white border border-transparent'
                )
              }
              title={sidebarCollapsed ? item.name : undefined}
            >
              <item.icon className="w-5 h-5 flex-shrink-0" />
              {!sidebarCollapsed && (
                <>
                  <span className="font-medium text-sm flex-1">{item.name}</span>
                  {mode === 'expert' && item.shortcut && (
                    <span className="text-xs text-gray-600 font-mono">{item.shortcut}</span>
                  )}
                </>
              )}
              
              {/* Tooltip for collapsed state */}
              {sidebarCollapsed && (
                <div className="absolute left-full ml-2 px-2 py-1 bg-[#1a1a1a] text-white text-sm rounded opacity-0 group-hover:opacity-100 pointer-events-none whitespace-nowrap z-50 border border-[#262626]">
                  {item.name}
                </div>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Collapse toggle (desktop) */}
        <button
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          className="hidden lg:flex absolute -right-3 top-20 w-6 h-6 bg-[#1a1a1a] border border-[#262626] rounded-full items-center justify-center text-gray-400 hover:text-white hover:bg-[#262626] transition-colors"
        >
          {sidebarCollapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <ChevronLeft className="w-4 h-4" />
          )}
        </button>

        {/* User section */}
        <div className={clsx(
          'absolute bottom-0 left-0 right-0 border-t border-[#1a1a1a]',
          sidebarCollapsed ? 'p-2' : 'p-3'
        )}>
          <div className="relative">
            <button
              onClick={() => setUserMenuOpen(!userMenuOpen)}
              className={clsx(
                'flex items-center gap-3 w-full rounded-lg hover:bg-[#1a1a1a] transition-colors',
                sidebarCollapsed ? 'p-2 justify-center' : 'px-3 py-2'
              )}
            >
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center flex-shrink-0">
                <span className="text-sm font-medium text-white">
                  {user?.username?.charAt(0).toUpperCase()}
                </span>
              </div>
              {!sidebarCollapsed && (
                <>
                  <div className="flex-1 text-left overflow-hidden">
                    <p className="text-sm font-medium text-white truncate">{user?.username}</p>
                    <p className="text-xs text-gray-500">
                      {user?.isAdmin ? 'Administrator' : 'User'}
                    </p>
                  </div>
                  <ChevronDown className={clsx(
                    'w-4 h-4 text-gray-500 transition-transform',
                    userMenuOpen && 'rotate-180'
                  )} />
                </>
              )}
            </button>

            {userMenuOpen && (
              <div className={clsx(
                'absolute bottom-full mb-2 bg-[#141414] border border-[#262626] rounded-lg shadow-xl py-1 overflow-hidden',
                sidebarCollapsed ? 'left-full ml-2 w-48' : 'left-0 right-0'
              )}>
                <div className="px-3 py-2 border-b border-[#262626]">
                  <p className="text-sm text-white">{user?.username}</p>
                  <p className="text-xs text-gray-500">{user?.isAdmin ? 'Administrator' : 'User'}</p>
                </div>
                
                {mode === 'expert' && (
                  <button
                    onClick={() => {
                      setShowShortcuts(true)
                      setUserMenuOpen(false)
                    }}
                    className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-400 hover:bg-[#1a1a1a] hover:text-white"
                  >
                    <Keyboard className="w-4 h-4" />
                    Keyboard Shortcuts
                    <span className="ml-auto text-xs text-gray-600">?</span>
                  </button>
                )}
                
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-400 hover:bg-[#1a1a1a] hover:text-red-400"
                >
                  <LogOut className="w-4 h-4" />
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className={clsx(
        'transition-all duration-200',
        sidebarCollapsed ? 'lg:pl-16' : 'lg:pl-64'
      )}>
        {/* Top bar */}
        <header className="sticky top-0 z-30 bg-[#0a0a0a]/95 backdrop-blur-sm border-b border-[#1a1a1a]">
          <div className="flex items-center justify-between px-4 py-3">
            <div className="flex items-center gap-4">
              {/* Mobile menu button */}
              <button
                onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                className="p-2 rounded-lg hover:bg-[#1a1a1a] lg:hidden"
              >
                <Menu className="w-5 h-5 text-gray-400" />
              </button>
              
              {/* Pending key indicator */}
              {pendingKey && mode === 'expert' && (
                <div className="flex items-center gap-2 px-3 py-1.5 bg-blue-500/10 rounded-lg border border-blue-500/30">
                  <span className="text-sm text-blue-400">Waiting for key:</span>
                  <kbd className="px-2 py-0.5 bg-blue-500/20 rounded text-xs font-mono text-blue-300">
                    {pendingKey}
                  </kbd>
                </div>
              )}
            </div>

            <div className="flex items-center gap-3">
              {/* Keyboard shortcut hint (expert mode) */}
              {mode === 'expert' && (
                <button
                  onClick={() => setShowShortcuts(true)}
                  className="hidden md:flex items-center gap-2 px-2 py-1 text-xs text-gray-500 hover:text-gray-300 transition-colors"
                >
                  <Keyboard className="w-3.5 h-3.5" />
                  <span>Press</span>
                  <kbd className="px-1.5 py-0.5 bg-[#1a1a1a] rounded text-gray-400 font-mono">?</kbd>
                  <span>for shortcuts</span>
                </button>
              )}
              
              {/* Status indicator */}
              <div className="flex items-center gap-2 px-3 py-1.5 bg-[#141414] rounded-full border border-[#1a1a1a]">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <span className="text-sm text-gray-400">System Active</span>
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="p-6">
          <Outlet />
        </main>
      </div>

      {/* Keyboard shortcuts modal */}
      {showShortcuts && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
          <div 
            className="absolute inset-0 bg-black/70"
            onClick={() => setShowShortcuts(false)}
          />
          <div className="relative bg-[#141414] border border-[#262626] rounded-xl shadow-2xl max-w-lg w-full max-h-[80vh] overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#262626]">
              <div className="flex items-center gap-3">
                <Keyboard className="w-5 h-5 text-blue-400" />
                <h2 className="text-lg font-semibold text-white">Keyboard Shortcuts</h2>
              </div>
              <button
                onClick={() => setShowShortcuts(false)}
                className="p-1.5 rounded-lg hover:bg-[#262626] text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="p-5 space-y-4 overflow-y-auto max-h-[60vh]">
              <div>
                <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">
                  Navigation
                </h3>
                <div className="space-y-2">
                  {GLOBAL_SHORTCUTS.filter(s => s.keys[0] === 'g').map((shortcut, i) => (
                    <ShortcutRow key={i} shortcut={shortcut} />
                  ))}
                </div>
              </div>
              
              <div>
                <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">
                  General
                </h3>
                <div className="space-y-2">
                  {GLOBAL_SHORTCUTS.filter(s => s.keys[0] !== 'g').map((shortcut, i) => (
                    <ShortcutRow key={i} shortcut={shortcut} />
                  ))}
                </div>
              </div>
            </div>
            
            <div className="px-5 py-3 bg-[#0f0f0f] border-t border-[#262626]">
              <p className="text-xs text-gray-500 text-center">
                Shortcuts are only available in Expert mode
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// SUB-COMPONENTS
// ============================================================================

function ShortcutRow({ shortcut }: { shortcut: { keys: string[]; description: string } }) {
  return (
    <div className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-[#1a1a1a] transition-colors">
      <span className="text-sm text-gray-300">{shortcut.description}</span>
      <div className="flex items-center gap-1">
        {shortcut.keys.map((key, i) => (
          <span key={i} className="flex items-center gap-1">
            <kbd className="px-2 py-1 bg-[#262626] border border-[#333] rounded text-xs font-mono text-gray-300 min-w-[24px] text-center">
              {key}
            </kbd>
            {i < shortcut.keys.length - 1 && (
              <span className="text-gray-600 text-xs">then</span>
            )}
          </span>
        ))}
      </div>
    </div>
  )
}
