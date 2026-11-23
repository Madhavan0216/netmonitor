/**
 * NetMonitor Design System
 * 
 * A professional SOC-grade design system.
 * Philosophy: Clean > flashy, Density > emptiness, Color = meaning
 */

// ============================================================================
// SEMANTIC COLORS - Every color has meaning
// ============================================================================

export const colors = {
  // Severity - consistent across all components
  severity: {
    critical: {
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
      text: 'text-red-400',
      dot: 'bg-red-500',
      hex: '#ef4444',
    },
    warning: {
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/30',
      text: 'text-amber-400',
      dot: 'bg-amber-500',
      hex: '#f59e0b',
    },
    info: {
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/30',
      text: 'text-blue-400',
      dot: 'bg-blue-500',
      hex: '#3b82f6',
    },
    success: {
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      text: 'text-emerald-400',
      dot: 'bg-emerald-500',
      hex: '#10b981',
    },
  },

  // Protocols - Wireshark-inspired consistency
  protocol: {
    TCP: { bg: 'bg-blue-500/20', text: 'text-blue-400', hex: '#3b82f6' },
    UDP: { bg: 'bg-green-500/20', text: 'text-green-400', hex: '#22c55e' },
    ICMP: { bg: 'bg-purple-500/20', text: 'text-purple-400', hex: '#a855f7' },
    DNS: { bg: 'bg-amber-500/20', text: 'text-amber-400', hex: '#f59e0b' },
    HTTP: { bg: 'bg-cyan-500/20', text: 'text-cyan-400', hex: '#06b6d4' },
    HTTPS: { bg: 'bg-emerald-500/20', text: 'text-emerald-400', hex: '#10b981' },
    ARP: { bg: 'bg-pink-500/20', text: 'text-pink-400', hex: '#ec4899' },
    SSH: { bg: 'bg-indigo-500/20', text: 'text-indigo-400', hex: '#6366f1' },
    SMB: { bg: 'bg-orange-500/20', text: 'text-orange-400', hex: '#f97316' },
    RDP: { bg: 'bg-rose-500/20', text: 'text-rose-400', hex: '#f43f5e' },
    UNKNOWN: { bg: 'bg-gray-500/20', text: 'text-gray-400', hex: '#6b7280' },
  },

  // Risk levels for hosts
  risk: {
    high: { bg: 'bg-red-500/20', border: 'border-red-500/50', text: 'text-red-400' },
    medium: { bg: 'bg-amber-500/20', border: 'border-amber-500/50', text: 'text-amber-400' },
    low: { bg: 'bg-emerald-500/20', border: 'border-emerald-500/50', text: 'text-emerald-400' },
    unknown: { bg: 'bg-gray-500/20', border: 'border-gray-500/50', text: 'text-gray-400' },
  },

  // Attack phases (for correlation display)
  attackPhase: {
    reconnaissance: '#8b5cf6', // purple
    initial_access: '#f97316', // orange  
    lateral_movement: '#ef4444', // red
    persistence: '#dc2626', // darker red
    command_control: '#7c3aed', // violet
    exfiltration: '#be123c', // rose
  },
} as const

// ============================================================================
// TYPOGRAPHY - Information density without clutter
// ============================================================================

export const typography = {
  // Monospace for technical data
  mono: 'font-mono text-sm',
  monoSmall: 'font-mono text-xs',
  
  // Headers
  h1: 'text-2xl font-semibold text-white',
  h2: 'text-xl font-semibold text-white',
  h3: 'text-lg font-medium text-white',
  h4: 'text-base font-medium text-white',
  
  // Body
  body: 'text-sm text-gray-300',
  bodyMuted: 'text-sm text-gray-500',
  
  // Labels
  label: 'text-xs font-medium text-gray-400 uppercase tracking-wider',
  
  // Data
  dataValue: 'text-sm font-medium text-white',
  dataLabel: 'text-xs text-gray-500',
} as const

// ============================================================================
// SPACING - Consistent rhythm
// ============================================================================

export const spacing = {
  card: 'p-4',
  cardCompact: 'p-3',
  cardLarge: 'p-6',
  section: 'space-y-4',
  sectionLarge: 'space-y-6',
  inline: 'gap-2',
  inlineLarge: 'gap-4',
} as const

// ============================================================================
// COMPONENTS - Reusable patterns
// ============================================================================

export const components = {
  // Cards
  card: 'bg-[#141414] rounded-lg border border-[#262626]',
  cardHover: 'bg-[#141414] rounded-lg border border-[#262626] hover:border-[#3a3a3a] transition-colors',
  cardInteractive: 'bg-[#141414] rounded-lg border border-[#262626] hover:bg-[#1a1a1a] cursor-pointer transition-all',
  
  // Inputs
  input: 'w-full px-3 py-2 bg-[#0a0a0a] border border-[#262626] rounded-lg text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20',
  inputCompact: 'px-2 py-1.5 bg-[#0a0a0a] border border-[#262626] rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50',
  
  // Buttons
  btnPrimary: 'px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
  btnSecondary: 'px-4 py-2 bg-[#262626] hover:bg-[#333] text-white rounded-lg font-medium transition-colors',
  btnDanger: 'px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg font-medium transition-colors',
  btnGhost: 'px-3 py-2 hover:bg-[#262626] text-gray-400 hover:text-white rounded-lg transition-colors',
  btnIcon: 'p-2 hover:bg-[#262626] text-gray-400 hover:text-white rounded-lg transition-colors',
  
  // Tables
  table: 'w-full',
  tableHeader: 'text-left text-xs font-medium text-gray-500 uppercase tracking-wider py-3 px-4 border-b border-[#262626]',
  tableCell: 'py-3 px-4 text-sm text-gray-300 border-b border-[#1f1f1f]',
  tableRow: 'hover:bg-[#1a1a1a] transition-colors',
  
  // Badges
  badge: 'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
  badgePill: 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
  
  // Status dots
  statusDot: 'w-2 h-2 rounded-full',
  statusDotLarge: 'w-3 h-3 rounded-full',
  
  // Tooltips
  tooltip: 'absolute z-50 px-2 py-1 text-xs bg-[#262626] text-white rounded shadow-lg border border-[#333]',
} as const

// ============================================================================
// ANIMATIONS - Motion only when informative
// ============================================================================

export const animations = {
  // Pulse for active/live states
  pulse: 'animate-pulse',
  
  // Fade in for new items
  fadeIn: 'animate-[fadeIn_0.2s_ease-out]',
  
  // Slide for panels
  slideIn: 'animate-[slideIn_0.2s_ease-out]',
  
  // Flow animation for network edges (CSS custom)
  flow: 'animate-[flow_1s_linear_infinite]',
} as const

// ============================================================================
// KEYBOARD SHORTCUTS (Expert mode)
// ============================================================================

export const shortcuts = {
  global: {
    search: 'Ctrl+K',
    toggleMode: 'Ctrl+Shift+M',
    dashboard: 'Alt+1',
    packets: 'Alt+2',
    scanner: 'Alt+3',
    alerts: 'Alt+4',
    network: 'Alt+5',
  },
  packets: {
    startCapture: 'Space',
    stopCapture: 'Escape',
    clearBuffer: 'Ctrl+L',
    filter: '/',
  },
  alerts: {
    acknowledgeSelected: 'A',
    deleteSelected: 'Delete',
    expandDetails: 'Enter',
  },
  networkMap: {
    zoomIn: '+',
    zoomOut: '-',
    resetView: '0',
    fitToScreen: 'F',
  },
} as const

// ============================================================================
// LAYOUT CONSTANTS
// ============================================================================

export const layout = {
  sidebarWidth: 256,
  sidebarCollapsedWidth: 64,
  headerHeight: 56,
  panelMinWidth: 320,
  tableRowHeight: 48,
  compactTableRowHeight: 36,
} as const

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Get severity styling
 */
export function getSeverityStyle(severity: string) {
  const s = severity.toLowerCase()
  if (s === 'critical') return colors.severity.critical
  if (s === 'warning') return colors.severity.warning
  if (s === 'info') return colors.severity.info
  return colors.severity.info
}

/**
 * Get protocol styling
 */
export function getProtocolStyle(protocol: string) {
  const p = protocol.toUpperCase()
  return colors.protocol[p as keyof typeof colors.protocol] || colors.protocol.UNKNOWN
}

/**
 * Get risk level styling
 */
export function getRiskStyle(riskScore: number) {
  if (riskScore >= 70) return colors.risk.high
  if (riskScore >= 40) return colors.risk.medium
  if (riskScore > 0) return colors.risk.low
  return colors.risk.unknown
}

/**
 * Format bytes to human readable
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

/**
 * Format duration in ms to human readable
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
  return `${Math.floor(ms / 3600000)}h ${Math.floor((ms % 3600000) / 60000)}m`
}

/**
 * Truncate IP for display in tight spaces
 */
export function truncateIP(ip: string, maxLength = 15): string {
  if (ip.length <= maxLength) return ip
  return ip.substring(0, maxLength - 2) + '…'
}

/**
 * Get attack phase display info
 */
export function getAttackPhaseInfo(phase: string) {
  const phases: Record<string, { label: string; color: string; description: string }> = {
    reconnaissance: {
      label: 'Reconnaissance',
      color: colors.attackPhase.reconnaissance,
      description: 'Gathering information about the target'
    },
    initial_access: {
      label: 'Initial Access',
      color: colors.attackPhase.initial_access,
      description: 'Attempting to gain entry to the network'
    },
    lateral_movement: {
      label: 'Lateral Movement',
      color: colors.attackPhase.lateral_movement,
      description: 'Moving between systems within the network'
    },
    persistence: {
      label: 'Persistence',
      color: colors.attackPhase.persistence,
      description: 'Maintaining access to compromised systems'
    },
    command_control: {
      label: 'Command & Control',
      color: colors.attackPhase.command_control,
      description: 'Communicating with compromised systems'
    },
    exfiltration: {
      label: 'Exfiltration',
      color: colors.attackPhase.exfiltration,
      description: 'Stealing data from the network'
    },
  }
  return phases[phase] || { label: phase, color: '#6b7280', description: 'Unknown attack phase' }
}
