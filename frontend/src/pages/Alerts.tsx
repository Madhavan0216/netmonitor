/**
 * Alert Center - Evidence-First Security Alert Management
 * 
 * Features:
 * - Evidence-first layout showing WHY alerts fired
 * - Attack phase timeline visualization
 * - Confidence indicators for all detections
 * - Quick actions with confirmation for destructive ops
 * - Beginner mode explanations
 */

import { useState, useEffect, useCallback } from 'react'
import { alertsApi } from '../services/api'
import { useAlertStream } from '../hooks/useWebSocket'
import { 
  AlertTriangle, 
  Info, 
  AlertCircle,
  Check,
  CheckCheck,
  Trash2,
  Clock,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Shield,
  Eye,
  Target,
  Wifi,
  WifiOff,
  ExternalLink,
  Search,
  Bell,
  BellOff,
  Zap
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { clsx } from 'clsx'
import { useUIStore } from '../stores/uiStore'
import { 
  getSeverityStyle,
  components 
} from '../design-system'

// ============================================================================
// TYPES
// ============================================================================

interface Alert {
  id: number
  severity: 'info' | 'warning' | 'critical'
  title: string
  description: string
  explanation: string
  source_ip: string | null
  destination_ip: string | null
  protocol: string | null
  port: number | null
  rule_id: string | null
  is_acknowledged: boolean
  acknowledged_by: string | null
  acknowledged_at: string | null
  created_at: string
  // Evidence fields (from detection system)
  evidence?: EvidenceItem[]
  confidence?: number
  attack_phase?: string
  mitre_tactics?: string[]
}

interface EvidenceItem {
  type: string
  description: string
  value: string | number | object
  weight: number
}

interface AlertStats {
  total_alerts: number
  info_count: number
  warning_count: number
  critical_count: number
  unacknowledged_count: number
  critical_unacknowledged: number
}

// ============================================================================
// ATTACK PHASE INFO
// ============================================================================

const ATTACK_PHASES: Record<string, { label: string; icon: React.ReactNode; color: string; description: string }> = {
  reconnaissance: {
    label: 'Reconnaissance',
    icon: <Eye className="w-4 h-4" />,
    color: 'text-blue-400',
    description: 'Attacker is gathering information about the network'
  },
  initial_access: {
    label: 'Initial Access',
    icon: <Target className="w-4 h-4" />,
    color: 'text-orange-400',
    description: 'Attacker is attempting to gain entry'
  },
  lateral_movement: {
    label: 'Lateral Movement',
    icon: <Wifi className="w-4 h-4" />,
    color: 'text-red-400',
    description: 'Attacker is moving between systems'
  },
  collection: {
    label: 'Collection',
    icon: <Shield className="w-4 h-4" />,
    color: 'text-purple-400',
    description: 'Attacker is gathering data'
  },
  exfiltration: {
    label: 'Exfiltration',
    icon: <ExternalLink className="w-4 h-4" />,
    color: 'text-red-500',
    description: 'Attacker is stealing data from network'
  },
  command_control: {
    label: 'Command & Control',
    icon: <Zap className="w-4 h-4" />,
    color: 'text-yellow-400',
    description: 'Attacker is communicating with compromised system'
  },
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Alerts() {
  // State
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [stats, setStats] = useState<AlertStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState('')
  const [acknowledgedFilter, setAcknowledgedFilter] = useState<'all' | 'unacknowledged' | 'acknowledged'>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedAlerts, setExpandedAlerts] = useState<Set<number>>(new Set())
  
  // Store
  const { mode, alertSoundEnabled, setAlertSoundEnabled } = useUIStore()

  // WebSocket for real-time alerts
  const { isConnected: wsConnected, alerts: wsAlerts } = useAlertStream({
    enabled: true
  })

  // Handle new alerts from WebSocket
  const handleNewAlert = useCallback((newAlert: any) => {
    // Play sound if enabled
    if (alertSoundEnabled && newAlert.severity === 'critical') {
      try {
        // Simple beep using Web Audio API
        const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)()
        const oscillator = audioContext.createOscillator()
        const gainNode = audioContext.createGain()
        oscillator.connect(gainNode)
        gainNode.connect(audioContext.destination)
        oscillator.frequency.value = 800
        gainNode.gain.value = 0.1
        oscillator.start()
        setTimeout(() => oscillator.stop(), 200)
      } catch (e) {
        // Audio not available
      }
    }
    
    // Prepend new alert to list
    setAlerts(prev => {
      // Convert WebSocket alert to local Alert format
      const alert: Alert = {
        id: Date.now(), // Temporary ID
        severity: newAlert.severity || 'info',
        title: newAlert.title || 'Alert',
        description: newAlert.description || '',
        explanation: newAlert.explanation || '',
        source_ip: newAlert.source_ip || null,
        destination_ip: newAlert.destination_ip || null,
        protocol: newAlert.protocol || null,
        port: newAlert.port || null,
        rule_id: newAlert.rule_id || newAlert.type || null,
        is_acknowledged: false,
        acknowledged_by: null,
        acknowledged_at: null,
        created_at: newAlert.timestamp || new Date().toISOString(),
        evidence: newAlert.evidence,
        confidence: newAlert.confidence
      }
      return [alert, ...prev].slice(0, 100) // Keep latest 100
    })
  }, [alertSoundEnabled])

  // Process WebSocket alerts
  useEffect(() => {
    if (wsAlerts.length > 0) {
      const latestAlert = wsAlerts[0]
      handleNewAlert(latestAlert)
    }
  }, [wsAlerts, handleNewAlert])

  // ============================================================================
  // DATA FETCHING
  // ============================================================================

  useEffect(() => {
    fetchData()
    // Poll less frequently when WebSocket is connected
    const pollInterval = wsConnected ? 15000 : 5000
    const interval = setInterval(fetchData, pollInterval)
    return () => clearInterval(interval)
  }, [severityFilter, acknowledgedFilter, wsConnected])

  const fetchData = async () => {
    try {
      const params: any = { limit: 100 }
      if (severityFilter) params.severity = severityFilter
      if (acknowledgedFilter !== 'all') {
        params.acknowledged = acknowledgedFilter === 'acknowledged'
      }

      const [alertsRes, statsRes] = await Promise.all([
        alertsApi.getAlerts(params),
        alertsApi.getStats(),
      ])
      
      // Handle APIResponse wrapper: { success, data: { alerts: [...] } }
      const alertsResponse = alertsRes.data
      let alertsArray: Alert[] = []
      
      if (Array.isArray(alertsResponse)) {
        alertsArray = alertsResponse
      } else if (alertsResponse?.data?.alerts && Array.isArray(alertsResponse.data.alerts)) {
        alertsArray = alertsResponse.data.alerts
      } else if (alertsResponse?.alerts && Array.isArray(alertsResponse.alerts)) {
        alertsArray = alertsResponse.alerts
      } else if (alertsResponse?.data && Array.isArray(alertsResponse.data)) {
        alertsArray = alertsResponse.data
      }
      
      setAlerts(alertsArray)
      
      // Handle stats response
      const statsData = statsRes.data?.data ?? statsRes.data
      setStats(statsData)
    } catch (error) {
      console.error('Failed to fetch alerts:', error)
      setAlerts([])
    } finally {
      setLoading(false)
    }
  }

  // ============================================================================
  // ACTIONS
  // ============================================================================

  const handleAcknowledge = async (alertId: number, e?: React.MouseEvent) => {
    e?.stopPropagation()
    try {
      await alertsApi.acknowledge(alertId)
      fetchData()
    } catch (error) {
      console.error('Failed to acknowledge alert:', error)
    }
  }

  const handleAcknowledgeAll = async () => {
    try {
      await alertsApi.acknowledgeAll(severityFilter || undefined)
      fetchData()
    } catch (error) {
      console.error('Failed to acknowledge all:', error)
    }
  }

  const handleDelete = async (alertId: number, e?: React.MouseEvent) => {
    e?.stopPropagation()
    if (!confirm('Delete this alert? This cannot be undone.')) return
    try {
      await alertsApi.deleteAlert(alertId)
      fetchData()
    } catch (error) {
      console.error('Failed to delete alert:', error)
    }
  }

  const handleClearAcknowledged = async () => {
    if (!confirm('Clear all acknowledged alerts? This cannot be undone.')) return
    try {
      await alertsApi.clearAlerts(true)
      fetchData()
    } catch (error) {
      console.error('Failed to clear alerts:', error)
    }
  }
  
  const toggleExpanded = (alertId: number) => {
    const newSet = new Set(expandedAlerts)
    if (newSet.has(alertId)) {
      newSet.delete(alertId)
    } else {
      newSet.add(alertId)
    }
    setExpandedAlerts(newSet)
  }

  // ============================================================================
  // FILTERING
  // ============================================================================

  const filteredAlerts = alerts.filter(alert => {
    if (!searchQuery) return true
    const query = searchQuery.toLowerCase()
    return (
      alert.title.toLowerCase().includes(query) ||
      alert.description.toLowerCase().includes(query) ||
      alert.source_ip?.toLowerCase().includes(query) ||
      alert.destination_ip?.toLowerCase().includes(query) ||
      alert.rule_id?.toLowerCase().includes(query)
    )
  })

  // Group by severity for summary
  const criticalAlerts = filteredAlerts.filter(a => a.severity === 'critical' && !a.is_acknowledged)

  // ============================================================================
  // RENDER
  // ============================================================================

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-10rem)]">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Alert Center</h1>
          <p className="text-gray-500 mt-1">
            Security events with evidence
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          {/* Sound toggle */}
          <button
            onClick={() => setAlertSoundEnabled(!alertSoundEnabled)}
            className={clsx(
              'p-2 rounded-lg border transition-colors',
              alertSoundEnabled
                ? 'bg-blue-500/10 border-blue-500/30 text-blue-400'
                : 'bg-[#1a1a1a] border-[#262626] text-gray-500'
            )}
            title={alertSoundEnabled ? 'Disable alert sounds' : 'Enable alert sounds'}
          >
            {alertSoundEnabled ? <Bell className="w-5 h-5" /> : <BellOff className="w-5 h-5" />}
          </button>
          
          <button
            onClick={fetchData}
            className="p-2 bg-[#1a1a1a] border border-[#262626] rounded-lg hover:bg-[#262626] transition-colors"
          >
            <RefreshCw className="w-5 h-5 text-gray-400" />
          </button>
          
          {/* WebSocket status */}
          <div className="flex items-center gap-1.5 px-2">
            {wsConnected ? (
              <>
                <Wifi className="w-4 h-4 text-emerald-400" />
                <span className="text-xs text-emerald-400">Live</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4 text-yellow-500" />
                <span className="text-xs text-yellow-500">Polling</span>
              </>
            )}
          </div>
        </div>
      </div>
      
      {/* Beginner explanation */}
      {mode === 'beginner' && (
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <Info className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-blue-200/70">
              <strong className="text-blue-300">Understanding Alerts:</strong> When suspicious network 
              activity is detected, an alert is created. Each alert shows <strong>why</strong> it was 
              triggered (evidence), how <strong>confident</strong> the system is, and what <strong>attack 
              phase</strong> it might represent. Acknowledge alerts after reviewing them.
            </div>
          </div>
        </div>
      )}

      {/* Critical banner */}
      {criticalAlerts.length > 0 && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <AlertCircle className="w-6 h-6 text-red-400" />
            <div className="flex-1">
              <h3 className="text-red-400 font-semibold">
                {criticalAlerts.length} Critical Alert{criticalAlerts.length !== 1 ? 's' : ''} Require Attention
              </h3>
              <p className="text-red-300/70 text-sm mt-0.5">
                These may indicate active threats to your network
              </p>
            </div>
            <button
              onClick={() => {
                setSeverityFilter('critical')
                setAcknowledgedFilter('unacknowledged')
              }}
              className="px-3 py-1.5 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-colors text-sm"
            >
              View Critical
            </button>
          </div>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Total"
          value={stats?.total_alerts || 0}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="text-white"
        />
        <StatCard
          label="Critical"
          value={stats?.critical_count || 0}
          icon={<AlertCircle className="w-5 h-5" />}
          color="text-red-400"
          bgColor="bg-red-500/5"
          highlight={(stats?.critical_unacknowledged ?? 0) > 0}
        />
        <StatCard
          label="Warning"
          value={stats?.warning_count || 0}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="text-yellow-400"
          bgColor="bg-yellow-500/5"
        />
        <StatCard
          label="Pending"
          value={stats?.unacknowledged_count || 0}
          icon={<Clock className="w-5 h-5" />}
          color="text-blue-400"
          bgColor="bg-blue-500/5"
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#141414] rounded-lg border border-[#262626] p-3">
        <div className="flex items-center gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search alerts..."
              className="pl-9 pr-4 py-2 w-64 bg-[#0f0f0f] border border-[#262626] rounded-lg text-white text-sm placeholder:text-gray-600 focus:outline-none focus:border-blue-500/50"
            />
          </div>
          
          {/* Severity filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className={clsx(components.input, 'w-40')}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>

          {/* Acknowledged filter */}
          <select
            value={acknowledgedFilter}
            onChange={(e) => setAcknowledgedFilter(e.target.value as any)}
            className={clsx(components.input, 'w-44')}
          >
            <option value="all">All Status</option>
            <option value="unacknowledged">Unacknowledged</option>
            <option value="acknowledged">Acknowledged</option>
          </select>
        </div>

        {/* Bulk actions */}
        <div className="flex items-center gap-2">
          {filteredAlerts.some(a => !a.is_acknowledged) && (
            <button
              onClick={handleAcknowledgeAll}
              className="flex items-center gap-2 px-3 py-2 bg-blue-500/10 text-blue-400 rounded-lg hover:bg-blue-500/20 transition-colors text-sm"
            >
              <CheckCheck className="w-4 h-4" />
              Acknowledge All
            </button>
          )}
          
          {filteredAlerts.some(a => a.is_acknowledged) && (
            <button
              onClick={handleClearAcknowledged}
              className="flex items-center gap-2 px-3 py-2 bg-[#262626] text-gray-400 rounded-lg hover:bg-[#333] transition-colors text-sm"
            >
              <Trash2 className="w-4 h-4" />
              Clear Acknowledged
            </button>
          )}
        </div>
      </div>

      {/* Alerts list */}
      <div className="space-y-2">
        {filteredAlerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 bg-[#0f0f0f] rounded-lg border border-[#262626]">
            <Shield className="w-12 h-12 text-gray-600 mb-4" />
            <h3 className="text-lg font-medium text-gray-400">No Alerts</h3>
            <p className="text-gray-500 text-sm mt-1">
              {searchQuery ? 'No alerts match your search' : 'Your network is looking secure'}
            </p>
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              isExpanded={expandedAlerts.has(alert.id)}
              onToggle={() => toggleExpanded(alert.id)}
              onAcknowledge={(e) => handleAcknowledge(alert.id, e)}
              onDelete={(e) => handleDelete(alert.id, e)}
              mode={mode}
            />
          ))
        )}
      </div>
    </div>
  )
}

// ============================================================================
// SUB-COMPONENTS
// ============================================================================

function StatCard({ 
  label, 
  value, 
  icon,
  color,
  bgColor,
  highlight = false 
}: { 
  label: string
  value: number
  icon: React.ReactNode
  color: string
  bgColor?: string
  highlight?: boolean
}) {
  return (
    <div className={clsx(
      'rounded-lg border p-4 transition-colors',
      bgColor || 'bg-[#141414]',
      highlight ? 'border-red-500/50 animate-pulse' : 'border-[#262626]'
    )}>
      <div className="flex items-center justify-between">
        <span className={clsx('opacity-60', color)}>{icon}</span>
        <span className={clsx('text-2xl font-semibold font-mono', color)}>
          {value.toLocaleString()}
        </span>
      </div>
      <p className="text-sm text-gray-500 mt-2">{label}</p>
    </div>
  )
}

function AlertCard({ 
  alert, 
  isExpanded, 
  onToggle, 
  onAcknowledge,
  onDelete,
  mode 
}: { 
  alert: Alert
  isExpanded: boolean
  onToggle: () => void
  onAcknowledge: (e?: React.MouseEvent) => void
  onDelete: (e?: React.MouseEvent) => void
  mode: 'beginner' | 'expert'
}) {
  const severityStyle = getSeverityStyle(alert.severity)
  const attackPhase = alert.attack_phase ? ATTACK_PHASES[alert.attack_phase] : null
  
  return (
    <div className={clsx(
      'rounded-lg border overflow-hidden transition-all',
      alert.is_acknowledged ? 'bg-[#0f0f0f] border-[#1a1a1a]' : 'bg-[#141414]',
      severityStyle.border
    )}>
      {/* Header */}
      <div
        onClick={onToggle}
        className="flex items-center gap-4 p-4 cursor-pointer hover:bg-[#1a1a1a] transition-colors"
      >
        {/* Expand arrow */}
        {isExpanded ? (
          <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
        )}
        
        {/* Severity icon */}
        <div className={clsx('flex-shrink-0', severityStyle.text)}>
          {alert.severity === 'critical' ? (
            <AlertCircle className="w-5 h-5" />
          ) : alert.severity === 'warning' ? (
            <AlertTriangle className="w-5 h-5" />
          ) : (
            <Info className="w-5 h-5" />
          )}
        </div>
        
        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className={clsx(
              'font-medium truncate',
              alert.is_acknowledged ? 'text-gray-400' : 'text-white'
            )}>
              {alert.title}
            </h3>
            
            {/* Badges */}
            <span className={clsx(
              'px-2 py-0.5 rounded text-xs font-medium',
              severityStyle.bg,
              severityStyle.text
            )}>
              {alert.severity}
            </span>
            
            {alert.confidence !== undefined && (
              <ConfidenceBadge confidence={alert.confidence} />
            )}
            
            {attackPhase && (
              <span className={clsx(
                'flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-[#262626]',
                attackPhase.color
              )}>
                {attackPhase.icon}
                {attackPhase.label}
              </span>
            )}
            
            {alert.is_acknowledged && (
              <span className="px-2 py-0.5 bg-[#262626] text-gray-500 rounded text-xs">
                Acknowledged
              </span>
            )}
          </div>
          
          {/* Meta info */}
          <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
            </span>
            
            {alert.source_ip && (
              <span className="font-mono">{alert.source_ip}</span>
            )}
            
            {alert.destination_ip && (
              <span className="font-mono">→ {alert.destination_ip}</span>
            )}
            
            {alert.rule_id && (
              <span className="opacity-60">Rule: {alert.rule_id}</span>
            )}
          </div>
        </div>
        
        {/* Actions */}
        <div className="flex items-center gap-1">
          {!alert.is_acknowledged && (
            <button
              onClick={onAcknowledge}
              className="p-2 text-gray-500 hover:text-green-400 hover:bg-green-500/10 rounded-lg transition-colors"
              title="Acknowledge"
            >
              <Check className="w-4 h-4" />
            </button>
          )}
          <button
            onClick={onDelete}
            className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
            title="Delete"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
      
      {/* Expanded content */}
      {isExpanded && (
        <div className="border-t border-[#262626] p-4 bg-[#0a0a0a]">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Description & Explanation */}
            <div className="space-y-4">
              <div>
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                  Description
                </h4>
                <p className="text-sm text-gray-300">{alert.description}</p>
              </div>
              
              {alert.explanation && (
                <div>
                  <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                    Why This Matters
                  </h4>
                  <p className="text-sm text-gray-400">{alert.explanation}</p>
                </div>
              )}
              
              {/* Attack phase explanation (beginner mode) */}
              {mode === 'beginner' && attackPhase && (
                <div className="p-3 bg-[#141414] rounded-lg border border-[#262626]">
                  <div className={clsx('flex items-center gap-2 mb-1', attackPhase.color)}>
                    {attackPhase.icon}
                    <span className="font-medium text-sm">{attackPhase.label}</span>
                  </div>
                  <p className="text-xs text-gray-500">{attackPhase.description}</p>
                </div>
              )}
            </div>
            
            {/* Evidence section */}
            <div>
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                Evidence
              </h4>
              
              {alert.evidence && alert.evidence.length > 0 ? (
                <div className="space-y-2">
                  {alert.evidence.map((item, index) => (
                    <EvidenceCard key={index} evidence={item} mode={mode} />
                  ))}
                </div>
              ) : (
                <div className="space-y-2">
                  {/* Construct evidence from alert fields */}
                  {alert.source_ip && (
                    <EvidenceCard
                      evidence={{
                        type: 'network',
                        description: 'Source IP address',
                        value: alert.source_ip,
                        weight: 0.5
                      }}
                      mode={mode}
                    />
                  )}
                  {alert.destination_ip && (
                    <EvidenceCard
                      evidence={{
                        type: 'network',
                        description: 'Destination IP address',
                        value: alert.destination_ip,
                        weight: 0.5
                      }}
                      mode={mode}
                    />
                  )}
                  {alert.protocol && (
                    <EvidenceCard
                      evidence={{
                        type: 'protocol',
                        description: 'Protocol used',
                        value: `${alert.protocol}${alert.port ? `:${alert.port}` : ''}`,
                        weight: 0.3
                      }}
                      mode={mode}
                    />
                  )}
                </div>
              )}
            </div>
          </div>
          
          {/* MITRE tactics */}
          {alert.mitre_tactics && alert.mitre_tactics.length > 0 && (
            <div className="mt-4 pt-4 border-t border-[#262626]">
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                MITRE ATT&CK Tactics
              </h4>
              <div className="flex flex-wrap gap-2">
                {alert.mitre_tactics.map((tactic, index) => (
                  <a
                    key={index}
                    href={`https://attack.mitre.org/tactics/${tactic}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 px-2 py-1 bg-purple-500/10 text-purple-400 rounded text-xs hover:bg-purple-500/20 transition-colors"
                  >
                    {tactic}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
  const percentage = Math.round(confidence * 100)
  let color = 'text-gray-400'
  if (percentage >= 80) color = 'text-emerald-400'
  else if (percentage >= 60) color = 'text-yellow-400'
  else if (percentage >= 40) color = 'text-orange-400'
  else color = 'text-red-400'
  
  return (
    <span className={clsx('text-xs font-mono', color)} title="Detection confidence">
      {percentage}%
    </span>
  )
}

function EvidenceCard({ evidence, mode }: { evidence: EvidenceItem; mode: 'beginner' | 'expert' }) {
  const weightPercentage = Math.round(evidence.weight * 100)
  
  return (
    <div className="p-3 bg-[#141414] rounded-lg border border-[#262626]">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <span className="text-xs text-gray-500">{evidence.type}</span>
          <p className="text-sm text-gray-300 mt-0.5">{evidence.description}</p>
          <code className="text-xs font-mono text-blue-400 mt-1 block">
            {typeof evidence.value === 'object' 
              ? JSON.stringify(evidence.value) 
              : String(evidence.value)
            }
          </code>
        </div>
        
        {/* Weight indicator */}
        <div className="flex items-center gap-1 ml-3" title={`Evidence weight: ${weightPercentage}%`}>
          <div className="w-16 h-1.5 bg-[#262626] rounded-full overflow-hidden">
            <div 
              className="h-full bg-blue-500 rounded-full"
              style={{ width: `${weightPercentage}%` }}
            />
          </div>
          {mode === 'expert' && (
            <span className="text-xs text-gray-500 font-mono">{weightPercentage}%</span>
          )}
        </div>
      </div>
    </div>
  )
}
