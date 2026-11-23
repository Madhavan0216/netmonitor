/**
 * Network Scanner - Educational & Safe Scanning Interface
 * 
 * Features:
 * - Explicit scope selection with safety warnings
 * - Real-time scan progress visualization
 * - Host discovery with OS fingerprinting
 * - Port scan results with service identification
 * - Beginner-friendly explanations
 */

import { useState, useEffect } from 'react'
import { scannerApi } from '../services/api'
import { 
  Search, 
  XCircle, 
  CheckCircle, 
  Clock,
  Server,
  AlertTriangle,
  Square,
  Wifi,
  Info,
  HelpCircle,
  Globe,
  Laptop,
  Smartphone,
  Router,
  Database,
  Lock,
  Unlock,
  Eye,
  Activity,
  Zap
} from 'lucide-react'
import { clsx } from 'clsx'
import { useUIStore } from '../stores/uiStore'
import { getRiskStyle, getProtocolStyle, components } from '../design-system'

// ============================================================================
// TYPES
// ============================================================================

interface ScanResult {
  scan_id: string
  scan_type: string
  target: string
  status: string
  progress: number
  hosts: HostResult[]
  start_time: string | null
  end_time: string | null
  error: string | null
  statistics: {
    hosts_up: number
    hosts_down: number
    total_hosts: number
    scan_time: string
  }
}

interface HostResult {
  ip_address: string
  hostname: string | null
  mac_address: string | null
  vendor: string | null
  state: string
  os_guess: string | null
  open_ports: PortInfo[]
  services: ServiceInfo[]
  risk_score?: number
}

interface PortInfo {
  port: number
  protocol: string
  state: string
}

interface ServiceInfo {
  port: number
  service: string
  product: string
  version: string
}

interface ScanType {
  id: string
  name: string
  description: string
  requires_root: boolean
  typical_duration: string
  use_case: string
  risk_level?: 'safe' | 'moderate' | 'aggressive'
}

// ============================================================================
// SCAN TYPE METADATA
// ============================================================================

const SCAN_TYPE_INFO: Record<string, { 
  icon: React.ReactNode
  riskLevel: 'safe' | 'moderate' | 'aggressive'
  shortDescription: string
  beginnerNote: string
}> = {
  ping: {
    icon: <Wifi className="w-4 h-4" />,
    riskLevel: 'safe',
    shortDescription: 'Quick host discovery',
    beginnerNote: 'Like knocking on doors to see who\'s home. Very quick and non-intrusive.'
  },
  quick: {
    icon: <Zap className="w-4 h-4" />,
    riskLevel: 'safe',
    shortDescription: 'Common ports scan',
    beginnerNote: 'Checks the 100 most common ports. Good for a quick overview.'
  },
  full: {
    icon: <Database className="w-4 h-4" />,
    riskLevel: 'moderate',
    shortDescription: 'All ports scan',
    beginnerNote: 'Scans all 65,535 ports. Takes longer but more thorough.'
  },
  service: {
    icon: <Server className="w-4 h-4" />,
    riskLevel: 'moderate',
    shortDescription: 'Service detection',
    beginnerNote: 'Identifies what software is running on open ports.'
  },
  os: {
    icon: <Laptop className="w-4 h-4" />,
    riskLevel: 'aggressive',
    shortDescription: 'OS fingerprinting',
    beginnerNote: 'Tries to identify operating systems. Sends unusual packets.'
  },
  stealth: {
    icon: <Eye className="w-4 h-4" />,
    riskLevel: 'aggressive',
    shortDescription: 'Stealthy SYN scan',
    beginnerNote: 'Harder to detect but requires admin privileges.'
  },
  aggressive: {
    icon: <AlertTriangle className="w-4 h-4" />,
    riskLevel: 'aggressive',
    shortDescription: 'Full assessment',
    beginnerNote: 'Comprehensive scan. May trigger security alerts on target systems.'
  }
}

// ============================================================================
// RISK LEVEL COLORS
// ============================================================================

const getRiskLevelStyle = (level: 'safe' | 'moderate' | 'aggressive') => {
  switch (level) {
    case 'safe':
      return { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' }
    case 'moderate':
      return { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' }
    case 'aggressive':
      return { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' }
  }
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function NetworkScanner() {
  // State
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('ping')
  const [ports, setPorts] = useState('')
  const [scanTypes, setScanTypes] = useState<ScanType[]>([])
  const [scans, setScans] = useState<ScanResult[]>([])
  const [activeScan, setActiveScan] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [targetValid, setTargetValid] = useState<boolean | null>(null)
  const [targetError, setTargetError] = useState('')
  const [showScanHistory, setShowScanHistory] = useState(false)
  const [selectedHost, setSelectedHost] = useState<HostResult | null>(null)
  const [confirmAggressive, setConfirmAggressive] = useState(false)
  
  // Store
  const { mode } = useUIStore()

  // ============================================================================
  // DATA FETCHING
  // ============================================================================

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchScans, 2000)
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      const [typesRes, scansRes] = await Promise.all([
        scannerApi.getScanTypes(),
        scannerApi.listScans(),
      ])
      // Handle APIResponse wrapper: { success, data: { scan_types: [...] } }
      const typesData = typesRes.data?.data ?? typesRes.data
      const scanTypesArray = typesData?.scan_types || typesData || []
      setScanTypes(Array.isArray(scanTypesArray) ? scanTypesArray : [])
      
      // Handle scans response
      const scansData = scansRes.data?.data ?? scansRes.data
      const scansArray = scansData?.scans || scansData || []
      setScans(Array.isArray(scansArray) ? scansArray : [])
    } catch (error) {
      console.error('Failed to fetch data:', error)
      setScanTypes([])
      setScans([])
    } finally {
      setLoading(false)
    }
  }

  const fetchScans = async () => {
    try {
      const response = await scannerApi.listScans()
      // Handle APIResponse wrapper
      const scansData = response.data?.data ?? response.data
      const scansArray = scansData?.scans || scansData || []
      setScans(Array.isArray(scansArray) ? scansArray : [])
      
      if (activeScan) {
        const scansList = Array.isArray(scansArray) ? scansArray : []
        const updated = scansList.find((s: ScanResult) => s.scan_id === activeScan.scan_id)
        if (updated) setActiveScan(updated)
      }
    } catch (error) {
      console.error('Failed to fetch scans:', error)
    }
  }

  // ============================================================================
  // VALIDATION
  // ============================================================================

  const validateTarget = async (value: string) => {
    if (!value) {
      setTargetValid(null)
      setTargetError('')
      return
    }

    try {
      const response = await scannerApi.validateTarget(value)
      // Handle APIResponse wrapper: { success, data: { valid, error, ... } }
      const validationData = response.data?.data ?? response.data
      const isValid = validationData?.valid ?? validationData?.is_valid ?? false
      const errorMsg = validationData?.error ?? validationData?.message ?? ''
      setTargetValid(isValid)
      setTargetError(isValid ? '' : errorMsg || 'Invalid target')
    } catch (error: any) {
      setTargetValid(false)
      setTargetError(error.response?.data?.detail || error.response?.data?.error || 'Validation failed')
    }
  }

  useEffect(() => {
    const timer = setTimeout(() => {
      if (target) validateTarget(target)
    }, 500)
    return () => clearTimeout(timer)
  }, [target])

  // ============================================================================
  // ACTIONS
  // ============================================================================

  const handleStartScan = async () => {
    // Safety check for aggressive scans
    const scanInfo = SCAN_TYPE_INFO[scanType]
    if (scanInfo?.riskLevel === 'aggressive' && !confirmAggressive) {
      setConfirmAggressive(true)
      return
    }
    
    setScanning(true)
    setConfirmAggressive(false)
    
    try {
      const params: any = {
        target,
        scan_type: scanType,
      }
      if (ports) params.ports = ports

      const response = await scannerApi.startScan(params)
      // Handle APIResponse wrapper: { success, data: ScanResult }
      const scanData = response.data?.data ?? response.data
      setActiveScan(scanData)
      fetchScans()
    } catch (error: any) {
      alert(error.response?.data?.detail || error.response?.data?.error || 'Failed to start scan')
    } finally {
      setScanning(false)
    }
  }

  const handleStopScan = async (scanId: string) => {
    try {
      await scannerApi.stopScan(scanId)
      if (activeScan?.scan_id === scanId) {
        setActiveScan(null)
      }
      fetchScans()
    } catch (error) {
      console.error('Failed to stop scan:', error)
    }
  }

  const handleViewScan = async (scanId: string) => {
    try {
      const response = await scannerApi.getScanStatus(scanId)
      // Handle APIResponse wrapper: { success, data: ScanResult }
      const scanData = response.data?.data ?? response.data
      setActiveScan(scanData)
    } catch (error) {
      console.error('Failed to load scan:', error)
    }
  }

  // ============================================================================
  // HELPERS
  // ============================================================================

  const selectedScanType = scanTypes.find(t => t.id === scanType)
  const scanInfo = SCAN_TYPE_INFO[scanType] || SCAN_TYPE_INFO.ping
  const riskStyle = getRiskLevelStyle(scanInfo.riskLevel)

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
          <h1 className="text-2xl font-semibold text-white">Network Scanner</h1>
          <p className="text-gray-500 mt-1">
            Discover hosts and services on your network
          </p>
        </div>
        
        <button
          onClick={() => setShowScanHistory(!showScanHistory)}
          className={clsx(
            'flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors text-sm',
            showScanHistory 
              ? 'bg-blue-500/10 border-blue-500/30 text-blue-400'
              : 'bg-[#1a1a1a] border-[#262626] text-gray-400 hover:bg-[#262626]'
          )}
        >
          <Clock className="w-4 h-4" />
          History ({scans.length})
        </button>
      </div>
      
      {/* Beginner explanation */}
      {mode === 'beginner' && (
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <Info className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-blue-200/70">
              <strong className="text-blue-300">Network Scanning Basics:</strong> This tool 
              discovers devices on your network and checks what services they're running. 
              <strong className="text-orange-300"> Only scan networks you own or have permission 
              to scan</strong> – scanning others' networks without consent may be illegal.
            </div>
          </div>
        </div>
      )}

      {/* Confirmation dialog for aggressive scans */}
      {confirmAggressive && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0" />
            <div className="flex-1">
              <h3 className="text-red-400 font-semibold">Aggressive Scan Warning</h3>
              <p className="text-red-300/70 text-sm mt-1">
                This scan type sends unusual packets that may trigger security alerts on the target 
                system and may be detected by IDS/IPS systems. Only proceed if you have authorization 
                to scan this target.
              </p>
              <div className="flex gap-2 mt-3">
                <button
                  onClick={() => setConfirmAggressive(false)}
                  className="px-3 py-1.5 bg-[#262626] text-gray-300 rounded-lg hover:bg-[#333] transition-colors text-sm"
                >
                  Cancel
                </button>
                <button
                  onClick={handleStartScan}
                  className="px-3 py-1.5 bg-red-600 text-white rounded-lg hover:bg-red-500 transition-colors text-sm"
                >
                  I Understand, Start Scan
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scan configuration */}
      <div className="bg-[#141414] rounded-lg border border-[#262626] p-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Target input */}
          <div className="lg:col-span-2">
            <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">
              Target
              {mode === 'beginner' && (
                <span className="ml-2 text-blue-400/70 normal-case tracking-normal">
                  IP address, hostname, or CIDR range
                </span>
              )}
            </label>
            <div className="relative">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g., 192.168.1.0/24 or 10.0.0.1"
                className={clsx(
                  components.input,
                  'pr-10 font-mono',
                  targetValid === false && 'border-red-500/50 focus:border-red-500'
                )}
              />
              {targetValid !== null && (
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  {targetValid ? (
                    <CheckCircle className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                </div>
              )}
            </div>
            {targetError && (
              <p className="text-xs text-red-400 mt-1">{targetError}</p>
            )}
          </div>
          
          {/* Custom ports */}
          <div>
            <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">
              Ports (optional)
            </label>
            <input
              type="text"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder="e.g., 22,80,443 or 1-1000"
              className={clsx(components.input, 'font-mono')}
            />
          </div>
        </div>
        
        {/* Scan type selection */}
        <div className="mt-4">
          <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
            Scan Type
          </label>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
            {scanTypes.map((type) => {
              const info = SCAN_TYPE_INFO[type.id] || SCAN_TYPE_INFO.ping
              const style = getRiskLevelStyle(info.riskLevel)
              const isSelected = scanType === type.id
              
              return (
                <button
                  key={type.id}
                  onClick={() => setScanType(type.id)}
                  className={clsx(
                    'relative p-3 rounded-lg border text-left transition-all',
                    isSelected 
                      ? `${style.bg} ${style.border}` 
                      : 'bg-[#0f0f0f] border-[#262626] hover:bg-[#1a1a1a]'
                  )}
                >
                  <div className={clsx(
                    'flex items-center gap-2 mb-1',
                    isSelected ? style.text : 'text-gray-400'
                  )}>
                    {info.icon}
                    <span className="font-medium text-sm">{type.name}</span>
                  </div>
                  <p className="text-xs text-gray-500 line-clamp-1">
                    {info.shortDescription}
                  </p>
                  
                  {/* Risk indicator */}
                  <div className={clsx(
                    'absolute top-2 right-2 w-2 h-2 rounded-full',
                    info.riskLevel === 'safe' && 'bg-emerald-400',
                    info.riskLevel === 'moderate' && 'bg-yellow-400',
                    info.riskLevel === 'aggressive' && 'bg-red-400'
                  )} />
                </button>
              )
            })}
          </div>
          
          {/* Selected scan info */}
          {selectedScanType && (
            <div className={clsx(
              'mt-3 p-3 rounded-lg border',
              riskStyle.bg,
              riskStyle.border
            )}>
              <div className="flex items-start gap-3">
                <div className={clsx('p-2 rounded-lg', riskStyle.bg)}>
                  {scanInfo.icon}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className={clsx('font-medium', riskStyle.text)}>
                      {selectedScanType.name}
                    </h4>
                    <span className={clsx(
                      'px-2 py-0.5 rounded text-xs font-medium',
                      riskStyle.bg,
                      riskStyle.text
                    )}>
                      {scanInfo.riskLevel}
                    </span>
                    <span className="text-xs text-gray-500">
                      ~{selectedScanType.typical_duration}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mt-1">
                    {mode === 'beginner' ? scanInfo.beginnerNote : selectedScanType.description}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
        
        {/* Start button */}
        <div className="mt-4 flex items-center justify-between">
          <div className="text-xs text-gray-500">
            {activeScan && activeScan.status === 'running' && (
              <span className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                Scan in progress: {activeScan.target}
              </span>
            )}
          </div>
          
          <button
            onClick={handleStartScan}
            disabled={!targetValid || scanning || (activeScan?.status === 'running')}
            className={clsx(
              'flex items-center gap-2 px-6 py-2.5 rounded-lg font-medium transition-colors',
              'disabled:opacity-50 disabled:cursor-not-allowed',
              scanInfo.riskLevel === 'aggressive'
                ? 'bg-red-600 hover:bg-red-500 text-white'
                : 'bg-blue-600 hover:bg-blue-500 text-white'
            )}
          >
            {scanning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Starting...
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                Start Scan
              </>
            )}
          </button>
        </div>
      </div>

      {/* Scan history */}
      {showScanHistory && scans.length > 0 && (
        <div className="bg-[#141414] rounded-lg border border-[#262626] overflow-hidden">
          <div className="px-4 py-3 border-b border-[#262626]">
            <h3 className="text-sm font-medium text-white">Scan History</h3>
          </div>
          <div className="divide-y divide-[#1a1a1a] max-h-48 overflow-y-auto">
            {scans.map((scan) => (
              <div
                key={scan.scan_id}
                onClick={() => handleViewScan(scan.scan_id)}
                className={clsx(
                  'flex items-center gap-4 px-4 py-3 cursor-pointer transition-colors',
                  activeScan?.scan_id === scan.scan_id ? 'bg-blue-500/10' : 'hover:bg-[#1a1a1a]'
                )}
              >
                <ScanStatusIcon status={scan.status} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white truncate">{scan.target}</p>
                  <p className="text-xs text-gray-500">{scan.scan_type} scan</p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-gray-400">
                    {scan.statistics?.hosts_up || 0} hosts
                  </p>
                  {scan.status === 'running' && (
                    <div className="flex items-center gap-2 mt-1">
                      <div className="w-16 h-1 bg-[#262626] rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-blue-500 rounded-full transition-all"
                          style={{ width: `${scan.progress}%` }}
                        />
                      </div>
                      <span className="text-xs text-blue-400">{scan.progress}%</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active scan results */}
      {activeScan && (
        <div className="space-y-4">
          {/* Scan header */}
          <div className="flex items-center justify-between bg-[#141414] rounded-lg border border-[#262626] p-4">
            <div className="flex items-center gap-4">
              <ScanStatusIcon status={activeScan.status} size="lg" />
              <div>
                <h3 className="text-lg font-medium text-white">{activeScan.target}</h3>
                <p className="text-sm text-gray-500">
                  {activeScan.scan_type} scan • 
                  {activeScan.statistics && ` ${activeScan.statistics.hosts_up} hosts up`}
                  {activeScan.statistics?.scan_time && ` • ${activeScan.statistics.scan_time}`}
                </p>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              {activeScan.status === 'running' && (
                <>
                  <div className="flex items-center gap-2">
                    <div className="w-24 h-2 bg-[#262626] rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-blue-500 rounded-full transition-all duration-300"
                        style={{ width: `${activeScan.progress}%` }}
                      />
                    </div>
                    <span className="text-sm text-blue-400 font-mono w-12">
                      {activeScan.progress}%
                    </span>
                  </div>
                  <button
                    onClick={() => handleStopScan(activeScan.scan_id)}
                    className="flex items-center gap-2 px-3 py-1.5 bg-red-600/20 text-red-400 rounded-lg hover:bg-red-600/30 transition-colors text-sm"
                  >
                    <Square className="w-4 h-4" />
                    Stop
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Error display */}
          {activeScan.error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
                <div>
                  <h4 className="text-red-400 font-medium">Scan Error</h4>
                  <p className="text-red-300/70 text-sm mt-1">{activeScan.error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Host results */}
          {activeScan.hosts && activeScan.hosts.length > 0 ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Host list */}
              <div className="bg-[#0f0f0f] rounded-lg border border-[#262626] overflow-hidden">
                <div className="px-4 py-3 border-b border-[#262626] flex items-center justify-between">
                  <h3 className="text-sm font-medium text-white">
                    Discovered Hosts ({activeScan.hosts.length})
                  </h3>
                </div>
                
                <div className="divide-y divide-[#1a1a1a] max-h-[500px] overflow-y-auto">
                  {activeScan.hosts.map((host) => (
                    <HostRow
                      key={host.ip_address}
                      host={host}
                      isSelected={selectedHost?.ip_address === host.ip_address}
                      onClick={() => setSelectedHost(host)}
                      mode={mode}
                    />
                  ))}
                </div>
              </div>
              
              {/* Host details */}
              {selectedHost ? (
                <HostDetails host={selectedHost} mode={mode} />
              ) : (
                <div className="bg-[#0f0f0f] rounded-lg border border-[#262626] flex flex-col items-center justify-center p-8">
                  <Server className="w-12 h-12 text-gray-600 mb-4" />
                  <p className="text-gray-500">Select a host to view details</p>
                </div>
              )}
            </div>
          ) : activeScan.status === 'completed' ? (
            <div className="bg-[#0f0f0f] rounded-lg border border-[#262626] flex flex-col items-center justify-center py-16">
              <Globe className="w-12 h-12 text-gray-600 mb-4" />
              <h3 className="text-lg font-medium text-gray-400">No Hosts Found</h3>
              <p className="text-gray-500 text-sm mt-1">
                No responsive hosts were discovered in the target range
              </p>
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// SUB-COMPONENTS
// ============================================================================

function ScanStatusIcon({ status, size = 'sm' }: { status: string; size?: 'sm' | 'lg' }) {
  const sizeClass = size === 'lg' ? 'w-10 h-10' : 'w-8 h-8'
  const iconSize = size === 'lg' ? 'w-5 h-5' : 'w-4 h-4'
  
  switch (status) {
    case 'running':
      return (
        <div className={clsx(sizeClass, 'rounded-full bg-blue-500/20 flex items-center justify-center')}>
          <Activity className={clsx(iconSize, 'text-blue-400 animate-pulse')} />
        </div>
      )
    case 'completed':
      return (
        <div className={clsx(sizeClass, 'rounded-full bg-emerald-500/20 flex items-center justify-center')}>
          <CheckCircle className={clsx(iconSize, 'text-emerald-400')} />
        </div>
      )
    case 'error':
    case 'failed':
      return (
        <div className={clsx(sizeClass, 'rounded-full bg-red-500/20 flex items-center justify-center')}>
          <XCircle className={clsx(iconSize, 'text-red-400')} />
        </div>
      )
    case 'stopped':
      return (
        <div className={clsx(sizeClass, 'rounded-full bg-yellow-500/20 flex items-center justify-center')}>
          <Square className={clsx(iconSize, 'text-yellow-400')} />
        </div>
      )
    default:
      return (
        <div className={clsx(sizeClass, 'rounded-full bg-gray-500/20 flex items-center justify-center')}>
          <Clock className={clsx(iconSize, 'text-gray-400')} />
        </div>
      )
  }
}

function HostRow({ 
  host, 
  isSelected, 
  onClick,
  mode 
}: { 
  host: HostResult
  isSelected: boolean
  onClick: () => void
  mode: 'beginner' | 'expert'
}) {
  const openPorts = host.open_ports?.length || 0
  const riskStyle = host.risk_score !== undefined ? getRiskStyle(host.risk_score) : null
  
  return (
    <div
      onClick={onClick}
      className={clsx(
        'flex items-center gap-4 px-4 py-3 cursor-pointer transition-colors',
        isSelected ? 'bg-blue-500/10' : 'hover:bg-[#1a1a1a]'
      )}
    >
      <div className="flex-shrink-0">
        <HostIcon vendor={host.vendor} osGuess={host.os_guess} />
      </div>
      
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="text-sm font-mono text-white">{host.ip_address}</p>
          {host.state === 'up' && (
            <span className="w-2 h-2 rounded-full bg-emerald-400" title="Host is up" />
          )}
          {riskStyle && host.risk_score !== undefined && host.risk_score >= 40 && (
            <span className={clsx('px-1.5 py-0.5 rounded text-xs', riskStyle.bg, riskStyle.text)}>
              {host.risk_score}% risk
            </span>
          )}
        </div>
        <p className="text-xs text-gray-500 truncate">
          {host.hostname || host.vendor || 'Unknown host'}
        </p>
      </div>
      
      <div className="text-right">
        <p className={clsx(
          'text-sm font-medium',
          openPorts > 0 ? 'text-blue-400' : 'text-gray-500'
        )}>
          {openPorts} port{openPorts !== 1 ? 's' : ''}
        </p>
        {host.os_guess && mode === 'expert' && (
          <p className="text-xs text-gray-500 truncate max-w-24">{host.os_guess}</p>
        )}
      </div>
    </div>
  )
}

function HostIcon({ vendor, osGuess }: { vendor: string | null; osGuess: string | null }) {
  // Determine icon based on vendor/OS
  const os = (osGuess || vendor || '').toLowerCase()
  
  if (os.includes('router') || os.includes('cisco') || os.includes('mikrotik')) {
    return <Router className="w-6 h-6 text-purple-400" />
  }
  if (os.includes('windows')) {
    return <Laptop className="w-6 h-6 text-blue-400" />
  }
  if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian')) {
    return <Server className="w-6 h-6 text-orange-400" />
  }
  if (os.includes('apple') || os.includes('mac') || os.includes('ios')) {
    return <Smartphone className="w-6 h-6 text-gray-400" />
  }
  if (os.includes('android')) {
    return <Smartphone className="w-6 h-6 text-emerald-400" />
  }
  
  return <Globe className="w-6 h-6 text-gray-500" />
}

function HostDetails({ host, mode }: { host: HostResult; mode: 'beginner' | 'expert' }) {
  return (
    <div className="bg-[#0f0f0f] rounded-lg border border-[#262626] overflow-hidden">
      <div className="px-4 py-3 border-b border-[#262626]">
        <div className="flex items-center gap-3">
          <HostIcon vendor={host.vendor} osGuess={host.os_guess} />
          <div>
            <h3 className="text-lg font-medium text-white font-mono">{host.ip_address}</h3>
            <p className="text-sm text-gray-500">
              {host.hostname || 'No hostname'} • {host.vendor || 'Unknown vendor'}
            </p>
          </div>
        </div>
      </div>
      
      <div className="p-4 space-y-4 max-h-[450px] overflow-y-auto">
        {/* Host info */}
        <div className="grid grid-cols-2 gap-4">
          <InfoCard label="MAC Address" value={host.mac_address || 'N/A'} mono />
          <InfoCard label="State" value={host.state} />
          <InfoCard label="OS Guess" value={host.os_guess || 'Unknown'} />
          <InfoCard label="Vendor" value={host.vendor || 'Unknown'} />
        </div>
        
        {/* Open ports */}
        {host.open_ports && host.open_ports.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
              Open Ports ({host.open_ports.length})
            </h4>
            <div className="space-y-1">
              {host.open_ports.map((port) => {
                const service = host.services?.find(s => s.port === port.port)
                const protocolStyle = getProtocolStyle(port.protocol.toUpperCase())
                
                return (
                  <div 
                    key={`${port.port}-${port.protocol}`}
                    className="flex items-center justify-between p-2 bg-[#141414] rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <span className={clsx(
                        'px-2 py-0.5 rounded text-xs font-mono',
                        protocolStyle.bg,
                        protocolStyle.text
                      )}>
                        {port.port}
                      </span>
                      <span className="text-sm text-gray-300">
                        {service?.service || 'unknown'}
                      </span>
                      {service?.product && (
                        <span className="text-xs text-gray-500">
                          {service.product} {service.version}
                        </span>
                      )}
                    </div>
                    
                    <div className="flex items-center gap-1">
                      {port.state === 'open' ? (
                        <Unlock className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <Lock className="w-4 h-4 text-yellow-400" />
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
        
        {/* Beginner port explanations */}
        {mode === 'beginner' && host.open_ports && host.open_ports.length > 0 && (
          <div className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg">
            <div className="flex items-start gap-2">
              <HelpCircle className="w-4 h-4 text-blue-400 mt-0.5" />
              <div className="text-xs text-blue-200/70">
                <strong className="text-blue-300">About Open Ports:</strong> Each open port 
                represents a service that accepts network connections. Common ports include 
                22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP). Unknown or unusual ports may 
                warrant investigation.
              </div>
            </div>
          </div>
        )}
        
        {/* No ports message */}
        {(!host.open_ports || host.open_ports.length === 0) && (
          <div className="text-center py-6 text-gray-500">
            <Lock className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No open ports detected</p>
            {mode === 'beginner' && (
              <p className="text-xs mt-1">
                This could mean the host has a firewall or no services running
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function InfoCard({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="p-3 bg-[#141414] rounded-lg">
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className={clsx('text-sm text-gray-300 truncate', mono && 'font-mono')}>
        {value}
      </p>
    </div>
  )
}
