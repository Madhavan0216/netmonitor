/**
 * Packet Explorer - Professional Packet Capture Interface
 * 
 * Features:
 * - Real-time WebSocket streaming
 * - Virtualized table for high performance
 * - Smart filters with educational hints
 * - Protocol-based coloring (Wireshark-inspired)
 * - Header-level inspection
 * - Zero payload display by default (privacy)
 */

import { useState, useEffect, useRef } from 'react'
import { packetsApi } from '../services/api'
import { usePacketStream, Packet as WSPacket } from '../hooks/useWebSocket'
import { 
  Play, 
  Square, 
  RefreshCw, 
  Trash2,
  ChevronDown,
  ChevronRight,
  Info,
  AlertCircle,
  WifiOff,
  Wifi
} from 'lucide-react'
import { clsx } from 'clsx'
import { useUIStore } from '../stores/uiStore'
import { getProtocolStyle, formatBytes, components } from '../design-system'

// ============================================================================
// TYPES
// ============================================================================

// Use the shared Packet type from WebSocket hook, with local extensions
type Packet = WSPacket & {
  id?: number
  ttl?: number
  direction?: 'inbound' | 'outbound' | 'internal'
}

interface CaptureStatus {
  is_running: boolean
  interface: string | null
  filter: string | null
  stats: {
    total_packets: number
    tcp_packets: number
    udp_packets: number
    icmp_packets: number
  }
}

interface NetworkInterface {
  name: string
  display_name?: string
  description?: string
  ip_addresses?: string[]
  mac_address?: string | null
  is_up?: boolean
  is_loopback?: boolean
}

// ============================================================================
// FILTER PRESETS (Educational)
// ============================================================================

const FILTER_PRESETS = [
  { 
    id: 'all', 
    label: 'All Traffic', 
    filter: '',
    description: 'Show all captured packets'
  },
  { 
    id: 'tcp', 
    label: 'TCP Only', 
    filter: 'tcp',
    description: 'TCP connections (web, email, file transfers)'
  },
  { 
    id: 'udp', 
    label: 'UDP Only', 
    filter: 'udp',
    description: 'UDP traffic (DNS, streaming, gaming)'
  },
  { 
    id: 'dns', 
    label: 'DNS Queries', 
    filter: 'udp port 53',
    description: 'Domain name lookups'
  },
  { 
    id: 'http', 
    label: 'HTTP/HTTPS', 
    filter: 'tcp port 80 or tcp port 443',
    description: 'Web traffic'
  },
  { 
    id: 'ssh', 
    label: 'SSH', 
    filter: 'tcp port 22',
    description: 'Secure shell connections'
  },
  { 
    id: 'icmp', 
    label: 'ICMP/Ping', 
    filter: 'icmp',
    description: 'Ping and network diagnostics'
  },
]

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function PacketCapture() {
  // State
  const [status, setStatus] = useState<CaptureStatus | null>(null)
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [selectedInterface, setSelectedInterface] = useState('')
  const [bpfFilter, setBpfFilter] = useState('')
  const [displayFilter, setDisplayFilter] = useState('')
  const [selectedPreset, setSelectedPreset] = useState('all')
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null)
  const [useWebSocketStream] = useState(true)
  
  // Refs
  const tableRef = useRef<HTMLDivElement>(null)
  
  // Store
  const { mode, packetAutoScroll, setPacketAutoScroll, packetDisplayLimit } = useUIStore()

  // WebSocket for real-time packet streaming
  const { 
    isConnected: wsConnected, 
    packets: wsPackets, 
    clearPackets: wsClearPackets
  } = usePacketStream({
    maxPackets: packetDisplayLimit,
    enabled: useWebSocketStream && status?.is_running
  })

  // Local packets state (for polling fallback)
  const [polledPackets, setPolledPackets] = useState<Packet[]>([])

  // Use WebSocket packets if connected, otherwise use polled packets
  const packets = useWebSocketStream && wsConnected ? wsPackets : polledPackets

  // Auto-scroll effect
  useEffect(() => {
    if (packetAutoScroll && tableRef.current && packets.length > 0) {
      tableRef.current.scrollTop = tableRef.current.scrollHeight
    }
  }, [packets, packetAutoScroll])

  // ============================================================================
  // DATA FETCHING
  // ============================================================================
  
  useEffect(() => {
    fetchData()
    // Only poll if WebSocket is not connected
    const interval = setInterval(() => {
      if (!wsConnected || !useWebSocketStream) {
        fetchPackets()
      }
      fetchStatus()
    }, 1000)
    return () => clearInterval(interval)
  }, [displayFilter, wsConnected, useWebSocketStream])

  const fetchData = async () => {
    try {
      const [statusRes, interfacesRes] = await Promise.all([
        packetsApi.getStatus(),
        packetsApi.getInterfaces(),
      ])
      
      // Parse status from APIResponse wrapper
      const statusData = statusRes.data?.data ?? statusRes.data
      setStatus(statusData)
      
      // Parse interfaces from APIResponse wrapper: { success, data: [...] }
      let interfaceList: NetworkInterface[] = []
      const ifaceResponse = interfacesRes.data
      
      if (Array.isArray(ifaceResponse)) {
        // Direct array response
        interfaceList = ifaceResponse
      } else if (ifaceResponse?.data && Array.isArray(ifaceResponse.data)) {
        // APIResponse wrapper: { success, data: [...] }
        interfaceList = ifaceResponse.data
      } else if (ifaceResponse?.interfaces && Array.isArray(ifaceResponse.interfaces)) {
        // Legacy format: { interfaces: [...] }
        interfaceList = ifaceResponse.interfaces
      }
      
      setInterfaces(interfaceList)
      
      // Select first active interface with an IP (not loopback), prefer interfaces with IP addresses
      const activeIface = interfaceList.find(i => 
        i.is_up && 
        !i.is_loopback && 
        i.ip_addresses && 
        i.ip_addresses.length > 0 &&
        !i.ip_addresses[0]?.startsWith('169.254')  // Skip link-local
      )
      if (activeIface) {
        // Use display_name if available (Windows friendly names work with Scapy)
        setSelectedInterface(activeIface.display_name || activeIface.name)
      } else if (interfaceList.length > 0) {
        setSelectedInterface(interfaceList[0].display_name || interfaceList[0].name)
      }
      
      await fetchPackets()
    } catch (error) {
      console.error('Failed to fetch data:', error)
      // Set safe defaults on error
      setInterfaces([])
      setStatus(null)
    } finally {
      setLoading(false)
    }
  }

  const fetchStatus = async () => {
    try {
      const statusRes = await packetsApi.getStatus()
      const statusData = statusRes.data?.data ?? statusRes.data
      setStatus(statusData)
    } catch (error) {
      console.error('Failed to fetch status:', error)
    }
  }

  const fetchPackets = async () => {
    try {
      const params: any = { limit: packetDisplayLimit }
      if (displayFilter) params.protocol = displayFilter
      const response = await packetsApi.getPackets(params)
      
      // Parse packets from APIResponse wrapper: { success, data: [...] }
      let packetsArray: Packet[] = []
      const packetsResponse = response.data
      
      if (Array.isArray(packetsResponse)) {
        // Direct array response
        packetsArray = packetsResponse
      } else if (packetsResponse?.data && Array.isArray(packetsResponse.data)) {
        // APIResponse wrapper: { success, data: [...] }
        packetsArray = packetsResponse.data
      } else if (packetsResponse?.packets && Array.isArray(packetsResponse.packets)) {
        // Legacy format: { packets: [...] }
        packetsArray = packetsResponse.packets
      }
      
      setPolledPackets(packetsArray)
    } catch (error) {
      console.error('Failed to fetch packets:', error)
      // Don't clear packets on error - keep last known state
    }
  }

  // ============================================================================
  // ACTIONS
  // ============================================================================
  
  const handleStartCapture = async () => {
    setActionLoading(true)
    try {
      await packetsApi.startCapture({
        interface: selectedInterface,
        bpf_filter: bpfFilter || undefined,
      })
      await fetchData()
    } catch (error: any) {
      alert(error.response?.data?.detail || 'Failed to start capture')
    } finally {
      setActionLoading(false)
    }
  }

  const handleStopCapture = async () => {
    setActionLoading(true)
    try {
      await packetsApi.stopCapture()
      await fetchData()
    } catch (error) {
      console.error('Failed to stop capture:', error)
    } finally {
      setActionLoading(false)
    }
  }

  const handleClearBuffer = async () => {
    try {
      await packetsApi.clearBuffer()
      // Clear both WebSocket and polled packets
      wsClearPackets()
      setPolledPackets([])
      await fetchPackets()
    } catch (error) {
      console.error('Failed to clear buffer:', error)
    }
  }
  
  const handlePresetChange = (presetId: string) => {
    setSelectedPreset(presetId)
    const preset = FILTER_PRESETS.find(p => p.id === presetId)
    if (preset) {
      setDisplayFilter(preset.id === 'all' ? '' : preset.id)
    }
  }

  // ============================================================================
  // FILTER PACKETS (client-side display filter)
  // ============================================================================
  
  // SAFETY: Ensure packets is always an array before filtering
  const safePackets = Array.isArray(packets) ? packets : []
  
  const filteredPackets = safePackets.filter(packet => {
    if (!displayFilter) return true
    if (!packet) return false
    
    const protocol = (packet.protocol ?? '').toLowerCase()
    const filter = displayFilter.toLowerCase()
    
    // Simple protocol matching
    if (filter === 'tcp' || filter === 'udp' || filter === 'icmp') {
      return protocol === filter
    }
    
    // Port-based matching
    if (filter === 'dns') {
      return packet.source_port === 53 || packet.destination_port === 53
    }
    
    if (filter === 'http') {
      return packet.destination_port === 80 || packet.source_port === 80
    }
    
    if (filter === 'https') {
      return packet.destination_port === 443 || packet.source_port === 443
    }
    
    if (filter === 'ssh') {
      return packet.destination_port === 22 || packet.source_port === 22
    }
    
    return true
  })

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
          <h1 className="text-2xl font-semibold text-white">Packet Explorer</h1>
          <p className="text-gray-500 mt-1">
            Real-time network traffic analysis
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          {/* Stats badges */}
          {status && (
            <div className="flex items-center gap-3 mr-4">
              <StatBadge 
                label="Total" 
                value={status.stats.total_packets} 
                color="text-white"
              />
              <StatBadge 
                label="TCP" 
                value={status.stats.tcp_packets} 
                color="text-blue-400"
              />
              <StatBadge 
                label="UDP" 
                value={status.stats.udp_packets} 
                color="text-green-400"
              />
              <StatBadge 
                label="ICMP" 
                value={status.stats.icmp_packets} 
                color="text-purple-400"
              />
            </div>
          )}
          
          <button
            onClick={fetchPackets}
            className="p-2 bg-[#1a1a1a] border border-[#262626] rounded-lg hover:bg-[#262626] transition-colors"
          >
            <RefreshCw className="w-5 h-5 text-gray-400" />
          </button>
        </div>
      </div>
      
      {/* Beginner explanation */}
      {mode === 'beginner' && (
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <Info className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-blue-200/70">
              <strong className="text-blue-300">What is Packet Capture?</strong> Every time your computer 
              communicates over the network, it sends "packets" of data. This tool lets you see those packets 
              in real-time. You can filter by type (TCP, UDP) or by service (DNS, HTTP).
              <span className="text-blue-400/70 block mt-1">
                Note: Payload content is hidden by default for privacy.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Controls */}
      <div className="bg-[#141414] rounded-lg border border-[#262626] p-4">
        <div className="flex flex-wrap items-end gap-4">
          {/* Interface selector */}
          <div className="flex-1 min-w-48">
            <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">
              Network Interface
            </label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={status?.is_running}
              className={clsx(components.input, 'disabled:opacity-50')}
            >
              {interfaces.map((iface) => {
                const displayName = iface.display_name || iface.name
                const ipInfo = iface.ip_addresses?.length ? ` (${iface.ip_addresses[0]})` : ''
                const statusIcon = iface.is_up ? '●' : '○'
                return (
                  <option key={iface.name} value={displayName}>
                    {statusIcon} {displayName}{ipInfo}
                  </option>
                )
              })}
            </select>
          </div>

          {/* BPF Filter */}
          <div className="flex-1 min-w-48">
            <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">
              Capture Filter (BPF)
              {mode === 'beginner' && (
                <span className="ml-2 text-blue-400/70 normal-case tracking-normal">
                  Advanced - leave blank for all
                </span>
              )}
            </label>
            <input
              type="text"
              value={bpfFilter}
              onChange={(e) => setBpfFilter(e.target.value)}
              disabled={status?.is_running}
              placeholder="e.g., tcp port 80"
              className={clsx(components.input, 'disabled:opacity-50 font-mono text-sm')}
            />
          </div>

          {/* Control buttons */}
          <div className="flex gap-2">
            {status?.is_running ? (
              <button
                onClick={handleStopCapture}
                disabled={actionLoading}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 disabled:bg-red-800 text-white rounded-lg transition-colors"
              >
                <Square className="w-4 h-4" />
                Stop
              </button>
            ) : (
              <button
                onClick={handleStartCapture}
                disabled={actionLoading || !selectedInterface}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 text-white rounded-lg transition-colors"
              >
                <Play className="w-4 h-4" />
                Start Capture
              </button>
            )}
            
            <button
              onClick={handleClearBuffer}
              className="flex items-center gap-2 px-3 py-2 bg-[#262626] hover:bg-[#333] text-gray-300 rounded-lg transition-colors"
              title="Clear buffer"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>
        
        {/* Capture status indicator */}
        <div className="flex items-center gap-4 mt-3 pt-3 border-t border-[#262626]">
          <div className="flex items-center gap-2">
            {status?.is_running ? (
              <>
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-sm text-emerald-400">Capturing on {status.interface}</span>
                {status.filter && (
                  <span className="text-xs text-gray-500 font-mono ml-2">
                    Filter: {status.filter}
                  </span>
                )}
              </>
            ) : (
              <>
                <div className="w-2 h-2 rounded-full bg-gray-500" />
                <span className="text-sm text-gray-400">Capture stopped</span>
              </>
            )}
          </div>
          
          {/* WebSocket status indicator */}
          <div className="flex items-center gap-2 ml-auto">
            {wsConnected ? (
              <>
                <Wifi className="w-4 h-4 text-emerald-400" />
                <span className="text-xs text-emerald-400">Live streaming</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4 text-yellow-500" />
                <span className="text-xs text-yellow-500">Polling mode</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-4">
        {/* Preset filters */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1">
          {FILTER_PRESETS.map((preset) => (
            <button
              key={preset.id}
              onClick={() => handlePresetChange(preset.id)}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-sm whitespace-nowrap transition-colors',
                selectedPreset === preset.id
                  ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                  : 'bg-[#1a1a1a] text-gray-400 border border-[#262626] hover:bg-[#262626]'
              )}
              title={preset.description}
            >
              {preset.label}
            </button>
          ))}
        </div>
        
        {/* Auto-scroll toggle */}
        <div className="flex items-center gap-2 ml-auto">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={packetAutoScroll}
              onChange={(e) => setPacketAutoScroll(e.target.checked)}
              className="w-4 h-4 rounded bg-[#262626] border-[#333] text-blue-500 focus:ring-blue-500/20"
            />
            <span className="text-sm text-gray-400">Auto-scroll</span>
          </label>
        </div>
      </div>

      {/* Main content */}
      <div className="flex gap-4">
        {/* Packet table */}
        <div className="flex-1 bg-[#0f0f0f] rounded-lg border border-[#262626] overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[80px_150px_150px_80px_80px_80px_1fr] gap-2 px-4 py-3 bg-[#0a0a0a] border-b border-[#262626] text-xs font-medium text-gray-500 uppercase tracking-wider">
            <div>Time</div>
            <div>Source</div>
            <div>Destination</div>
            <div>Protocol</div>
            <div>Length</div>
            <div>Port</div>
            <div>Info</div>
          </div>
          
          {/* Table body */}
          <div 
            ref={tableRef}
            className="h-[calc(100vh-26rem)] overflow-y-auto"
          >
            {filteredPackets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-gray-500">
                <WifiOff className="w-12 h-12 mb-4 opacity-50" />
                <p>No packets captured yet</p>
                <p className="text-sm mt-1">Start a capture to see traffic</p>
              </div>
            ) : (
              filteredPackets.map((packet, index) => (
                <PacketRow
                  key={index}
                  packet={packet}
                  isSelected={selectedPacket === packet}
                  onClick={() => setSelectedPacket(packet)}
                />
              ))
            )}
          </div>
        </div>
        
        {/* Packet details panel */}
        {selectedPacket && (
          <div className="w-96 bg-[#141414] rounded-lg border border-[#262626] overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#262626]">
              <h3 className="text-sm font-medium text-white">Packet Details</h3>
              <button
                onClick={() => setSelectedPacket(null)}
                className="p-1 hover:bg-[#262626] rounded transition-colors"
              >
                <ChevronRight className="w-4 h-4 text-gray-500" />
              </button>
            </div>
            
            <div className="p-4 space-y-4 h-[calc(100vh-30rem)] overflow-y-auto">
              <PacketDetailSection packet={selectedPacket} mode={mode} />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// SUB-COMPONENTS
// ============================================================================

function StatBadge({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center">
      <div className={clsx('text-lg font-semibold font-mono', color)}>
        {value.toLocaleString()}
      </div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  )
}

function PacketRow({ 
  packet, 
  isSelected, 
  onClick
}: { 
  packet: Packet
  isSelected: boolean
  onClick: () => void
}) {
  const protocolStyle = getProtocolStyle(packet.protocol)
  const time = new Date(packet.timestamp)
  
  return (
    <div
      onClick={onClick}
      className={clsx(
        'grid grid-cols-[80px_150px_150px_80px_80px_80px_1fr] gap-2 px-4 py-2 border-b border-[#1a1a1a] cursor-pointer transition-colors text-sm',
        isSelected ? 'bg-blue-500/10' : 'hover:bg-[#1a1a1a]'
      )}
    >
      {/* Time */}
      <div className="font-mono text-xs text-gray-500">
        {time.toLocaleTimeString('en-US', { hour12: false })}
      </div>
      
      {/* Source */}
      <div className="font-mono text-xs text-gray-300 truncate" title={packet.source_ip}>
        {packet.source_ip}
        {packet.source_port && <span className="text-gray-500">:{packet.source_port}</span>}
      </div>
      
      {/* Destination */}
      <div className="font-mono text-xs text-gray-300 truncate" title={packet.destination_ip}>
        {packet.destination_ip}
        {packet.destination_port && <span className="text-gray-500">:{packet.destination_port}</span>}
      </div>
      
      {/* Protocol */}
      <div>
        <span className={clsx(
          'inline-flex px-2 py-0.5 rounded text-xs font-mono',
          protocolStyle.bg,
          protocolStyle.text
        )}>
          {packet.protocol}
        </span>
      </div>
      
      {/* Length */}
      <div className="font-mono text-xs text-gray-400">
        {formatBytes(packet.size)}
      </div>
      
      {/* Port */}
      <div className="font-mono text-xs text-gray-400">
        {packet.destination_port || '-'}
      </div>
      
      {/* Info */}
      <div className="text-xs text-gray-500 truncate">
        {packet.info || packet.flags || '-'}
      </div>
    </div>
  )
}

function PacketDetailSection({ packet, mode }: { packet: Packet; mode: 'beginner' | 'expert' }) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['header']))
  
  const toggleSection = (section: string) => {
    const newSet = new Set(expandedSections)
    if (newSet.has(section)) {
      newSet.delete(section)
    } else {
      newSet.add(section)
    }
    setExpandedSections(newSet)
  }
  
  const protocolStyle = getProtocolStyle(packet.protocol)
  
  return (
    <div className="space-y-3">
      {/* Protocol badge */}
      <div className={clsx(
        'flex items-center gap-2 p-3 rounded-lg',
        protocolStyle.bg
      )}>
        <span className={clsx('text-lg font-semibold', protocolStyle.text)}>
          {packet.protocol}
        </span>
        <span className="text-sm text-gray-400">
          {packet.size} bytes
        </span>
      </div>
      
      {/* Header section */}
      <DetailSection
        title="IP Header"
        expanded={expandedSections.has('header')}
        onToggle={() => toggleSection('header')}
      >
        <DetailRow label="Source IP" value={packet.source_ip} mono />
        <DetailRow label="Destination IP" value={packet.destination_ip} mono />
        {packet.ttl && <DetailRow label="TTL" value={packet.ttl.toString()} />}
        <DetailRow label="Protocol" value={packet.protocol} />
        <DetailRow label="Total Length" value={`${packet.size} bytes`} />
      </DetailSection>
      
      {/* Transport section */}
      {(packet.source_port || packet.destination_port) && (
        <DetailSection
          title={`${packet.protocol} Header`}
          expanded={expandedSections.has('transport')}
          onToggle={() => toggleSection('transport')}
        >
          {packet.source_port && (
            <DetailRow label="Source Port" value={packet.source_port.toString()} mono />
          )}
          {packet.destination_port && (
            <DetailRow 
              label="Destination Port" 
              value={packet.destination_port.toString()} 
              mono 
              hint={getPortHint(packet.destination_port)}
            />
          )}
          {packet.flags && (
            <DetailRow label="Flags" value={packet.flags} mono />
          )}
        </DetailSection>
      )}
      
      {/* Info section */}
      {packet.info && (
        <DetailSection
          title="Additional Info"
          expanded={expandedSections.has('info')}
          onToggle={() => toggleSection('info')}
        >
          <div className="text-sm text-gray-300 font-mono break-all">
            {packet.info}
          </div>
        </DetailSection>
      )}
      
      {/* Privacy notice */}
      <div className="p-3 bg-[#0a0a0a] rounded-lg border border-[#262626]">
        <div className="flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-gray-500 mt-0.5" />
          <div className="text-xs text-gray-500">
            Payload content is hidden by default for privacy.
            {mode === 'expert' && ' Enable in Settings if needed.'}
          </div>
        </div>
      </div>
    </div>
  )
}

function DetailSection({ 
  title, 
  expanded, 
  onToggle, 
  children 
}: { 
  title: string
  expanded: boolean
  onToggle: () => void
  children: React.ReactNode
}) {
  return (
    <div className="border border-[#262626] rounded-lg overflow-hidden">
      <button
        onClick={onToggle}
        className="flex items-center justify-between w-full px-3 py-2 bg-[#0f0f0f] hover:bg-[#1a1a1a] transition-colors"
      >
        <span className="text-sm font-medium text-gray-300">{title}</span>
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-gray-500" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500" />
        )}
      </button>
      {expanded && (
        <div className="p-3 space-y-2 bg-[#0a0a0a]">
          {children}
        </div>
      )}
    </div>
  )
}

function DetailRow({ 
  label, 
  value, 
  mono = false,
  hint
}: { 
  label: string
  value: string
  mono?: boolean
  hint?: string
}) {
  return (
    <div className="flex items-start justify-between py-1">
      <span className="text-xs text-gray-500">{label}</span>
      <div className="text-right">
        <span className={clsx('text-sm text-gray-300', mono && 'font-mono')}>
          {value}
        </span>
        {hint && (
          <div className="text-xs text-gray-500">{hint}</div>
        )}
      </div>
    </div>
  )
}

function getPortHint(port: number): string | undefined {
  const portHints: Record<number, string> = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAP/SSL',
    995: 'POP3/SSL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP Proxy',
    8443: 'HTTPS Alt',
  }
  return portHints[port]
}
