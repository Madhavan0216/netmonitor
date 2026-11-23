/**
 * Network Map - Flagship Visualization
 * 
 * Professional network topology visualization with:
 * - Force-directed layout
 * - Live traffic flows
 * - Risk-based coloring
 * - Zoomable/pannable canvas
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { networkApi } from '../services/api'
import { useTopologyStream } from '../hooks/useWebSocket'
import { 
  RefreshCw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Play,
  Pause,
  Layers,
  Router,
  X,
  Wifi,
  WifiOff
} from 'lucide-react'
import { clsx } from 'clsx'
import { useUIStore } from '../stores/uiStore'
import { getProtocolStyle, getRiskStyle } from '../design-system'

// ============================================================================
// TYPES
// ============================================================================

interface Host {
  id: number
  ip_address: string
  mac_address: string | null
  hostname: string | null
  os_info: string | null
  device_type: string | null
  is_gateway: boolean
  first_seen: string
  last_seen: string
  ports: PortResult[]
  risk_score?: number
}

interface PortResult {
  port: number
  state: string
  service: string | null
  version: string | null
}

interface TopologyNode {
  id: string
  label: string
  ip: string
  type: string
  is_gateway: boolean
  ports_open: number
  x?: number
  y?: number
  vx?: number
  vy?: number
  risk_score?: number
}

interface TopologyEdge {
  source: string
  target: string
  type: string
  packets?: number
  bytes?: number
  protocol?: string
}

// ============================================================================
// FORCE SIMULATION HOOK
// ============================================================================

function useForceSimulation(
  nodes: TopologyNode[], 
  edges: TopologyEdge[],
  width: number,
  height: number
) {
  const [positions, setPositions] = useState<Map<string, { x: number; y: number }>>(new Map())
  const animationRef = useRef<number>()
  const nodesRef = useRef<TopologyNode[]>([])
  
  useEffect(() => {
    if (nodes.length === 0 || width === 0 || height === 0) return
    
    const centerX = width / 2
    const centerY = height / 2
    
    // Initialize node positions
    nodesRef.current = nodes.map((node, i) => {
      const existing = nodesRef.current.find(n => n.id === node.id)
      if (existing?.x !== undefined) {
        return { ...node, x: existing.x, y: existing.y, vx: existing.vx || 0, vy: existing.vy || 0 }
      }
      
      if (node.is_gateway) {
        return { ...node, x: centerX, y: centerY, vx: 0, vy: 0 }
      }
      
      const angle = (2 * Math.PI * i) / nodes.length
      const radius = Math.min(width, height) * 0.35
      return {
        ...node,
        x: centerX + radius * Math.cos(angle) + (Math.random() - 0.5) * 50,
        y: centerY + radius * Math.sin(angle) + (Math.random() - 0.5) * 50,
        vx: 0,
        vy: 0,
      }
    })
    
    // Create edge lookup for connected nodes
    const edgeMap = new Map<string, Set<string>>()
    edges.forEach(e => {
      if (!edgeMap.has(e.source)) edgeMap.set(e.source, new Set())
      if (!edgeMap.has(e.target)) edgeMap.set(e.target, new Set())
      edgeMap.get(e.source)!.add(e.target)
      edgeMap.get(e.target)!.add(e.source)
    })
    
    // Physics parameters
    const REPULSION = 5000
    const ATTRACTION = 0.005
    const DAMPING = 0.85
    const MIN_DISTANCE = 80
    
    let iteration = 0
    const MAX_ITERATIONS = 300
    
    function simulate() {
      if (iteration >= MAX_ITERATIONS) return
      
      const simNodes = nodesRef.current
      
      for (let i = 0; i < simNodes.length; i++) {
        const node = simNodes[i]
        if (node.is_gateway) continue
        
        let fx = 0, fy = 0
        
        // Repulsion from other nodes
        for (let j = 0; j < simNodes.length; j++) {
          if (i === j) continue
          const other = simNodes[j]
          
          const dx = (node.x || 0) - (other.x || 0)
          const dy = (node.y || 0) - (other.y || 0)
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          
          if (dist < MIN_DISTANCE * 3) {
            const force = REPULSION / (dist * dist)
            fx += (dx / dist) * force
            fy += (dy / dist) * force
          }
        }
        
        // Attraction to connected nodes
        const connected = edgeMap.get(node.id)
        if (connected) {
          connected.forEach(otherId => {
            const other = simNodes.find(n => n.id === otherId)
            if (!other) return
            
            const dx = (other.x || 0) - (node.x || 0)
            const dy = (other.y || 0) - (node.y || 0)
            
            fx += dx * ATTRACTION
            fy += dy * ATTRACTION
          })
        }
        
        // Center gravity
        const dx = centerX - (node.x || 0)
        const dy = centerY - (node.y || 0)
        fx += dx * 0.001
        fy += dy * 0.001
        
        // Update velocity and position
        node.vx = ((node.vx || 0) + fx) * DAMPING
        node.vy = ((node.vy || 0) + fy) * DAMPING
        node.x = (node.x || 0) + (node.vx || 0)
        node.y = (node.y || 0) + (node.vy || 0)
        
        // Keep in bounds
        const margin = 50
        node.x = Math.max(margin, Math.min(width - margin, node.x || 0))
        node.y = Math.max(margin, Math.min(height - margin, node.y || 0))
      }
      
      // Update state
      const newPositions = new Map<string, { x: number; y: number }>()
      simNodes.forEach(n => {
        newPositions.set(n.id, { x: n.x || 0, y: n.y || 0 })
      })
      setPositions(newPositions)
      
      iteration++
      
      if (iteration < MAX_ITERATIONS) {
        animationRef.current = requestAnimationFrame(simulate)
      }
    }
    
    simulate()
    
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
    }
  }, [nodes.length, edges.length, width, height])
  
  return positions
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function NetworkMap() {
  const [hosts, setHosts] = useState<Host[]>([])
  const [nodes, setNodes] = useState<TopologyNode[]>([])
  const [edges, setEdges] = useState<TopologyEdge[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState(false)
  const [panStart, setPanStart] = useState({ x: 0, y: 0 })
  const [showFlows, setShowFlows] = useState(true)
  const [isLive, setIsLive] = useState(true)
  
  const containerRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 })
  
  const { mode, showNetworkLabels } = useUIStore()
  const positions = useForceSimulation(nodes, edges, dimensions.width, dimensions.height)
  
  // WebSocket for real-time topology updates
  const { isConnected: wsConnected } = useTopologyStream({
    enabled: isLive,
    onUpdate: (topology) => {
      // Handle topology change event
      if (topology.event === 'change' && topology.data) {
        const topoData = topology.data
        if (topoData.nodes) setNodes(topoData.nodes)
        if (topoData.edges) setEdges(topoData.edges)
      }
    }
  })
  
  // Fetch data (initial load and fallback polling)
  useEffect(() => {
    fetchData()
    // Poll less frequently when WebSocket is connected
    const pollInterval = wsConnected ? 15000 : 5000
    const interval = isLive ? setInterval(fetchData, pollInterval) : null
    return () => { if (interval) clearInterval(interval) }
  }, [isLive, wsConnected])
  
  const fetchData = async () => {
    try {
      const [hostsRes, topoRes] = await Promise.all([
        networkApi.getDiscoveredHosts(),
        networkApi.getTopology(),
      ])
      
      const hostsData = hostsRes.data?.hosts || hostsRes.data || []
      setHosts(Array.isArray(hostsData) ? hostsData : [])
      
      const topoData = topoRes.data
      if (topoData) {
        setNodes(topoData.nodes || [])
        setEdges(topoData.edges || [])
      }
    } catch (error) {
      console.error('Failed to fetch network data:', error)
    } finally {
      setLoading(false)
    }
  }
  
  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect()
        setDimensions({ width: rect.width, height: rect.height })
      }
    }
    
    updateDimensions()
    window.addEventListener('resize', updateDimensions)
    return () => window.removeEventListener('resize', updateDimensions)
  }, [])
  
  // Render canvas
  useEffect(() => {
    renderCanvas()
  }, [positions, nodes, edges, zoom, pan, selectedNode, showFlows])
  
  const renderCanvas = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas || positions.size === 0) return
    
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    
    const { width, height } = dimensions
    canvas.width = width * window.devicePixelRatio
    canvas.height = height * window.devicePixelRatio
    canvas.style.width = `${width}px`
    canvas.style.height = `${height}px`
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio)
    
    ctx.save()
    ctx.translate(pan.x, pan.y)
    ctx.scale(zoom, zoom)
    
    // Background
    ctx.fillStyle = '#0a0a0a'
    ctx.fillRect(-pan.x / zoom, -pan.y / zoom, width / zoom, height / zoom)
    
    // Grid
    ctx.strokeStyle = '#1a1a1a'
    ctx.lineWidth = 1 / zoom
    const gridSize = 50
    for (let x = 0; x < width / zoom; x += gridSize) {
      ctx.beginPath()
      ctx.moveTo(x, 0)
      ctx.lineTo(x, height / zoom)
      ctx.stroke()
    }
    for (let y = 0; y < height / zoom; y += gridSize) {
      ctx.beginPath()
      ctx.moveTo(0, y)
      ctx.lineTo(width / zoom, y)
      ctx.stroke()
    }
    
    // Draw edges
    edges.forEach((edge) => {
      const startPos = positions.get(edge.source)
      const endPos = positions.get(edge.target)
      if (!startPos || !endPos) return
      
      const protocolStyle = getProtocolStyle(edge.protocol || 'unknown')
      const isHighlighted = edge.source === selectedNode?.id || edge.target === selectedNode?.id
      
      ctx.beginPath()
      ctx.moveTo(startPos.x, startPos.y)
      ctx.lineTo(endPos.x, endPos.y)
      ctx.strokeStyle = isHighlighted ? protocolStyle.hex : '#333333'
      ctx.lineWidth = isHighlighted ? 3 / zoom : 2 / zoom
      ctx.stroke()
      
      // Flow animation
      if (showFlows && edge.packets) {
        const t = (Date.now() % 2000) / 2000
        const fx = startPos.x + (endPos.x - startPos.x) * t
        const fy = startPos.y + (endPos.y - startPos.y) * t
        
        ctx.beginPath()
        ctx.arc(fx, fy, 4 / zoom, 0, Math.PI * 2)
        ctx.fillStyle = protocolStyle.hex
        ctx.fill()
      }
    })
    
    // Draw nodes
    nodes.forEach((node) => {
      const pos = positions.get(node.id)
      if (!pos) return
      
      const isSelected = selectedNode?.id === node.id
      const riskScore = node.risk_score || 0
      const baseRadius = node.is_gateway ? 35 : 25
      const radius = baseRadius / (zoom > 1 ? 1 : zoom)
      
      // Risk glow
      if (riskScore >= 70) {
        ctx.beginPath()
        ctx.arc(pos.x, pos.y, radius + 8, 0, Math.PI * 2)
        const gradient = ctx.createRadialGradient(pos.x, pos.y, radius, pos.x, pos.y, radius + 15)
        gradient.addColorStop(0, 'rgba(239, 68, 68, 0.3)')
        gradient.addColorStop(1, 'rgba(239, 68, 68, 0)')
        ctx.fillStyle = gradient
        ctx.fill()
      }
      
      // Node circle
      ctx.beginPath()
      ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2)
      
      if (node.is_gateway) {
        ctx.fillStyle = '#3b82f6'
      } else if (isSelected) {
        ctx.fillStyle = '#4ade80'
      } else {
        ctx.fillStyle = '#1f1f1f'
      }
      ctx.fill()
      
      ctx.strokeStyle = isSelected ? '#4ade80' : node.is_gateway ? '#60a5fa' : '#404040'
      ctx.lineWidth = isSelected ? 3 / zoom : 2 / zoom
      ctx.stroke()
      
      // Label inside node
      ctx.fillStyle = '#ffffff'
      ctx.font = `${12 / (zoom > 1 ? 1 : zoom)}px Inter, sans-serif`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      
      if (node.is_gateway) {
        ctx.fillText('GW', pos.x, pos.y)
      } else {
        ctx.fillText(node.type?.charAt(0).toUpperCase() || '?', pos.x, pos.y)
      }
      
      // IP label below
      if (showNetworkLabels || isSelected) {
        ctx.fillStyle = '#888888'
        ctx.font = `${11 / zoom}px Inter, sans-serif`
        ctx.fillText(node.label || node.ip, pos.x, pos.y + radius + 15 / zoom)
      }
      
      // Risk badge
      if ((node.risk_score || 0) >= 40) {
        ctx.beginPath()
        ctx.arc(pos.x + radius * 0.7, pos.y - radius * 0.7, 8 / zoom, 0, Math.PI * 2)
        ctx.fillStyle = node.risk_score! >= 70 ? '#ef4444' : '#f59e0b'
        ctx.fill()
        ctx.fillStyle = '#ffffff'
        ctx.font = `bold ${8 / zoom}px Inter, sans-serif`
        ctx.fillText('!', pos.x + radius * 0.7, pos.y - radius * 0.7)
      }
      
      // Ports indicator
      if (node.ports_open > 0) {
        ctx.fillStyle = '#666666'
        ctx.font = `${9 / zoom}px Inter, sans-serif`
        ctx.fillText(`${node.ports_open} ports`, pos.x, pos.y + radius + 26 / zoom)
      }
    })
    
    ctx.restore()
  }, [positions, nodes, edges, zoom, pan, selectedNode, showFlows, dimensions, showNetworkLabels])
  
  // Interaction handlers
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current
    if (!canvas) return
    
    const rect = canvas.getBoundingClientRect()
    const x = (e.clientX - rect.left - pan.x) / zoom
    const y = (e.clientY - rect.top - pan.y) / zoom
    
    let clickedNode: TopologyNode | null = null
    for (const node of nodes) {
      const pos = positions.get(node.id)
      if (!pos) continue
      
      const radius = node.is_gateway ? 35 : 25
      const dist = Math.sqrt((x - pos.x) ** 2 + (y - pos.y) ** 2)
      
      if (dist <= radius) {
        clickedNode = node
        break
      }
    }
    
    setSelectedNode(clickedNode)
  }
  
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (e.button === 0) {
      setIsPanning(true)
      setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y })
    }
  }
  
  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (isPanning) {
      setPan({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y,
      })
    }
  }
  
  const handleMouseUp = () => {
    setIsPanning(false)
  }
  
  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault()
    const delta = e.deltaY > 0 ? 0.9 : 1.1
    setZoom(z => Math.max(0.25, Math.min(3, z * delta)))
  }
  
  const resetView = () => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
    setSelectedNode(null)
  }
  
  // Loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-10rem)]">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }
  
  const selectedHost = selectedNode 
    ? hosts.find(h => h.ip_address === selectedNode.ip)
    : null
  
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Network Map</h1>
          <p className="text-gray-500 mt-1">
            {nodes.length} hosts • {edges.length} connections
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsLive(!isLive)}
            className={clsx(
              'flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
              isLive 
                ? 'bg-emerald-500/20 text-emerald-400'
                : 'bg-[#262626] text-gray-400 hover:text-white'
            )}
          >
            {isLive ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            {isLive ? 'Live' : 'Paused'}
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
            <div className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0">ℹ️</div>
            <div className="text-sm text-blue-200/70">
              <strong className="text-blue-300">Understanding the Network Map:</strong> This shows all devices 
              on your network. The <strong>gateway</strong> (router) is in the center. Devices with 
              <span className="text-red-400"> red warning badges</span> may be risky.
              Click any device for details. Scroll to zoom, drag to pan.
            </div>
          </div>
        </div>
      )}
      
      {/* Main content */}
      <div className="flex gap-4">
        {/* Canvas */}
        <div className="flex-1 bg-[#0a0a0a] rounded-lg border border-[#262626] overflow-hidden relative">
          {/* Toolbar */}
          <div className="absolute top-4 left-4 z-10 flex items-center gap-2">
            <div className="flex items-center bg-[#141414] border border-[#262626] rounded-lg">
              <button
                onClick={() => setZoom(z => Math.min(3, z * 1.2))}
                className="p-2 hover:bg-[#262626] rounded-l-lg transition-colors"
              >
                <ZoomIn className="w-4 h-4 text-gray-400" />
              </button>
              <span className="px-2 text-xs text-gray-500 font-mono min-w-[3rem] text-center">
                {Math.round(zoom * 100)}%
              </span>
              <button
                onClick={() => setZoom(z => Math.max(0.25, z * 0.8))}
                className="p-2 hover:bg-[#262626] rounded-r-lg transition-colors"
              >
                <ZoomOut className="w-4 h-4 text-gray-400" />
              </button>
            </div>
            
            <button
              onClick={resetView}
              className="p-2 bg-[#141414] border border-[#262626] rounded-lg hover:bg-[#262626] transition-colors"
              title="Reset view"
            >
              <Maximize2 className="w-4 h-4 text-gray-400" />
            </button>
            
            <button
              onClick={() => setShowFlows(!showFlows)}
              className={clsx(
                'p-2 border rounded-lg transition-colors',
                showFlows 
                  ? 'bg-blue-500/20 border-blue-500/30 text-blue-400'
                  : 'bg-[#141414] border-[#262626] text-gray-400 hover:bg-[#262626]'
              )}
              title="Toggle traffic flows"
            >
              <Layers className="w-4 h-4" />
            </button>
          </div>
          
          {/* Legend */}
          <div className="absolute bottom-4 left-4 z-10 bg-[#141414]/90 border border-[#262626] rounded-lg p-3">
            <div className="text-xs text-gray-500 mb-2">Legend</div>
            <div className="space-y-1.5 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span className="text-gray-400">Gateway</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-[#1f1f1f] border border-[#404040]" />
                <span className="text-gray-400">Host</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-gray-400">High Risk</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-emerald-500" />
                <span className="text-gray-400">Selected</span>
              </div>
            </div>
          </div>
          
          {/* Canvas element */}
          <div ref={containerRef} className="w-full h-[calc(100vh-16rem)]">
            <canvas
              ref={canvasRef}
              onClick={handleCanvasClick}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onWheel={handleWheel}
              className={clsx(
                'w-full h-full',
                isPanning ? 'cursor-grabbing' : 'cursor-grab'
              )}
            />
          </div>
        </div>
        
        {/* Details panel */}
        {selectedNode && (
          <div className="w-80 bg-[#141414] rounded-lg border border-[#262626] p-4 space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-medium text-white">
                  {selectedNode.label || selectedNode.ip}
                </h3>
                <p className="text-sm text-gray-500 font-mono">{selectedNode.ip}</p>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-1 hover:bg-[#262626] rounded transition-colors"
              >
                <X className="w-4 h-4 text-gray-500" />
              </button>
            </div>
            
            {/* Risk score */}
            {(selectedNode.risk_score || 0) > 0 && (
              <div className={clsx(
                'p-3 rounded-lg border',
                getRiskStyle(selectedNode.risk_score || 0).bg,
                getRiskStyle(selectedNode.risk_score || 0).border
              )}>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-400">Risk Score</span>
                  <span className={clsx(
                    'text-lg font-semibold',
                    getRiskStyle(selectedNode.risk_score || 0).text
                  )}>
                    {selectedNode.risk_score}/100
                  </span>
                </div>
              </div>
            )}
            
            {/* Details */}
            <div className="space-y-3">
              <DetailRow label="Type" value={selectedNode.type || 'Unknown'} />
              <DetailRow label="MAC" value={selectedHost?.mac_address || 'N/A'} mono />
              <DetailRow label="Hostname" value={selectedHost?.hostname || 'N/A'} />
              <DetailRow label="OS" value={selectedHost?.os_info || 'Unknown'} />
              <DetailRow 
                label="First Seen" 
                value={selectedHost?.first_seen ? new Date(selectedHost.first_seen).toLocaleDateString() : 'N/A'} 
              />
              <DetailRow label="Open Ports" value={selectedNode.ports_open.toString()} />
            </div>
            
            {/* Open ports list */}
            {selectedHost?.ports && selectedHost.ports.length > 0 && (
              <div>
                <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">
                  Services
                </div>
                <div className="space-y-1 max-h-40 overflow-y-auto">
                  {selectedHost.ports.map((port) => (
                    <div 
                      key={port.port}
                      className="flex items-center justify-between py-1.5 px-2 bg-[#0a0a0a] rounded text-xs"
                    >
                      <span className="font-mono text-white">{port.port}</span>
                      <span className="text-gray-500">{port.service || 'unknown'}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Gateway badge */}
            {selectedNode.is_gateway && (
              <div className="flex items-center gap-2 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                <Router className="w-5 h-5 text-blue-400" />
                <div>
                  <div className="text-sm font-medium text-blue-300">Gateway Device</div>
                  <div className="text-xs text-blue-400/70">Primary network router</div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function DetailRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between py-1 border-b border-[#1f1f1f]">
      <span className="text-xs text-gray-500">{label}</span>
      <span className={clsx('text-sm text-gray-300', mono && 'font-mono text-xs')}>
        {value}
      </span>
    </div>
  )
}
