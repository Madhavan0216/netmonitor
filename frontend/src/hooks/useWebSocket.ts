/**
 * WebSocket Hook for Real-Time Updates
 * 
 * Connects to the backend WebSocket for live packet, alert,
 * and topology streaming.
 * 
 * FIXED: Uses refs for callbacks to prevent infinite reconnection loops
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { useAuthStore } from '../stores/authStore'

// WebSocket message types
export interface WSMessage {
  type: 'packet' | 'alert' | 'stats' | 'topology' | 'scan'
  channel: string
  data: any
  timestamp: string
}

export interface Packet {
  timestamp: string
  source_ip: string
  destination_ip: string
  source_mac?: string | null
  destination_mac?: string | null
  protocol: string
  source_port?: number | null
  destination_port?: number | null
  size: number
  flags?: string | null
  info: string
  layer?: string
  raw_summary?: string
}

export interface Alert {
  id: string
  type: string
  severity: string
  title: string
  description: string
  source_ip?: string
  destination_ip?: string
  timestamp: string
  evidence?: Record<string, any>
}

export interface TopologyChange {
  event: string
  [key: string]: any
}

export interface UseWebSocketOptions {
  channel?: 'packets' | 'alerts' | 'stats' | 'topology' | 'scans' | 'all'
  onPacket?: (packet: Packet) => void
  onAlert?: (alert: Alert) => void
  onStats?: (stats: any) => void
  onTopology?: (topology: TopologyChange) => void
  onScan?: (scan: any) => void
  maxPackets?: number
  enabled?: boolean
}

export interface UseWebSocketReturn {
  isConnected: boolean
  packets: Packet[]
  alerts: Alert[]
  lastStats: any
  lastTopology: TopologyChange | null
  error: string | null
  reconnect: () => void
  clearPackets: () => void
  clearAlerts: () => void
}

/**
 * WebSocket hook for real-time network monitoring data
 */
export function useWebSocket(options: UseWebSocketOptions = {}): UseWebSocketReturn {
  const {
    channel = 'all',
    onPacket,
    onAlert,
    onStats,
    onTopology,
    onScan,
    maxPackets = 1000,
    enabled = true
  } = options

  const { token } = useAuthStore()
  
  // Core refs
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const mountedRef = useRef(true)
  const isConnectingRef = useRef(false)
  
  // Callback refs - prevents infinite loops by storing callbacks in refs
  const onPacketRef = useRef(onPacket)
  const onAlertRef = useRef(onAlert)
  const onStatsRef = useRef(onStats)
  const onTopologyRef = useRef(onTopology)
  const onScanRef = useRef(onScan)
  const maxPacketsRef = useRef(maxPackets)
  const tokenRef = useRef(token)
  
  // Keep refs updated with latest values (runs on every render but doesn't cause re-renders)
  useEffect(() => {
    onPacketRef.current = onPacket
    onAlertRef.current = onAlert
    onStatsRef.current = onStats
    onTopologyRef.current = onTopology
    onScanRef.current = onScan
    maxPacketsRef.current = maxPackets
    tokenRef.current = token
  })
  
  // State
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [packets, setPackets] = useState<Packet[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [lastStats, setLastStats] = useState<any>(null)
  const [lastTopology, setLastTopology] = useState<TopologyChange | null>(null)

  const clearPackets = useCallback(() => {
    setPackets([])
  }, [])

  const clearAlerts = useCallback(() => {
    setAlerts([])
  }, [])

  // Connect function - uses refs so dependencies are stable
  const connect = useCallback(() => {
    const currentToken = tokenRef.current
    
    if (!enabled) {
      console.log('[WebSocket] Not enabled, skipping connection')
      return
    }
    
    if (!currentToken) {
      console.log('[WebSocket] No token, skipping connection')
      return
    }
    
    if (!mountedRef.current) {
      console.log('[WebSocket] Component unmounted, skipping connection')
      return
    }
    
    if (isConnectingRef.current) {
      console.log('[WebSocket] Already connecting, skipping')
      return
    }
    
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      console.log('[WebSocket] Already connected')
      return
    }
    
    if (wsRef.current?.readyState === WebSocket.CONNECTING) {
      console.log('[WebSocket] Already connecting (WebSocket state)')
      return
    }
    
    isConnectingRef.current = true

    // Close existing connection
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    // Build WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.hostname
    const port = import.meta.env.VITE_API_PORT || '8000'
    const wsUrl = `${protocol}//${host}:${port}/ws/live?token=${currentToken}&channel=${channel}`

    console.log(`[WebSocket] Connecting to channel: ${channel}`)

    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        if (!mountedRef.current) {
          ws.close()
          return
        }
        console.log('[WebSocket] Connected successfully')
        setIsConnected(true)
        setError(null)
        reconnectAttemptsRef.current = 0
        isConnectingRef.current = false
      }

      ws.onmessage = (event) => {
        if (!mountedRef.current) return
        
        try {
          const message: WSMessage = JSON.parse(event.data)
          
          switch (message.type) {
            case 'packet':
              const packet = message.data as Packet
              setPackets(prev => {
                const newPackets = [...prev, packet]
                // Keep only the latest maxPackets
                const max = maxPacketsRef.current
                if (newPackets.length > max) {
                  return newPackets.slice(-max)
                }
                return newPackets
              })
              onPacketRef.current?.(packet)
              break
              
            case 'alert':
              const alert = message.data as Alert
              setAlerts(prev => [alert, ...prev].slice(0, 100)) // Keep latest 100 alerts
              onAlertRef.current?.(alert)
              break
              
            case 'stats':
              setLastStats(message.data)
              onStatsRef.current?.(message.data)
              break
              
            case 'topology':
              setLastTopology(message.data as TopologyChange)
              onTopologyRef.current?.(message.data)
              break
              
            case 'scan':
              onScanRef.current?.(message.data)
              break
          }
        } catch (e) {
          console.error('[WebSocket] Failed to parse message:', e)
        }
      }

      ws.onerror = () => {
        console.error('[WebSocket] Connection error')
        setError('WebSocket connection error')
        isConnectingRef.current = false
      }

      ws.onclose = (event) => {
        console.log(`[WebSocket] Closed: code=${event.code}`)
        setIsConnected(false)
        wsRef.current = null
        isConnectingRef.current = false

        // Attempt reconnect with exponential backoff (max 5 attempts)
        if (enabled && mountedRef.current && reconnectAttemptsRef.current < 5) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 10000)
          reconnectAttemptsRef.current++
          
          console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current}/5)`)
          
          reconnectTimeoutRef.current = setTimeout(() => {
            if (mountedRef.current) {
              connect()
            }
          }, delay)
        } else if (reconnectAttemptsRef.current >= 5) {
          console.log('[WebSocket] Max reconnection attempts reached')
          setError('Unable to connect after 5 attempts')
        }
      }
    } catch (e) {
      console.error('[WebSocket] Failed to create connection:', e)
      setError('Failed to create WebSocket connection')
      isConnectingRef.current = false
    }
  }, [enabled, channel]) // Only depends on enabled and channel - NOT callbacks!

  const reconnect = useCallback(() => {
    reconnectAttemptsRef.current = 0
    isConnectingRef.current = false
    setError(null)
    connect()
  }, [connect])

  // Connect on mount, disconnect on unmount
  useEffect(() => {
    mountedRef.current = true
    
    // Small delay to batch rapid re-renders
    const connectTimer = setTimeout(() => {
      if (mountedRef.current) {
        connect()
      }
    }, 50)

    return () => {
      mountedRef.current = false
      clearTimeout(connectTimer)
      
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
        reconnectTimeoutRef.current = null
      }
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      isConnectingRef.current = false
    }
  }, [connect])

  // Reconnect when token changes
  useEffect(() => {
    const currentToken = useAuthStore.getState().token
    if (currentToken && !isConnected && !isConnectingRef.current) {
      // Small delay to prevent rapid reconnections
      const timer = setTimeout(() => {
        if (mountedRef.current && !isConnected && !isConnectingRef.current) {
          reconnectAttemptsRef.current = 0
          connect()
        }
      }, 100)
      return () => clearTimeout(timer)
    }
  }, [token, isConnected, connect])

  return {
    isConnected,
    packets,
    alerts,
    lastStats,
    lastTopology,
    error,
    reconnect,
    clearPackets,
    clearAlerts
  }
}

/**
 * Simplified hook just for packets
 */
export function usePacketStream(options: { 
  maxPackets?: number
  enabled?: boolean
} = {}) {
  return useWebSocket({
    channel: 'packets',
    maxPackets: options.maxPackets,
    enabled: options.enabled
  })
}

/**
 * Simplified hook just for alerts
 */
export function useAlertStream(options: {
  enabled?: boolean
} = {}) {
  return useWebSocket({
    channel: 'alerts',
    enabled: options.enabled
  })
}

/**
 * Simplified hook just for topology
 */
export function useTopologyStream(options: {
  enabled?: boolean
  onUpdate?: (topology: TopologyChange) => void
} = {}) {
  return useWebSocket({
    channel: 'topology',
    onTopology: options.onUpdate,
    enabled: options.enabled
  })
}
