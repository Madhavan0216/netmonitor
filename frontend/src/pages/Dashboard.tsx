import { useState, useEffect } from 'react'
import { dashboardApi } from '../services/api'
import {
  AlertTriangle,
  Shield,
  Server,
  Globe,
} from 'lucide-react'
import TrafficChart from '../components/TrafficChart'
import AlertsFeed from '../components/AlertsFeed'
import SecurityScoreCard from '../components/SecurityScoreCard'

interface DashboardSummary {
  capture_status: {
    is_running: boolean
    interface: string | null
    total_packets: number
    total_bytes: number
    unique_hosts: number
  }
  alert_summary: {
    total: number
    critical: number
    warning: number
    info: number
    unacknowledged: number
    critical_unacknowledged: number
  }
  traffic_summary: {
    tcp_percentage: number
    udp_percentage: number
    icmp_percentage: number
    http_packets: number
    https_packets: number
    dns_packets: number
  }
  detection_summary: {
    total_analyzed: number
    threats_detected: number
    breakdown: {
      port_scans: number
      arp_spoofs: number
      floods: number
      dns_tunnels: number
      suspicious_traffic: number
    }
  }
  system_status: {
    services: {
      capture: string
      detection: string
      alerting: string
    }
    health: string
  }
}

export default function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [securityScore, setSecurityScore] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchDashboardData()
    const interval = setInterval(fetchDashboardData, 5000) // Refresh every 5 seconds
    return () => clearInterval(interval)
  }, [])

  const fetchDashboardData = async () => {
    try {
      const [summaryRes, scoreRes] = await Promise.all([
        dashboardApi.getSummary(),
        dashboardApi.getSecurityScore(),
      ])
      // Handle APIResponse wrapper: { success, data: T }
      const summaryData = summaryRes.data?.data ?? summaryRes.data
      const scoreData = scoreRes.data?.data ?? scoreRes.data
      setSummary(summaryData)
      setSecurityScore(scoreData)
      setError(null)
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-4 bg-red-900/20 border border-red-900/50 rounded-lg">
        <p className="text-red-400">{error}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400 mt-1">Real-time network security overview</p>
      </div>

      {/* Security Score and Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <SecurityScoreCard score={securityScore} />
        
        {/* Capture Status */}
        <div className="bg-dark-card rounded-xl border border-dark-border p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-medium text-white">Capture Status</h3>
            <div className={`flex items-center gap-2 px-2 py-1 rounded-full text-xs ${
              summary?.capture_status?.is_running 
                ? 'bg-green-500/20 text-green-400' 
                : 'bg-gray-500/20 text-gray-400'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                summary?.capture_status?.is_running ? 'bg-green-500 animate-pulse' : 'bg-gray-500'
              }`} />
              {summary?.capture_status?.is_running ? 'Active' : 'Inactive'}
            </div>
          </div>
          
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Interface</span>
              <span className="text-white font-mono">
                {summary?.capture_status?.interface || 'None'}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Packets Captured</span>
              <span className="text-white font-mono">
                {(summary?.capture_status?.total_packets ?? 0).toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Data Volume</span>
              <span className="text-white font-mono">
                {formatBytes(summary?.capture_status?.total_bytes ?? 0)}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Unique Hosts</span>
              <span className="text-white font-mono">
                {summary?.capture_status?.unique_hosts ?? 0}
              </span>
            </div>
          </div>
        </div>

        {/* Detection Summary */}
        <div className="bg-dark-card rounded-xl border border-dark-border p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-medium text-white">Threat Detection</h3>
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Packets Analyzed</span>
              <span className="text-white font-mono">
                {(summary?.detection_summary?.total_analyzed ?? 0).toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Threats Detected</span>
              <span className={`font-mono ${
                (summary?.detection_summary?.threats_detected ?? 0) > 0 ? 'text-yellow-400' : 'text-green-400'
              }`}>
                {summary?.detection_summary?.threats_detected ?? 0}
              </span>
            </div>
            
            <div className="pt-2 border-t border-dark-border">
              <p className="text-xs text-gray-500 mb-2">Breakdown</p>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-gray-400">Port Scans</span>
                  <span className="text-white">{summary?.detection_summary?.breakdown?.port_scans ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">ARP Spoof</span>
                  <span className="text-white">{summary?.detection_summary?.breakdown?.arp_spoofs ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">DNS Tunnel</span>
                  <span className="text-white">{summary?.detection_summary?.breakdown?.dns_tunnels ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Floods</span>
                  <span className="text-white">{summary?.detection_summary?.breakdown?.floods ?? 0}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          title="Total Alerts"
          value={summary?.alert_summary?.total ?? 0}
          icon={AlertTriangle}
          color="blue"
        />
        <StatCard
          title="Critical Alerts"
          value={summary?.alert_summary?.critical_unacknowledged ?? 0}
          icon={AlertTriangle}
          color="red"
          pulse={(summary?.alert_summary?.critical_unacknowledged ?? 0) > 0}
        />
        <StatCard
          title="HTTP/S Traffic"
          value={`${(summary?.traffic_summary?.http_packets ?? 0) + (summary?.traffic_summary?.https_packets ?? 0)}`}
          icon={Globe}
          color="cyan"
          suffix="packets"
        />
        <StatCard
          title="DNS Queries"
          value={summary?.traffic_summary?.dns_packets ?? 0}
          icon={Server}
          color="yellow"
          suffix="queries"
        />
      </div>

      {/* Traffic Chart and Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-dark-card rounded-xl border border-dark-border p-6">
          <h3 className="font-medium text-white mb-4">Protocol Distribution</h3>
          <TrafficChart summary={summary?.traffic_summary} />
        </div>
        
        <div className="bg-dark-card rounded-xl border border-dark-border p-6">
          <h3 className="font-medium text-white mb-4">Recent Alerts</h3>
          <AlertsFeed limit={5} />
        </div>
      </div>
    </div>
  )
}

interface StatCardProps {
  title: string
  value: number | string
  icon: React.ComponentType<{ className?: string }>
  color: 'blue' | 'red' | 'green' | 'yellow' | 'cyan'
  pulse?: boolean
  suffix?: string
}

function StatCard({ title, value, icon: Icon, color, pulse, suffix }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-500/20 text-blue-400',
    red: 'bg-red-500/20 text-red-400',
    green: 'bg-green-500/20 text-green-400',
    yellow: 'bg-yellow-500/20 text-yellow-400',
    cyan: 'bg-cyan-500/20 text-cyan-400',
  }

  return (
    <div className="bg-dark-card rounded-xl border border-dark-border p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-gray-400">{title}</span>
        <div className={`p-1.5 rounded-lg ${colorClasses[color]}`}>
          <Icon className={`w-4 h-4 ${pulse ? 'animate-pulse' : ''}`} />
        </div>
      </div>
      <div className="flex items-baseline gap-1">
        <span className="text-2xl font-bold text-white">{value}</span>
        {suffix && <span className="text-sm text-gray-400">{suffix}</span>}
      </div>
    </div>
  )
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
