import { useState, useEffect } from 'react'
import { alertsApi } from '../services/api'
import { AlertTriangle, Info, AlertCircle, Clock, Check } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

interface Alert {
  id: number
  severity: 'info' | 'warning' | 'critical'
  title: string
  description: string
  explanation: string
  source_ip: string | null
  created_at: string
  is_acknowledged: boolean
}

interface AlertsFeedProps {
  limit?: number
}

export default function AlertsFeed({ limit = 10 }: AlertsFeedProps) {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchAlerts()
    const interval = setInterval(fetchAlerts, 5000)
    return () => clearInterval(interval)
  }, [limit])

  const fetchAlerts = async () => {
    try {
      const response = await alertsApi.getAlerts({ limit })
      // API returns: { success: bool, data: { alerts: [...], total, filtered } }
      // Handle multiple possible response shapes defensively
      const responseData = response.data
      let alertsArray: Alert[] = []
      
      if (Array.isArray(responseData)) {
        // Direct array response
        alertsArray = responseData
      } else if (responseData?.data?.alerts && Array.isArray(responseData.data.alerts)) {
        // Wrapped response: { success, data: { alerts: [...] } }
        alertsArray = responseData.data.alerts
      } else if (responseData?.alerts && Array.isArray(responseData.alerts)) {
        // Partial wrap: { alerts: [...] }
        alertsArray = responseData.alerts
      }
      
      setAlerts(alertsArray)
      setError(null)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch alerts'
      console.error('Failed to fetch alerts:', err)
      setError(errorMessage)
      // Keep existing alerts on error, don't crash
    } finally {
      setLoading(false)
    }
  }

  const handleAcknowledge = async (alertId: number) => {
    try {
      await alertsApi.acknowledge(alertId)
      fetchAlerts()
    } catch (error) {
      console.error('Failed to acknowledge alert:', error)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-32">
        <div className="spinner" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-32 text-gray-400">
        <AlertCircle className="w-8 h-8 mb-2 opacity-50 text-red-400" />
        <p className="text-red-400">Failed to load alerts</p>
      </div>
    )
  }

  if (!Array.isArray(alerts) || alerts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-32 text-gray-400">
        <AlertTriangle className="w-8 h-8 mb-2 opacity-50" />
        <p>No alerts to display</p>
      </div>
    )
  }

  return (
    <div className="space-y-3 max-h-96 overflow-y-auto">
      {alerts.map((alert) => (
        <AlertItem 
          key={alert.id} 
          alert={alert} 
          onAcknowledge={() => handleAcknowledge(alert.id)}
        />
      ))}
    </div>
  )
}

interface AlertItemProps {
  alert: Alert
  onAcknowledge: () => void
}

function AlertItem({ alert, onAcknowledge }: AlertItemProps) {
  const [expanded, setExpanded] = useState(false)
  
  const severityConfig = {
    info: {
      icon: Info,
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/30',
      textColor: 'text-blue-400',
      iconColor: 'text-blue-400',
    },
    warning: {
      icon: AlertTriangle,
      bgColor: 'bg-yellow-500/10',
      borderColor: 'border-yellow-500/30',
      textColor: 'text-yellow-400',
      iconColor: 'text-yellow-400',
    },
    critical: {
      icon: AlertCircle,
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/30',
      textColor: 'text-red-400',
      iconColor: 'text-red-400',
    },
  }

  const config = severityConfig[alert.severity]
  const Icon = config.icon

  return (
    <div 
      className={`${config.bgColor} border ${config.borderColor} rounded-lg p-3 cursor-pointer transition-all hover:bg-opacity-20`}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start gap-3">
        <Icon className={`w-5 h-5 mt-0.5 ${config.iconColor} flex-shrink-0`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <h4 className="font-medium text-white text-sm truncate">{alert.title}</h4>
            <div className="flex items-center gap-2 flex-shrink-0">
              {!alert.is_acknowledged && (
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    onAcknowledge()
                  }}
                  className="p-1 rounded hover:bg-white/10 transition-colors"
                  title="Acknowledge"
                >
                  <Check className="w-4 h-4 text-gray-400 hover:text-green-400" />
                </button>
              )}
              <span className={`text-xs ${config.textColor} uppercase font-medium`}>
                {alert.severity}
              </span>
            </div>
          </div>
          <p className="text-xs text-gray-400 mt-1">{alert.description}</p>
          
          {expanded && (
            <div className="mt-3 pt-3 border-t border-dark-border">
              <p className="text-sm text-gray-300 mb-2">{alert.explanation}</p>
              <div className="flex items-center gap-4 text-xs text-gray-500">
                {alert.source_ip && (
                  <span>Source: <code className="text-gray-400">{alert.source_ip}</code></span>
                )}
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
