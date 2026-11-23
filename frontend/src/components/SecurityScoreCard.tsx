import { CheckCircle, AlertTriangle, XCircle } from 'lucide-react'

interface SecurityScore {
  score: number
  status: 'good' | 'warning' | 'critical'
  message: string
  factors: {
    critical_alerts: number
    warning_alerts: number
    info_alerts: number
  }
}

interface SecurityScoreCardProps {
  score: SecurityScore | null
}

export default function SecurityScoreCard({ score }: SecurityScoreCardProps) {
  // Loading state
  if (!score) {
    return (
      <div className="bg-dark-card rounded-xl border border-dark-border p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-dark-border rounded w-1/3 mb-4"></div>
          <div className="h-24 bg-dark-border rounded"></div>
        </div>
      </div>
    )
  }

  const statusConfig = {
    good: {
      icon: CheckCircle,
      color: 'text-green-400',
      bgColor: 'bg-green-500/20',
      borderColor: 'border-green-500/30',
      gradientFrom: 'from-green-500',
      gradientTo: 'to-emerald-500',
    },
    warning: {
      icon: AlertTriangle,
      color: 'text-yellow-400',
      bgColor: 'bg-yellow-500/20',
      borderColor: 'border-yellow-500/30',
      gradientFrom: 'from-yellow-500',
      gradientTo: 'to-orange-500',
    },
    critical: {
      icon: XCircle,
      color: 'text-red-400',
      bgColor: 'bg-red-500/20',
      borderColor: 'border-red-500/30',
      gradientFrom: 'from-red-500',
      gradientTo: 'to-rose-500',
    },
  }

  // Safely get config with fallback to 'good' if status is invalid
  const validStatus = score.status && statusConfig[score.status] ? score.status : 'good'
  const config = statusConfig[validStatus]
  const StatusIcon = config.icon
  
  // Safe defaults for factors
  const factors = score.factors ?? { critical_alerts: 0, warning_alerts: 0, info_alerts: 0 }
  const scoreValue = typeof score.score === 'number' ? score.score : 0

  // Calculate the circumference and stroke offset for the progress ring
  const radius = 45
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (scoreValue / 100) * circumference

  return (
    <div className={`bg-dark-card rounded-xl border ${config.borderColor} p-6`}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium text-white">Security Score</h3>
        <StatusIcon className={`w-5 h-5 ${config.color}`} />
      </div>

      <div className="flex items-center gap-6">
        {/* Circular progress */}
        <div className="relative">
          <svg className="w-28 h-28 transform -rotate-90">
            {/* Background circle */}
            <circle
              cx="56"
              cy="56"
              r={radius}
              className="stroke-dark-border"
              strokeWidth="8"
              fill="none"
            />
            {/* Progress circle */}
            <circle
              cx="56"
              cy="56"
              r={radius}
              className={`stroke-current ${config.color}`}
              strokeWidth="8"
              fill="none"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              style={{ transition: 'stroke-dashoffset 0.5s ease-out' }}
            />
          </svg>
          {/* Score text */}
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-3xl font-bold text-white">{scoreValue}</span>
          </div>
        </div>

        {/* Status and message */}
        <div className="flex-1">
          <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${config.bgColor} ${config.color} mb-2`}>
            <StatusIcon className="w-3.5 h-3.5" />
            {validStatus === 'good' ? 'Healthy' : validStatus === 'warning' ? 'At Risk' : 'Critical'}
          </div>
          <p className="text-sm text-gray-400">{score.message || 'Security status unknown'}</p>
        </div>
      </div>

      {/* Alert breakdown */}
      <div className="mt-4 pt-4 border-t border-dark-border">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <p className="text-lg font-semibold text-red-400">{factors.critical_alerts ?? 0}</p>
            <p className="text-xs text-gray-500">Critical</p>
          </div>
          <div>
            <p className="text-lg font-semibold text-yellow-400">{factors.warning_alerts ?? 0}</p>
            <p className="text-xs text-gray-500">Warnings</p>
          </div>
          <div>
            <p className="text-lg font-semibold text-blue-400">{factors.info_alerts ?? 0}</p>
            <p className="text-xs text-gray-500">Info</p>
          </div>
        </div>
      </div>
    </div>
  )
}
