/**
 * Reusable UI Components
 * 
 * Professional SOC-grade components following the design system.
 */

import React from 'react'
import { 
  AlertTriangle, 
  AlertCircle, 
  Info, 
  CheckCircle,
  HelpCircle,
  ChevronRight,
  X
} from 'lucide-react'
import { components, getSeverityStyle, getProtocolStyle, typography } from '../../design-system'
import { useUIStore } from '../../stores/uiStore'
import { clsx } from 'clsx'

// ============================================================================
// SEVERITY BADGE
// ============================================================================

interface SeverityBadgeProps {
  severity: 'critical' | 'warning' | 'info'
  size?: 'sm' | 'md'
  showIcon?: boolean
}

export function SeverityBadge({ severity, size = 'md', showIcon = true }: SeverityBadgeProps) {
  const style = getSeverityStyle(severity)
  const Icon = severity === 'critical' ? AlertTriangle : severity === 'warning' ? AlertCircle : Info
  
  return (
    <span className={clsx(
      components.badgePill,
      style.bg,
      style.text,
      size === 'sm' && 'text-[10px] px-1.5 py-0'
    )}>
      {showIcon && <Icon className={clsx('mr-1', size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5')} />}
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  )
}

// ============================================================================
// PROTOCOL BADGE
// ============================================================================

interface ProtocolBadgeProps {
  protocol: string
  size?: 'sm' | 'md'
}

export function ProtocolBadge({ protocol, size = 'md' }: ProtocolBadgeProps) {
  const style = getProtocolStyle(protocol)
  
  return (
    <span className={clsx(
      components.badge,
      style.bg,
      style.text,
      'font-mono',
      size === 'sm' && 'text-[10px] px-1.5 py-0'
    )}>
      {protocol.toUpperCase()}
    </span>
  )
}

// ============================================================================
// CONFIDENCE INDICATOR
// ============================================================================

interface ConfidenceIndicatorProps {
  score: number // 0-1
  showLabel?: boolean
  size?: 'sm' | 'md'
}

export function ConfidenceIndicator({ score, showLabel = true, size = 'md' }: ConfidenceIndicatorProps) {
  const percentage = Math.round(score * 100)
  const barColor = score >= 0.8 ? 'bg-red-500' : score >= 0.5 ? 'bg-amber-500' : 'bg-blue-500'
  
  return (
    <div className={clsx('flex items-center gap-2', size === 'sm' && 'gap-1')}>
      <div className={clsx(
        'flex-1 h-1.5 bg-[#262626] rounded-full overflow-hidden',
        size === 'sm' && 'h-1'
      )}>
        <div 
          className={clsx(barColor, 'h-full rounded-full transition-all')}
          style={{ width: `${percentage}%` }}
        />
      </div>
      {showLabel && (
        <span className={clsx(
          'font-mono text-gray-400',
          size === 'sm' ? 'text-[10px]' : 'text-xs'
        )}>
          {percentage}%
        </span>
      )}
    </div>
  )
}

// ============================================================================
// STATUS DOT
// ============================================================================

interface StatusDotProps {
  status: 'active' | 'inactive' | 'warning' | 'error'
  pulse?: boolean
  size?: 'sm' | 'md' | 'lg'
}

export function StatusDot({ status, pulse = false, size = 'md' }: StatusDotProps) {
  const colorMap = {
    active: 'bg-emerald-500',
    inactive: 'bg-gray-500',
    warning: 'bg-amber-500',
    error: 'bg-red-500',
  }
  
  const sizeMap = {
    sm: 'w-1.5 h-1.5',
    md: 'w-2 h-2',
    lg: 'w-3 h-3',
  }
  
  return (
    <span className={clsx(
      'rounded-full inline-block',
      colorMap[status],
      sizeMap[size],
      pulse && status !== 'inactive' && 'animate-pulse'
    )} />
  )
}

// ============================================================================
// TOOLTIP (Beginner Mode Helper)
// ============================================================================

interface TooltipProps {
  content: React.ReactNode
  children: React.ReactNode
  position?: 'top' | 'bottom' | 'left' | 'right'
}

export function Tooltip({ content, children, position = 'top' }: TooltipProps) {
  const [show, setShow] = React.useState(false)
  
  // Tooltips help both beginners and experts with context
  const positionClasses = {
    top: 'bottom-full left-1/2 -translate-x-1/2 mb-2',
    bottom: 'top-full left-1/2 -translate-x-1/2 mt-2',
    left: 'right-full top-1/2 -translate-y-1/2 mr-2',
    right: 'left-full top-1/2 -translate-y-1/2 ml-2',
  }
  
  return (
    <div 
      className="relative inline-flex"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      {children}
      {show && (
        <div className={clsx(
          components.tooltip,
          positionClasses[position],
          'whitespace-nowrap'
        )}>
          {content}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// EXPLANATION PANEL (Beginner Mode)
// ============================================================================

interface ExplanationPanelProps {
  title: string
  children: React.ReactNode
  learnMoreUrl?: string
  dismissible?: boolean
  onDismiss?: () => void
}

export function ExplanationPanel({ 
  title, 
  children, 
  learnMoreUrl,
  dismissible = false,
  onDismiss 
}: ExplanationPanelProps) {
  const { mode } = useUIStore()
  
  // Only show in beginner mode
  if (mode === 'expert') return null
  
  return (
    <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-4">
      <div className="flex items-start gap-3">
        <HelpCircle className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-medium text-blue-300 mb-1">{title}</h4>
          <div className="text-sm text-blue-200/70 space-y-2">
            {children}
          </div>
          {learnMoreUrl && (
            <a 
              href={learnMoreUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 mt-2 text-xs text-blue-400 hover:text-blue-300"
            >
              Learn more <ChevronRight className="w-3 h-3" />
            </a>
          )}
        </div>
        {dismissible && onDismiss && (
          <button 
            onClick={onDismiss}
            className="p-1 hover:bg-blue-500/20 rounded text-blue-400"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// STAT CARD
// ============================================================================

interface StatCardProps {
  label: string
  value: string | number
  icon?: React.ReactNode
  trend?: { value: number; label: string }
  severity?: 'default' | 'critical' | 'warning' | 'success'
  compact?: boolean
}

export function StatCard({ label, value, icon, trend, severity = 'default', compact = false }: StatCardProps) {
  const severityColors = {
    default: 'text-white',
    critical: 'text-red-400',
    warning: 'text-amber-400',
    success: 'text-emerald-400',
  }
  
  if (compact) {
    return (
      <div className="flex items-center justify-between py-2 border-b border-[#1f1f1f] last:border-0">
        <span className="text-xs text-gray-500">{label}</span>
        <span className={clsx('text-sm font-medium', severityColors[severity])}>
          {value}
        </span>
      </div>
    )
  }
  
  return (
    <div className={components.card}>
      <div className="p-4">
        <div className="flex items-center justify-between">
          <span className={typography.label}>{label}</span>
          {icon && <span className="text-gray-500">{icon}</span>}
        </div>
        <div className={clsx('mt-2 text-2xl font-semibold', severityColors[severity])}>
          {value}
        </div>
        {trend && (
          <div className={clsx(
            'mt-1 text-xs',
            trend.value > 0 ? 'text-red-400' : trend.value < 0 ? 'text-emerald-400' : 'text-gray-500'
          )}>
            {trend.value > 0 ? '↑' : trend.value < 0 ? '↓' : '→'} {Math.abs(trend.value)}% {trend.label}
          </div>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// EMPTY STATE
// ============================================================================

interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      {icon && <div className="text-gray-600 mb-4">{icon}</div>}
      <h3 className="text-lg font-medium text-gray-300">{title}</h3>
      {description && <p className="mt-1 text-sm text-gray-500 max-w-sm">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

// ============================================================================
// DATA TABLE
// ============================================================================

interface Column<T> {
  key: string
  header: string
  width?: string
  render?: (item: T) => React.ReactNode
  sortable?: boolean
}

interface DataTableProps<T> {
  columns: Column<T>[]
  data: T[]
  keyExtractor: (item: T) => string | number
  onRowClick?: (item: T) => void
  selectedKey?: string | number | null
  compact?: boolean
  loading?: boolean
  emptyMessage?: string
}

export function DataTable<T>({ 
  columns, 
  data, 
  keyExtractor,
  onRowClick,
  selectedKey,
  compact = false,
  loading = false,
  emptyMessage = 'No data'
}: DataTableProps<T>) {
  const { mode } = useUIStore()
  const isCompact = compact || mode === 'expert'
  
  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }
  
  if (data.length === 0) {
    return (
      <EmptyState
        title={emptyMessage}
      />
    )
  }
  
  return (
    <div className="overflow-x-auto">
      <table className={components.table}>
        <thead>
          <tr className="bg-[#0f0f0f]">
            {columns.map((col) => (
              <th 
                key={col.key} 
                className={components.tableHeader}
                style={{ width: col.width }}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item) => {
            const key = keyExtractor(item)
            const isSelected = selectedKey === key
            
            return (
              <tr 
                key={key}
                onClick={() => onRowClick?.(item)}
                className={clsx(
                  components.tableRow,
                  onRowClick && 'cursor-pointer',
                  isSelected && 'bg-blue-500/10'
                )}
              >
                {columns.map((col) => (
                  <td 
                    key={col.key} 
                    className={clsx(
                      components.tableCell,
                      isCompact && 'py-2'
                    )}
                  >
                    {col.render 
                      ? col.render(item) 
                      : (item as any)[col.key]
                    }
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ============================================================================
// KEYBOARD SHORTCUT HINT
// ============================================================================

interface KeyboardHintProps {
  keys: string
  action?: string
}

export function KeyboardHint({ keys, action }: KeyboardHintProps) {
  const { mode } = useUIStore()
  
  // Only show in expert mode
  if (mode === 'beginner') return null
  
  return (
    <div className="inline-flex items-center gap-1 text-xs text-gray-500">
      {keys.split('+').map((key, i) => (
        <React.Fragment key={key}>
          {i > 0 && <span>+</span>}
          <kbd className="px-1.5 py-0.5 bg-[#262626] border border-[#333] rounded text-[10px] font-mono">
            {key}
          </kbd>
        </React.Fragment>
      ))}
      {action && <span className="ml-1">{action}</span>}
    </div>
  )
}

// ============================================================================
// MODE TOGGLE
// ============================================================================

export function ModeToggle() {
  const { mode, toggleMode } = useUIStore()
  
  return (
    <button
      onClick={toggleMode}
      className={clsx(
        'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
        mode === 'beginner' 
          ? 'bg-blue-500/20 text-blue-400 hover:bg-blue-500/30'
          : 'bg-purple-500/20 text-purple-400 hover:bg-purple-500/30'
      )}
      title={`Switch to ${mode === 'beginner' ? 'Expert' : 'Beginner'} mode (Ctrl+Shift+M)`}
    >
      {mode === 'beginner' ? (
        <>
          <HelpCircle className="w-4 h-4" />
          <span>Beginner</span>
        </>
      ) : (
        <>
          <CheckCircle className="w-4 h-4" />
          <span>Expert</span>
        </>
      )}
    </button>
  )
}

// ============================================================================
// LOADING SPINNER
// ============================================================================

interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg'
}

export function Spinner({ size = 'md' }: SpinnerProps) {
  const sizeMap = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
  }
  
  return (
    <div className={clsx(
      sizeMap[size],
      'border-2 border-blue-500 border-t-transparent rounded-full animate-spin'
    )} />
  )
}

// ============================================================================
// ACTION CARD (for recommended actions)
// ============================================================================

interface ActionCardProps {
  priority: 'immediate' | 'soon' | 'when_convenient'
  title: string
  steps: string[]
  automated?: string[]
  collapsed?: boolean
}

export function ActionCard({ priority, title, steps, automated, collapsed = false }: ActionCardProps) {
  const [isExpanded, setIsExpanded] = React.useState(!collapsed)
  
  const priorityStyles = {
    immediate: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: 'Immediate' },
    soon: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: 'Soon' },
    when_convenient: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', label: 'Low Priority' },
  }
  
  const style = priorityStyles[priority]
  
  return (
    <div className={clsx('rounded-lg border', style.bg, style.border)}>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between p-3 text-left"
      >
        <div className="flex items-center gap-2">
          <span className={clsx('text-xs font-medium', style.text)}>{style.label}</span>
          <span className="text-sm text-white">{title}</span>
        </div>
        <ChevronRight className={clsx(
          'w-4 h-4 text-gray-500 transition-transform',
          isExpanded && 'rotate-90'
        )} />
      </button>
      
      {isExpanded && (
        <div className="px-3 pb-3 space-y-2">
          <ol className="space-y-1 text-sm text-gray-300">
            {steps.map((step, i) => (
              <li key={i} className="flex gap-2">
                <span className="text-gray-500">{i + 1}.</span>
                {step}
              </li>
            ))}
          </ol>
          
          {automated && automated.length > 0 && (
            <div className="mt-2 pt-2 border-t border-[#333]">
              <span className="text-xs text-gray-500">Automated options:</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {automated.map((option) => (
                  <button
                    key={option}
                    className="px-2 py-1 text-xs bg-[#262626] hover:bg-[#333] text-gray-300 rounded transition-colors"
                  >
                    {option}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
