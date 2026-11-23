import { Doughnut } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js'

ChartJS.register(ArcElement, Tooltip, Legend)

interface TrafficSummary {
  tcp_percentage: number
  udp_percentage: number
  icmp_percentage: number
  http_packets: number
  https_packets: number
  dns_packets: number
}

interface TrafficChartProps {
  summary?: TrafficSummary
}

export default function TrafficChart({ summary }: TrafficChartProps) {
  if (!summary) {
    return (
      <div className="h-64 flex items-center justify-center text-gray-400">
        No traffic data available
      </div>
    )
  }

  const data = {
    labels: ['TCP', 'UDP', 'ICMP', 'Other'],
    datasets: [
      {
        data: [
          summary.tcp_percentage,
          summary.udp_percentage,
          summary.icmp_percentage,
          Math.max(0, 100 - summary.tcp_percentage - summary.udp_percentage - summary.icmp_percentage),
        ],
        backgroundColor: [
          'rgba(59, 130, 246, 0.8)',  // Blue - TCP
          'rgba(34, 197, 94, 0.8)',   // Green - UDP
          'rgba(168, 85, 247, 0.8)',  // Purple - ICMP
          'rgba(107, 114, 128, 0.8)', // Gray - Other
        ],
        borderColor: [
          'rgba(59, 130, 246, 1)',
          'rgba(34, 197, 94, 1)',
          'rgba(168, 85, 247, 1)',
          'rgba(107, 114, 128, 1)',
        ],
        borderWidth: 2,
      },
    ],
  }

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: {
          color: '#9ca3af',
          padding: 15,
          usePointStyle: true,
          pointStyle: 'circle',
        },
      },
      tooltip: {
        backgroundColor: '#1a1a1a',
        titleColor: '#fff',
        bodyColor: '#9ca3af',
        borderColor: '#2a2a2a',
        borderWidth: 1,
        padding: 12,
        callbacks: {
          label: (context: any) => `${context.label}: ${context.raw.toFixed(1)}%`,
        },
      },
    },
    cutout: '60%',
  }

  return (
    <div className="h-64">
      <Doughnut data={data} options={options} />
    </div>
  )
}
