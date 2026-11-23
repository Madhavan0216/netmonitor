/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Dark theme colors
        dark: {
          bg: '#0f0f0f',
          card: '#1a1a1a',
          border: '#2a2a2a',
          hover: '#252525',
        },
        // Severity colors
        severity: {
          info: '#3b82f6',
          warning: '#f59e0b',
          critical: '#ef4444',
        },
        // Protocol colors
        protocol: {
          tcp: '#3b82f6',
          udp: '#22c55e',
          icmp: '#a855f7',
          dns: '#f59e0b',
          http: '#06b6d4',
          https: '#10b981',
          arp: '#ec4899',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.3s ease-in-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
