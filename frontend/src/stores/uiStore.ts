/**
 * UI State Store
 * 
 * Manages UI preferences including:
 * - Beginner vs Expert mode
 * - Theme preferences
 * - Panel states
 */

import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type UserMode = 'beginner' | 'expert'

interface UIState {
  // Mode
  mode: UserMode
  setMode: (mode: UserMode) => void
  toggleMode: () => void
  
  // Panels
  sidebarCollapsed: boolean
  setSidebarCollapsed: (collapsed: boolean) => void
  
  // Network Map preferences
  networkMapLayout: 'force' | 'hierarchical' | 'circular'
  setNetworkMapLayout: (layout: 'force' | 'hierarchical' | 'circular') => void
  showNetworkLabels: boolean
  setShowNetworkLabels: (show: boolean) => void
  
  // Packet view preferences
  packetAutoScroll: boolean
  setPacketAutoScroll: (auto: boolean) => void
  packetDisplayLimit: number
  setPacketDisplayLimit: (limit: number) => void
  
  // Alert preferences
  alertSoundEnabled: boolean
  setAlertSoundEnabled: (enabled: boolean) => void
  alertDesktopNotifications: boolean
  setAlertDesktopNotifications: (enabled: boolean) => void
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      // Mode - default to beginner for safety
      mode: 'beginner',
      setMode: (mode) => set({ mode }),
      toggleMode: () => set((state) => ({ 
        mode: state.mode === 'beginner' ? 'expert' : 'beginner' 
      })),
      
      // Panels
      sidebarCollapsed: false,
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
      
      // Network Map
      networkMapLayout: 'force',
      setNetworkMapLayout: (layout) => set({ networkMapLayout: layout }),
      showNetworkLabels: true,
      setShowNetworkLabels: (show) => set({ showNetworkLabels: show }),
      
      // Packets
      packetAutoScroll: true,
      setPacketAutoScroll: (auto) => set({ packetAutoScroll: auto }),
      packetDisplayLimit: 500,
      setPacketDisplayLimit: (limit) => set({ packetDisplayLimit: limit }),
      
      // Alerts
      alertSoundEnabled: true,
      setAlertSoundEnabled: (enabled) => set({ alertSoundEnabled: enabled }),
      alertDesktopNotifications: false,
      setAlertDesktopNotifications: (enabled) => set({ alertDesktopNotifications: enabled }),
    }),
    {
      name: 'netmonitor-ui',
    }
  )
)
