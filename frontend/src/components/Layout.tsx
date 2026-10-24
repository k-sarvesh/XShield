import { NavLink, useLocation } from 'react-router-dom'
import {
  Activity, AlertTriangle, Shield, BarChart3, HeartPulse,
  Wifi, WifiOff, Radio
} from 'lucide-react'
import type { HealthData } from '../api/client'
import ThemeToggle from './ThemeToggle'

interface LayoutProps {
  children: React.ReactNode
  health?: HealthData
  isConnected: boolean
  isLoading: boolean
}

const navItems = [
  { to: '/monitor', icon: Activity, label: 'Live Monitor' },
  { to: '/incidents', icon: AlertTriangle, label: 'Alerts & Incidents' },
  { to: '/response', icon: Shield, label: 'Network Response' },
  { to: '/history', icon: BarChart3, label: 'Historical Analysis' },
  { to: '/health', icon: HeartPulse, label: 'System Health' },
]

export default function Layout({ children, health, isConnected, isLoading }: LayoutProps) {
  const location = useLocation()

  return (
    <div className="flex h-screen overflow-hidden">
      {/* ── Sidebar ── */}
      <aside className="w-64 flex-shrink-0 bg-navy-800 border-r border-navy-600 flex flex-col">
        {/* Branding */}
        <div className="px-5 py-5 border-b border-navy-600">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">XShield</h1>
              <p className="text-[10px] text-slate-500 font-medium uppercase tracking-widest">Security Dashboard</p>
            </div>
          </div>
          <p className="text-[10px] text-slate-600 mt-2">
            v{health?.api_version || '5.0.0'} · ML-Assisted Threat Intel
          </p>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => isActive ? 'nav-link-active' : 'nav-link-inactive'}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Sidebar Footer */}
        <div className="px-4 py-3 border-t border-navy-600 space-y-2">
          <div className="flex items-center gap-2 text-xs">
            {isConnected ? (
              <>
                <span className="status-dot bg-emerald-400 animate-pulse-dot" />
                <span className="text-emerald-400">Backend Connected</span>
              </>
            ) : isLoading ? (
              <>
                <span className="status-dot bg-amber-400 animate-pulse-dot" />
                <span className="text-amber-400">Connecting…</span>
              </>
            ) : (
              <>
                <span className="status-dot bg-red-400" />
                <span className="text-red-400">Disconnected</span>
              </>
            )}
          </div>
          {health && (
            <div className="text-[10px] text-slate-600">
              Mode: {health.response_mode} · {health.recommended_mode === 'replay' ? 'Replay' : 'Live'}
            </div>
          )}
        </div>
      </aside>

      {/* ── Main Area ── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar */}
        <header className="h-12 flex-shrink-0 bg-navy-800/80 backdrop-blur border-b border-navy-600 flex items-center justify-between px-6">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold text-slate-200">
              {navItems.find(n => n.to === location.pathname)?.label || 'XShield'}
            </h2>
            {health?.runtime_active && (
              <span className="flex items-center gap-1.5 text-xs text-cyan-400">
                <Radio className="w-3 h-3 animate-pulse" />
                Ingestion Active
              </span>
            )}
          </div>
          <div className="flex items-center gap-4 text-xs text-slate-500">
            {health && (
              <>
                {health.is_npcap_installed ? (
                  <span className="text-emerald-500 dark:text-emerald-400 flex items-center gap-1 font-semibold">
                    <Radio className="w-3 h-3 text-emerald-500 animate-pulse" />
                    Npcap Driver Ready
                  </span>
                ) : (
                  <span className="text-amber-500 dark:text-amber-400 flex items-center gap-1">
                    <WifiOff className="w-3 h-3" />
                    Npcap Not Detected
                  </span>
                )}
                <span>
                  {isConnected ? (
                    <span className="flex items-center gap-1 text-slate-400">
                      <Wifi className="w-3 h-3" /> API OK
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-red-400">
                      <WifiOff className="w-3 h-3" /> API Down
                    </span>
                  )}
                </span>
                <span className="text-slate-600">|</span>
                <span>{new Date(health.timestamp).toLocaleTimeString()}</span>
              </>
            )}
            <div className="pl-1 border-l border-navy-600">
              <ThemeToggle />
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-y-auto p-6">
          {/* Environmental Banners */}
          {health && !health.is_npcap_installed && (
            <div className="banner-warning mb-4">
              <strong>⚠ Capture Driver Notice:</strong> Npcap driver not detected.
              Live promiscuous sniffing requires Npcap. <strong>Deterministic Replay Engine</strong> is active for demonstration.
            </div>
          )}
          {health?.response_mode === 'SIMULATION' && (
            <div className="banner-simulation mb-4">
              <strong>🛡 Safety Notice — Simulation Mode Active:</strong> All blocking actions are recorded
              without modifying Windows Firewall. Zero risk of network disruption.
            </div>
          )}
          {!isConnected && !isLoading && (
            <div className="banner-danger mb-4">
              <strong>Backend Disconnected.</strong> Cannot reach XShield API at 127.0.0.1:8000.
              Start the backend with: <code className="font-mono text-xs bg-red-900/40 px-1 rounded">python -m uvicorn api_server:app --port 8000</code>
            </div>
          )}

          {children}
        </main>
      </div>
    </div>
  )
}
