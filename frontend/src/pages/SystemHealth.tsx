import React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  HeartPulse, Shield, Cpu, Network, CheckCircle2,
  AlertTriangle, XCircle, RefreshCw, Key, HardDrive
} from 'lucide-react'
import { api } from '../api/client'

export default function SystemHealth() {
  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 5000,
  })

  const health = healthQuery.data

  return (
    <div className="space-y-6">
      {/* ── Status Header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-navy-800/80 border border-navy-600 rounded-xl p-5 shadow-lg">
        <div className="flex items-center gap-3.5">
          <div className="p-3 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white shadow-cyan-500/20 shadow-lg">
            <HeartPulse className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-tight">System Health & Telemetry</h2>
              <span className="badge-success text-xs font-mono font-semibold">
                API {health?.api_version || '5.0.0'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Host Environment Diagnostics · Windows Driver Readiness · ML Model Integrity
            </p>
          </div>
        </div>

        <button
          onClick={() => healthQuery.refetch()}
          className="btn-secondary text-xs flex items-center gap-1.5 py-2 px-3.5 self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Diagnostics</span>
        </button>
      </div>

      {/* ── Core Health Indicators ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Npcap Packet Driver */}
        <div className={`card p-4 border-l-4 ${health?.is_npcap_installed ? 'border-l-emerald-500' : 'border-l-amber-500'}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Capture Driver</span>
            {health?.is_npcap_installed ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
          </div>
          <div className="mt-2 text-base font-bold text-white">
            {health?.is_npcap_installed ? 'Npcap Driver Active' : 'Npcap Driver Not Found'}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {health?.is_npcap_installed
              ? 'Promiscuous packet sniffing enabled.'
              : 'Required for live sniffing. Replay mode active.'}
          </p>
        </div>

        {/* Admin Elevation */}
        <div className={`card p-4 border-l-4 ${health?.is_admin ? 'border-l-emerald-500' : 'border-l-slate-500'}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Process Privilege</span>
            <Key className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-base font-bold text-white">
            {health?.is_admin ? 'Administrator / Elevated' : 'Standard User'}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {health?.is_admin
              ? 'Can execute live firewall modifications.'
              : 'Simulation mode enforced for safety.'}
          </p>
        </div>

        {/* Runtime Engine */}
        <div className={`card p-4 border-l-4 ${health?.runtime_active ? 'border-l-cyan-500' : 'border-l-slate-600'}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Ingestion Runtime</span>
            <HardDrive className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-base font-bold text-white">
            {health?.runtime_active ? 'Active & Ingesting' : 'Idle / Standby'}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Single-instance memory aggregation queue.
          </p>
        </div>

        {/* Response Mode */}
        <div className="card p-4 border-l-4 border-l-blue-500">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Response Mode</span>
            <Shield className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2 text-base font-bold text-white">
            {health?.response_mode || 'SIMULATION'}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Zero-risk simulated containment ledger.
          </p>
        </div>
      </div>

      {/* ── Detection Models ── */}
      <div className="card p-5 bg-navy-800/90">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Active Machine Learning Threat Models</span>
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Models trained to detect Command & Control (C2) beaconing, irregular periodicity, and abnormal flow volumes.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {health?.models && Object.keys(health.models).length > 0 ? (
            Object.entries(health.models).map(([name, info]) => (
              <div key={name} className="p-4 rounded-xl bg-navy-900 border border-navy-700 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-slate-200 text-xs">{name}</span>
                  {info.is_available ? (
                    <span className="badge-success text-[10px] font-mono">AVAILABLE</span>
                  ) : (
                    <span className="badge-danger text-[10px] font-mono">UNAVAILABLE</span>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs pt-1 border-t border-navy-800">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Feature Vector Count</span>
                    <span className="font-mono text-cyan-400 font-bold">{info.feature_count} features</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Port Feature Policy</span>
                    <span className="font-mono text-slate-300">{info.port_policy}</span>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="col-span-2 text-xs text-slate-500 italic p-4 bg-navy-900 rounded-lg">
              No models currently registered in the manifest directory.
            </div>
          )}
        </div>
      </div>

      {/* ── Discovered Network Interfaces ── */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-navy-600 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <span>Host Network Interfaces</span>
              <span className="text-xs text-slate-400 font-normal">
                ({health?.interfaces?.length || 0} interfaces detected)
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Available network adapters for packet capture and promiscuous inspection.
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-navy-900/90 text-slate-400 font-medium border-b border-navy-600 uppercase tracking-wider text-[11px]">
                <th className="py-2.5 px-4">Adapter Name</th>
                <th className="py-2.5 px-4">Description</th>
                <th className="py-2.5 px-4">IPv4 / IPv6 Addresses</th>
                <th className="py-2.5 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-700/50">
              {!health?.interfaces || health.interfaces.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500">
                    No physical or virtual network interfaces enumerated.
                  </td>
                </tr>
              ) : (
                health.interfaces.map((iface, idx) => {
                  const name = String(iface.name || iface.description || `Adapter ${idx + 1}`)
                  const ips = Array.isArray(iface.ips) ? iface.ips.join(', ') : String(iface.ip || '—')
                  return (
                    <tr key={idx} className="hover:bg-navy-700/40 transition">
                      <td className="py-2.5 px-4 font-mono font-medium text-slate-200">{name}</td>
                      <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                        {String(iface.description || iface.guid || 'Ethernet / Wi-Fi Adapter')}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-cyan-400 text-[11px]">{ips}</td>
                      <td className="py-2.5 px-4">
                        <span className="badge-success text-[10px]">READY</span>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
