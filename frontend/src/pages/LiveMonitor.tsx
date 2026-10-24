import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Square, AlertOctagon, ShieldCheck, HelpCircle,
  Activity, Sliders, RefreshCw, ChevronRight, X, ExternalLink,
  ShieldAlert, Info, Database, Zap, Radio, Wifi, Network
} from 'lucide-react'
import { api, FlowItem } from '../api/client'
import { useNavigate } from 'react-router-dom'

export default function LiveMonitor() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  // Ingestion Mode state: 'live' | 'synthetic' | 'dataset'
  const [trafficMode, setTrafficMode] = useState<'live' | 'synthetic' | 'dataset'>('live')
  const [selectedInterface, setSelectedInterface] = useState<string>('Wi-Fi')
  const [bpfFilter, setBpfFilter] = useState<string>('ip or ip6')
  const [delaySeconds, setDelaySeconds] = useState<number>(0.4)
  const [totalFlows, setTotalFlows] = useState<number>(100)
  const [c2Ratio, setC2Ratio] = useState<number>(0.35)
  const [onlySuspicious, setOnlySuspicious] = useState<boolean>(false)
  const [selectedFlow, setSelectedFlow] = useState<FlowItem | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  // Polling queries
  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
  })

  const statusQuery = useQuery({
    queryKey: ['monitorStatus'],
    queryFn: api.monitorStatus,
    refetchInterval: 1200,
  })

  const statsQuery = useQuery({
    queryKey: ['monitorStats'],
    queryFn: api.monitorStats,
    refetchInterval: 1200,
  })

  const flowsQuery = useQuery({
    queryKey: ['flows'],
    queryFn: () => api.flows(100),
    refetchInterval: 1200,
  })

  // Start Live Capture mutation
  const startLiveMutation = useMutation({
    mutationFn: () =>
      api.startLiveCapture({
        interface: selectedInterface || undefined,
        bpf_filter: bpfFilter,
      }),
    onSuccess: () => {
      setActionError(null)
      queryClient.invalidateQueries({ queryKey: ['monitorStatus'] })
      queryClient.invalidateQueries({ queryKey: ['monitorStats'] })
      queryClient.invalidateQueries({ queryKey: ['flows'] })
    },
    onError: (err: Error) => {
      setActionError(err.message)
    },
  })

  // Start Replay mutation
  const startReplayMutation = useMutation({
    mutationFn: () =>
      api.startReplay({
        mode: trafficMode === 'dataset' ? 'csv_tqh' : 'synthetic',
        delay_seconds: delaySeconds,
        total_flows: totalFlows,
        c2_ratio: c2Ratio,
      }),
    onSuccess: () => {
      setActionError(null)
      queryClient.invalidateQueries({ queryKey: ['monitorStatus'] })
      queryClient.invalidateQueries({ queryKey: ['monitorStats'] })
      queryClient.invalidateQueries({ queryKey: ['flows'] })
    },
    onError: (err: Error) => {
      setActionError(err.message)
    },
  })

  // Stop all ingestion mutation
  const stopMutation = useMutation({
    mutationFn: async () => {
      await api.stopLiveCapture().catch(() => {})
      await api.stopReplay().catch(() => {})
    },
    onSuccess: () => {
      setActionError(null)
      queryClient.invalidateQueries({ queryKey: ['monitorStatus'] })
      queryClient.invalidateQueries({ queryKey: ['flows'] })
    },
    onError: (err: Error) => {
      setActionError(err.message)
    },
  })

  const isCapturing = statusQuery.data?.capture_running ?? false
  const isReplaying = statusQuery.data?.replay_running ?? false
  const isIngesting = isCapturing || isReplaying || (statusQuery.data?.is_active ?? false)
  const stats = statsQuery.data || { total: 0, suspicious: 0, benign: 0, insufficient: 0 }
  const flows = flowsQuery.data || []
  const filteredFlows = onlySuspicious
    ? flows.filter((f) => f.verdict.is_suspicious || f.verdict.risk_tier === 'HIGH' || f.verdict.risk_tier === 'SUSPICIOUS')
    : flows

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  const getTierBadge = (tier: string) => {
    switch (tier?.toUpperCase()) {
      case 'HIGH':
      case 'SUSPICIOUS':
        return <span className="badge-danger font-mono font-semibold">{tier}</span>
      case 'BENIGN':
        return <span className="badge-success font-mono">{tier}</span>
      case 'INSUFFICIENT':
        return <span className="badge-warning font-mono">{tier}</span>
      default:
        return <span className="badge-neutral font-mono">{tier || 'UNKNOWN'}</span>
    }
  }

  return (
    <div className="space-y-6">
      {/* ── Status Bar / Header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-navy-800/90 border border-navy-600 rounded-xl p-4 backdrop-blur shadow-lg">
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-lg transition-all ${
            isIngesting
              ? 'bg-gradient-to-br from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/30'
              : 'bg-cyan-50 dark:bg-navy-900 border border-cyan-200 dark:border-cyan-500/30 text-cyan-600 dark:text-cyan-400'
          }`}>
            <Activity className={`w-5 h-5 ${isIngesting ? 'animate-pulse' : ''}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-white">Flow Monitoring Engine</h2>
              {isCapturing ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/25">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  Live Network Capture Active (Npcap)
                </span>
              ) : isReplaying ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/25">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
                  Streaming Replay Active
                </span>
              ) : statusQuery.data?.replay_finished ? (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-100 dark:bg-slate-700/60 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-600">
                  Replay Completed
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-400 border border-slate-300 dark:border-slate-700">
                  Standby
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Source: <span className="text-slate-300 font-medium">{statusQuery.data?.replay_source || 'None'}</span>
              {statusQuery.data?.elapsed_seconds ? ` · Analyzed: ${statusQuery.data.flows_streamed} flows (${statusQuery.data.elapsed_seconds.toFixed(1)}s)` : ''}
            </p>
          </div>
        </div>

        {/* Global Controls */}
        <div className="flex items-center gap-2">
          {isIngesting ? (
            <button
              onClick={() => stopMutation.mutate()}
              disabled={stopMutation.isPending}
              className="btn-danger flex items-center gap-2"
            >
              <Square className="w-4 h-4 fill-current" />
              <span>{isCapturing ? 'Stop Live Sniffer' : 'Stop Stream'}</span>
            </button>
          ) : trafficMode === 'live' ? (
            <button
              onClick={() => startLiveMutation.mutate()}
              disabled={startLiveMutation.isPending}
              className="btn-primary flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-bold shadow-sm shadow-emerald-600/30"
            >
              <Radio className="w-4 h-4 animate-pulse" />
              <span>Start Live Sniffing</span>
            </button>
          ) : (
            <button
              onClick={() => startReplayMutation.mutate()}
              disabled={startReplayMutation.isPending}
              className="btn-primary flex items-center gap-2 font-bold"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{trafficMode === 'dataset' ? 'Start Dataset Stream' : 'Start Replay'}</span>
            </button>
          )}
          <button
            onClick={() => {
              queryClient.invalidateQueries({ queryKey: ['flows'] })
              queryClient.invalidateQueries({ queryKey: ['monitorStats'] })
            }}
            className="btn-secondary p-2"
            title="Refresh feed"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {actionError && (
        <div className="banner-danger">
          <strong>Ingestion Error:</strong> {actionError}
        </div>
      )}

      {/* ── KPI Metric Cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4 border-l-4 border-l-cyan-500">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Analyzed</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white tracking-tight">
            {stats.total.toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {isCapturing ? 'Live network sessions evaluated' : 'Ingested network sessions'}
          </p>
        </div>

        <div className="card p-4 border-l-4 border-l-red-500 bg-red-950/10">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-red-400">Suspicious / High Risk</span>
            <AlertOctagon className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-red-400 tracking-tight">
            {stats.suspicious.toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {stats.total > 0 ? `${((stats.suspicious / stats.total) * 100).toFixed(1)}% threat detection rate` : 'No threat flows'}
          </p>
        </div>

        <div className="card p-4 border-l-4 border-l-emerald-500">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-emerald-400">Benign Traffic</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-400 tracking-tight">
            {stats.benign.toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Cleared baseline flows</p>
        </div>

        <div className="card p-4 border-l-4 border-l-amber-500">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-amber-400">Insufficient Data</span>
            <HelpCircle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-amber-400 tracking-tight">
            {stats.insufficient.toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Incomplete or short flows</p>
        </div>
      </div>

      {/* ── Mode Selection & Tuning Panel ── */}
      <div className="card p-4 bg-navy-800/80">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Sliders className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
            <span>Traffic Ingestion & Detection Controls</span>
          </div>
          {healthQuery.data?.is_npcap_installed && (
            <span className="badge-success text-[10px] font-mono">
              Npcap Driver Armed
            </span>
          )}
        </div>

        {/* Ingestion Mode Selector Tabs */}
        <div className="mb-4">
          <label className="block text-slate-400 mb-1.5 font-medium text-xs">Traffic Source Mode</label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => setTrafficMode('live')}
              disabled={isIngesting}
              className={`py-2 px-3 rounded-lg text-center transition flex items-center justify-center gap-2 font-bold text-xs ${
                trafficMode === 'live'
                  ? 'bg-emerald-100 dark:bg-emerald-950/70 border-2 border-emerald-600 dark:border-emerald-400 text-emerald-900 dark:text-emerald-200 shadow-sm'
                  : 'bg-white dark:bg-navy-900 border border-slate-300 dark:border-navy-600 text-slate-700 dark:text-slate-400 hover:text-emerald-700 dark:hover:text-emerald-300 hover:border-emerald-400'
              }`}
            >
              <Radio className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              <span>Live Network (Npcap)</span>
            </button>

            <button
              type="button"
              onClick={() => setTrafficMode('synthetic')}
              disabled={isIngesting}
              className={`py-2 px-3 rounded-lg text-center transition flex items-center justify-center gap-2 font-bold text-xs ${
                trafficMode === 'synthetic'
                  ? 'bg-cyan-100 dark:bg-cyan-950/70 border-2 border-cyan-600 dark:border-cyan-400 text-cyan-900 dark:text-cyan-200 shadow-sm'
                  : 'bg-white dark:bg-navy-900 border border-slate-300 dark:border-navy-600 text-slate-700 dark:text-slate-400 hover:text-cyan-700 dark:hover:text-cyan-300 hover:border-cyan-400'
              }`}
            >
              <Zap className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span>Synthetic C2 Generator</span>
            </button>

            <button
              type="button"
              onClick={() => setTrafficMode('dataset')}
              disabled={isIngesting}
              className={`py-2 px-3 rounded-lg text-center transition flex items-center justify-center gap-2 font-bold text-xs ${
                trafficMode === 'dataset'
                  ? 'bg-cyan-100 dark:bg-cyan-950/70 border-2 border-cyan-600 dark:border-cyan-400 text-cyan-900 dark:text-cyan-200 shadow-sm'
                  : 'bg-white dark:bg-navy-900 border border-slate-300 dark:border-navy-600 text-slate-700 dark:text-slate-400 hover:text-cyan-700 dark:hover:text-cyan-300 hover:border-cyan-400'
              }`}
            >
              <Database className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span>Dataset CSV Stream</span>
            </button>
          </div>
        </div>

        {/* Live Network Adapter Selector (when in Live mode) */}
        {trafficMode === 'live' ? (
          <div className="p-3 bg-navy-900/60 rounded-lg border border-navy-700/60 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-medium">Capture Network Adapter</label>
                <select
                  value={selectedInterface}
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  disabled={isIngesting}
                  className="input-field text-xs bg-navy-900 cursor-pointer"
                >
                  <option value="">Default (All Active Interfaces)</option>
                  {healthQuery.data?.interfaces?.map((iface: any) => (
                    <option key={iface.name} value={iface.name}>
                      {iface.name} {iface.is_up ? '· (Connected)' : '· (Disconnected)'}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Packet Filter (BPF)</label>
                <input
                  type="text"
                  value={bpfFilter}
                  onChange={(e) => setBpfFilter(e.target.value)}
                  disabled={isIngesting}
                  placeholder="e.g. ip or ip6, tcp, port 443"
                  className="input-field text-xs font-mono"
                />
              </div>
            </div>

            <div className="flex items-center gap-2 text-[11px] text-emerald-400 bg-emerald-950/20 border border-emerald-500/20 p-2 rounded">
              <Network className="w-4 h-4 flex-shrink-0" />
              <span>
                <strong>Live Sniffing Ready:</strong> Raw network packets flowing through your adapter are reconstructed into bidirectional TCP/UDP flow records, client TLS fingerprints (JA4) are extracted, and every session is evaluated by the live ML model.
              </span>
            </div>
          </div>
        ) : (
          /* Replay Tuning Controls (when in Synthetic or Dataset mode) */
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs pt-1">
            <div>
              <div className="flex justify-between text-slate-400 mb-1 font-medium">
                <span>Streaming Interval</span>
                <span className="font-mono text-cyan-700 dark:text-cyan-400 font-bold">{delaySeconds}s</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="2.0"
                step="0.1"
                value={delaySeconds}
                onChange={(e) => setDelaySeconds(parseFloat(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer"
                disabled={isIngesting}
              />
              <div className="flex justify-between text-[10px] text-slate-500 mt-0.5">
                <span>0.1s (Fast)</span>
                <span>2.0s (Slow)</span>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-400 mb-1 font-medium">
                <span>Batch Total Flows</span>
                <span className="font-mono text-cyan-700 dark:text-cyan-400 font-bold">{totalFlows}</span>
              </div>
              <input
                type="range"
                min="20"
                max="500"
                step="20"
                value={totalFlows}
                onChange={(e) => setTotalFlows(parseInt(e.target.value, 10))}
                className="w-full accent-cyan-500 cursor-pointer"
                disabled={isIngesting}
              />
              <div className="flex justify-between text-[10px] text-slate-500 mt-0.5">
                <span>20 flows</span>
                <span>500 flows</span>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-400 mb-1 font-medium">
                <span>C2 Threat Ratio</span>
                <span className="font-mono text-cyan-700 dark:text-cyan-400 font-bold">{(c2Ratio * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="0.8"
                step="0.05"
                value={c2Ratio}
                onChange={(e) => setC2Ratio(parseFloat(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer"
                disabled={isIngesting || trafficMode === 'dataset'}
              />
              <div className="flex justify-between text-[10px] text-slate-500 mt-0.5">
                <span>10% Low</span>
                <span>80% Heavy Attack</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Real-Time Flow Table ── */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-navy-600 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span>Evaluated Flow Feed</span>
              <span className="text-xs text-slate-400 font-normal">
                ({filteredFlows.length} {onlySuspicious ? 'suspicious' : 'recent'} flows)
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Click any row to view ML inference metrics, indicators of compromise, and evidence.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={onlySuspicious}
                onChange={(e) => setOnlySuspicious(e.target.checked)}
                className="rounded border-navy-600 text-cyan-500 focus:ring-0 bg-navy-900 cursor-pointer"
              />
              <span className="text-red-400 font-medium">Show Suspicious Only</span>
            </label>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-navy-900/90 text-slate-400 font-medium border-b border-navy-600 uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Source IP : Port</th>
                <th className="py-3 px-4">Destination IP : Port</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Volume</th>
                <th className="py-3 px-4">Risk Tier</th>
                <th className="py-3 px-4">ML Score</th>
                <th className="py-3 px-4">Detector</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-700/50">
              {filteredFlows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500">
                    <Activity className="w-8 h-8 mx-auto mb-2 text-slate-600 animate-pulse" />
                    <p className="text-sm font-medium text-slate-400">No network flows captured yet</p>
                    <p className="text-xs text-slate-500 mt-1">
                      Click <strong>Start Replay</strong> above to stream synthetic or dataset flows into the detection engine.
                    </p>
                  </td>
                </tr>
              ) : (
                filteredFlows.map((item) => {
                  const { flow, verdict } = item
                  const isSusp = verdict.is_suspicious || verdict.risk_tier === 'HIGH' || verdict.risk_tier === 'SUSPICIOUS'
                  return (
                    <tr
                      key={flow.flow_id}
                      onClick={() => setSelectedFlow(item)}
                      className={`cursor-pointer transition-colors hover:bg-navy-700/40 ${
                        isSusp ? 'bg-red-950/15' : ''
                      } ${selectedFlow?.flow.flow_id === flow.flow_id ? 'bg-cyan-950/30 ring-1 ring-cyan-500/50' : ''}`}
                    >
                      <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {flow.last_seen ? flow.last_seen.split(' ')[1] || flow.last_seen : '—'}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-200">
                        {flow.src_ip}
                        <span className="text-slate-500">:{flow.src_port}</span>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-200">
                        {flow.dst_ip}
                        <span className="text-slate-500">:{flow.dst_port}</span>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-400 font-semibold">{flow.proto}</td>
                      <td className="py-2.5 px-4 text-slate-400 font-mono">
                        {flow.tot_pkts} pkts · {formatBytes(flow.tot_bytes)}
                      </td>
                      <td className="py-2.5 px-4">{getTierBadge(verdict.risk_tier)}</td>
                      <td className="py-2.5 px-4 font-mono">
                        {verdict.raw_score !== null && verdict.raw_score !== undefined ? (
                          <span
                            className={
                              verdict.raw_score >= 0.7
                                ? 'text-red-400 font-bold'
                                : verdict.raw_score >= 0.4
                                ? 'text-amber-400'
                                : 'text-slate-400'
                            }
                          >
                            {verdict.raw_score.toFixed(3)}
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">
                        <span className="text-[11px] truncate max-w-[120px] inline-block" title={verdict.detection_source}>
                          {verdict.detection_source}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          type="button"
                          className="text-slate-400 hover:text-cyan-400 p-1"
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedFlow(item)
                          }}
                        >
                          <ChevronRight className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Flow Verdict & Evidence Drawer / Modal ── */}
      {selectedFlow && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm p-0">
          <div
            className="w-full max-w-xl h-full bg-navy-800 border-l border-navy-600 flex flex-col shadow-2xl overflow-hidden animate-slide-in"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drawer Header */}
            <div className="p-5 border-b border-navy-600 flex items-center justify-between bg-navy-900/60">
              <div className="flex items-center gap-3">
                <div
                  className={`p-2 rounded-lg ${
                    selectedFlow.verdict.is_suspicious ? 'bg-red-500/20 text-red-400' : 'bg-cyan-500/20 text-cyan-400'
                  }`}
                >
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Flow Verdict Breakdown</h3>
                  <p className="text-xs text-slate-400 font-mono truncate max-w-[320px]">
                    ID: {selectedFlow.flow.flow_id}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedFlow(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-navy-700 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Body */}
            <div className="flex-1 overflow-y-auto p-5 space-y-5">
              {/* Verdict Summary Card */}
              <div className="card p-4 bg-navy-900/60 border border-navy-600 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Classification Tier</span>
                  {getTierBadge(selectedFlow.verdict.risk_tier)}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">ML Confidence Score</span>
                  <span className="text-base font-mono font-bold text-cyan-400">
                    {selectedFlow.verdict.raw_score !== null && selectedFlow.verdict.raw_score !== undefined
                      ? selectedFlow.verdict.raw_score.toFixed(4)
                      : 'N/A'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Detection Pipeline</span>
                  <span className="text-xs text-slate-300 font-medium">{selectedFlow.verdict.detection_source}</span>
                </div>
                {selectedFlow.verdict.model_name && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">Model Name</span>
                    <span className="text-xs font-mono text-slate-300">{selectedFlow.verdict.model_name}</span>
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Applied Threshold</span>
                  <span className="text-xs font-mono text-slate-300">
                    {selectedFlow.verdict.threshold_applied ?? 0.5}
                  </span>
                </div>
              </div>

              {/* Network Session Details */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Session Metadata</h4>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="bg-navy-900/80 p-2.5 rounded-lg border border-navy-700">
                    <span className="text-slate-500 block text-[10px]">Source</span>
                    <span className="font-mono text-slate-200">
                      {selectedFlow.flow.src_ip}:{selectedFlow.flow.src_port}
                    </span>
                  </div>
                  <div className="bg-navy-900/80 p-2.5 rounded-lg border border-navy-700">
                    <span className="text-slate-500 block text-[10px]">Destination</span>
                    <span className="font-mono text-slate-200">
                      {selectedFlow.flow.dst_ip}:{selectedFlow.flow.dst_port}
                    </span>
                  </div>
                  <div className="bg-navy-900/80 p-2.5 rounded-lg border border-navy-700">
                    <span className="text-slate-500 block text-[10px]">Protocol / State</span>
                    <span className="font-mono text-slate-200">
                      {selectedFlow.flow.proto} · {selectedFlow.flow.conn_state || 'ESTABLISHED'}
                    </span>
                  </div>
                  <div className="bg-navy-900/80 p-2.5 rounded-lg border border-navy-700">
                    <span className="text-slate-500 block text-[10px]">Duration</span>
                    <span className="font-mono text-slate-200">{selectedFlow.flow.duration.toFixed(3)}s</span>
                  </div>
                  <div className="bg-navy-900/80 p-2.5 rounded-lg border border-navy-700">
                    <span className="text-slate-500 block text-[10px]">Total Packets</span>
                    <span className="font-mono text-slate-200">
                      {selectedFlow.flow.tot_pkts} (orig: {selectedFlow.flow.orig_pkts}, resp: {selectedFlow.flow.resp_pkts})
                    </span>
                  </div>
                  <div className="bg-navy-900/80 p-2.5 rounded-lg border border-navy-700">
                    <span className="text-slate-500 block text-[10px]">Total Volume</span>
                    <span className="font-mono text-slate-200">{formatBytes(selectedFlow.flow.tot_bytes)}</span>
                  </div>
                </div>
              </div>

              {/* Fingerprinting & Threat Indicators */}
              {(selectedFlow.flow.sni || selectedFlow.flow.ja4) && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                    TLS & Fingerprint Data
                  </h4>
                  <div className="space-y-2 text-xs">
                    {selectedFlow.flow.sni && (
                      <div className="bg-navy-900/80 p-2.5 rounded-lg border border-navy-700">
                        <span className="text-slate-500 block text-[10px]">Server Name Indication (SNI)</span>
                        <span className="font-mono text-cyan-300 font-semibold">{selectedFlow.flow.sni}</span>
                      </div>
                    )}
                    {selectedFlow.flow.ja4 && (
                      <div className="bg-navy-900/80 p-2.5 rounded-lg border border-navy-700">
                        <span className="text-slate-500 block text-[10px]">JA4 TLS Client Fingerprint</span>
                        <span className="font-mono text-amber-300 text-[11px] break-all">{selectedFlow.flow.ja4}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Evidence Indicators */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  Detection Evidence ({selectedFlow.verdict.evidence?.length || 0})
                </h4>
                {selectedFlow.verdict.evidence && selectedFlow.verdict.evidence.length > 0 ? (
                  <div className="space-y-2">
                    {selectedFlow.verdict.evidence.map((ev, idx) => (
                      <div key={idx} className="bg-navy-900/80 p-3 rounded-lg border border-navy-700 text-xs">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-medium text-slate-200">{ev.indicator}</span>
                          <span
                            className={`badge text-[10px] uppercase font-mono ${
                              ev.confidence?.toLowerCase() === 'high'
                                ? 'badge-danger'
                                : ev.confidence?.toLowerCase() === 'medium'
                                ? 'badge-warning'
                                : 'badge-neutral'
                            }`}
                          >
                            {ev.confidence} Conf.
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px] leading-relaxed">{ev.description}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic bg-navy-900/40 p-3 rounded-lg border border-navy-800">
                    No specific threat indicators flagged for this flow.
                  </p>
                )}
              </div>

              {/* Detection Limitations */}
              {selectedFlow.verdict.limitations && selectedFlow.verdict.limitations.length > 0 && (
                <div className="bg-amber-950/20 border border-amber-500/20 rounded-lg p-3 text-xs">
                  <div className="flex items-center gap-1.5 text-amber-400 font-medium mb-1">
                    <Info className="w-3.5 h-3.5" />
                    <span>Inference Limitations</span>
                  </div>
                  <ul className="list-disc list-inside text-slate-400 space-y-1 text-[11px]">
                    {selectedFlow.verdict.limitations.map((lim, idx) => (
                      <li key={idx}>{lim}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Drawer Actions Footer */}
            <div className="p-4 border-t border-navy-600 bg-navy-900/90 flex items-center justify-between gap-3">
              <button
                type="button"
                onClick={() => {
                  navigate(`/response?ip=${encodeURIComponent(selectedFlow.flow.src_ip)}`)
                }}
                className="btn-danger text-xs flex items-center gap-1.5 flex-1 justify-center"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                Block Source IP
              </button>
              <button
                type="button"
                onClick={() => {
                  navigate('/incidents')
                }}
                className="btn-secondary text-xs flex items-center gap-1.5 flex-1 justify-center"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                View Incidents
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
