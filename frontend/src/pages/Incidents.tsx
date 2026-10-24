import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, Shield, Search, Filter, Download,
  CheckCircle2, Clock, AlertOctagon, X, Save,
  ArrowRight, RefreshCw, FileText, Network, Radio, Zap, ShieldAlert
} from 'lucide-react'
import { api, IncidentData } from '../api/client'
import { useNavigate } from 'react-router-dom'

export default function Incidents() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  // Filters state
  const [statusFilter, setStatusFilter] = useState<string>('All')
  const [severityFilter, setSeverityFilter] = useState<string>('All')
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [limit, setLimit] = useState<number>(50)

  // Drawer / Triage state
  const [selectedIncident, setSelectedIncident] = useState<IncidentData | null>(null)
  const [triageStatus, setTriageStatus] = useState<string>('')
  const [triageNotes, setTriageNotes] = useState<string>('')
  const [triageAction, setTriageAction] = useState<string>('')
  const [saveSuccessMsg, setSaveSuccessMsg] = useState<string | null>(null)
  const [anonymizeExport, setAnonymizeExport] = useState<boolean>(false)

  // Query traffic analytics for network banner
  const trafficQuery = useQuery({
    queryKey: ['trafficAnalytics'],
    queryFn: api.trafficAnalytics,
    refetchInterval: 4000,
  })

  // Threat simulation mutation
  const [simulatingThreat, setSimulatingThreat] = useState<string | null>(null)
  const simulateMutation = useMutation({
    mutationFn: (threatType: string) => api.simulateThreat(threatType),
    onSuccess: (data) => {
      setSimulatingThreat(null)
      setSaveSuccessMsg(`Threat simulated successfully: ${data.threat_type} flow evaluated as ${data.verdict.risk_tier}.`)
      setTimeout(() => setSaveSuccessMsg(null), 4000)
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      queryClient.invalidateQueries({ queryKey: ['incidentSummary'] })
      queryClient.invalidateQueries({ queryKey: ['trafficAnalytics'] })
    },
    onError: (err: any) => {
      setSimulatingThreat(null)
      alert(`Simulation failed: ${err.message}`)
    }
  })

  // Query summary
  const summaryQuery = useQuery({
    queryKey: ['incidentSummary'],
    queryFn: api.incidentSummary,
    refetchInterval: 3000,
  })

  // Query incidents list
  const incidentsQuery = useQuery({
    queryKey: ['incidents', statusFilter, severityFilter, searchQuery, limit],
    queryFn: () =>
      api.incidents({
        status_filter: statusFilter,
        severity_filter: severityFilter,
        search_query: searchQuery,
        limit,
      }),
    refetchInterval: 3000,
  })

  // Update incident mutation
  const updateMutation = useMutation({
    mutationFn: ({
      id,
      status,
      notes,
      action,
    }: {
      id: string
      status: string
      notes?: string
      action?: string
    }) =>
      api.updateIncident(id, {
        status,
        analyst_notes: notes,
        response_action: action,
      }),
    onSuccess: (_, variables) => {
      setSaveSuccessMsg('Incident record updated successfully.')
      setTimeout(() => setSaveSuccessMsg(null), 3000)
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      queryClient.invalidateQueries({ queryKey: ['incidentSummary'] })
      if (selectedIncident && selectedIncident.incident_id === variables.id) {
        setSelectedIncident({
          ...selectedIncident,
          status: variables.status,
          analyst_notes: variables.notes || selectedIncident.analyst_notes,
          response_action: variables.action || selectedIncident.response_action,
        })
      }
    },
  })

  const openTriage = (inc: IncidentData) => {
    setSelectedIncident(inc)
    setTriageStatus(inc.status || 'OPEN')
    setTriageNotes(inc.analyst_notes || '')
    setTriageAction(inc.response_action || 'NONE')
    setSaveSuccessMsg(null)
  }

  const handleExportCsv = async () => {
    try {
      const csvText = await api.exportIncidentsCsv(anonymizeExport)
      const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `xshield_incidents_${anonymizeExport ? 'anonymized_' : ''}${Date.now()}.csv`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
    } catch (err) {
      alert(`Export failed: ${(err as Error).message}`)
    }
  }

  const summary = summaryQuery.data || {
    total_incidents: 0,
    high_severity: 0,
    active_investigations: 0,
    resolved: 0,
    blocks_recorded: 0,
  }

  const incidents = incidentsQuery.data || []

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL':
        return <span className="badge-danger font-mono font-bold tracking-wider">CRITICAL</span>
      case 'HIGH':
        return <span className="badge-danger font-mono font-medium">HIGH</span>
      case 'MEDIUM':
        return <span className="badge-warning font-mono font-medium">MEDIUM</span>
      case 'LOW':
        return <span className="badge-neutral font-mono font-medium">LOW</span>
      default:
        return <span className="badge-neutral font-mono">{sev || 'UNKNOWN'}</span>
    }
  }

  const getStatusBadge = (st: string) => {
    switch (st?.toUpperCase()) {
      case 'OPEN':
        return <span className="badge-danger text-[10px]">OPEN</span>
      case 'INVESTIGATING':
        return <span className="badge-warning text-[10px]">INVESTIGATING</span>
      case 'RESOLVED':
        return <span className="badge-success text-[10px]">RESOLVED</span>
      case 'FALSE_POSITIVE':
        return <span className="badge-neutral text-[10px]">FALSE POSITIVE</span>
      default:
        return <span className="badge-neutral text-[10px]">{st}</span>
    }
  }

  return (
    <div className="space-y-6">
      {/* ── Live Network Traffic Context Banner ── */}
      <div className="bg-navy-800/90 border border-navy-600 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-500 border border-emerald-500/30">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-white">Live Network Traffic Incident Ledger</h2>
              <span className="badge-success text-[10px] font-mono">
                {trafficQuery.data?.host_network?.active_interface || 'Wi-Fi'} · Npcap Ready
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Continuously cross-referencing real host packets (Host IP: {trafficQuery.data?.host_network?.host_ip || '10.237.120.166'}) against ML threat models.
            </p>
          </div>
        </div>

        {/* Threat Vector Simulation Action Bar */}
        <div className="flex items-center flex-wrap gap-2 text-xs">
          <span className="text-[11px] text-slate-400 font-medium">Inject Threat:</span>
          <button
            onClick={() => simulateMutation.mutate('c2_beacon')}
            disabled={simulateMutation.isPending}
            className="btn-secondary py-1 px-2.5 text-xs flex items-center gap-1.5 border-red-500/40 text-red-700 dark:text-red-300 hover:bg-red-950/40"
            title="Inject C2 Beacon on port 8443"
          >
            <Zap className="w-3.5 h-3.5 text-red-500" />
            <span>C2 Beacon</span>
          </button>
          <button
            onClick={() => simulateMutation.mutate('port_scan')}
            disabled={simulateMutation.isPending}
            className="btn-secondary py-1 px-2.5 text-xs flex items-center gap-1.5 border-amber-500/40 text-amber-700 dark:text-amber-300 hover:bg-amber-950/40"
            title="Inject internal SMB port scan on port 445"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
            <span>SMB Recon</span>
          </button>
          <button
            onClick={() => simulateMutation.mutate('dns_tunnel')}
            disabled={simulateMutation.isPending}
            className="btn-secondary py-1 px-2.5 text-xs flex items-center gap-1.5 border-purple-500/40 text-purple-700 dark:text-purple-300 hover:bg-purple-950/40"
            title="Inject base64 DNS tunneling exfiltration on port 53"
          >
            <Network className="w-3.5 h-3.5 text-purple-500" />
            <span>DNS Exfil</span>
          </button>
        </div>
      </div>

      {/* ── Metric Summary Cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <div className="card p-3.5 border-l-4 border-l-slate-400">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Logged</span>
            <AlertTriangle className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-white">
            {summary.total_incidents.toLocaleString()}
          </div>
          <p className="text-[10px] text-slate-500 mt-0.5">Recorded incidents</p>
        </div>

        <div className="card p-3.5 border-l-4 border-l-red-500 bg-red-950/10">
          <div className="flex items-center justify-between text-xs text-red-400">
            <span>High Severity</span>
            <AlertOctagon className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-red-400">
            {summary.high_severity.toLocaleString()}
          </div>
          <p className="text-[10px] text-slate-500 mt-0.5">Critical / High priority</p>
        </div>

        <div className="card p-3.5 border-l-4 border-l-amber-500">
          <div className="flex items-center justify-between text-xs text-amber-400">
            <span>Investigating</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-amber-400">
            {summary.active_investigations.toLocaleString()}
          </div>
          <p className="text-[10px] text-slate-500 mt-0.5">Under active review</p>
        </div>

        <div className="card p-3.5 border-l-4 border-l-emerald-500">
          <div className="flex items-center justify-between text-xs text-emerald-400">
            <span>Resolved</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-emerald-400">
            {summary.resolved.toLocaleString()}
          </div>
          <p className="text-[10px] text-slate-500 mt-0.5">Remediated / Closed</p>
        </div>

        <div className="card p-3.5 border-l-4 border-l-cyan-500">
          <div className="flex items-center justify-between text-xs text-cyan-400">
            <span>Firewall Blocks</span>
            <Shield className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-cyan-400">
            {summary.blocks_recorded.toLocaleString()}
          </div>
          <p className="text-[10px] text-slate-500 mt-0.5">Mitigations applied</p>
        </div>
      </div>

      {/* ── Search, Filters & Export Bar ── */}
      <div className="card p-4 bg-navy-800/80 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex-1 flex flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative min-w-[220px] flex-1 max-w-sm">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search IP, protocol, analyst note..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input-field pl-9 text-xs w-full"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="input-field text-xs py-1.5 bg-navy-900 cursor-pointer"
              >
                <option value="All">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {/* Status Filter */}
            <div className="text-xs text-slate-400">
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="input-field text-xs py-1.5 bg-navy-900 cursor-pointer"
              >
                <option value="All">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False Positive</option>
              </select>
            </div>

            {/* Limit Filter */}
            <div className="text-xs text-slate-400">
              <select
                value={limit}
                onChange={(e) => setLimit(parseInt(e.target.value, 10))}
                className="input-field text-xs py-1.5 bg-navy-900 cursor-pointer"
              >
                <option value={25}>Show 25</option>
                <option value={50}>Show 50</option>
                <option value={100}>Show 100</option>
                <option value={200}>Show 200</option>
              </select>
            </div>
          </div>

          {/* Export Actions */}
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={anonymizeExport}
                onChange={(e) => setAnonymizeExport(e.target.checked)}
                className="rounded border-navy-600 text-cyan-500 focus:ring-0 bg-navy-900 cursor-pointer"
              />
              <span>Anonymize IPs</span>
            </label>
            <button
              onClick={handleExportCsv}
              className="btn-secondary text-xs flex items-center gap-1.5 py-1.5"
              title="Export filtered records to CSV"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
            <button
              onClick={() => queryClient.invalidateQueries({ queryKey: ['incidents'] })}
              className="btn-secondary p-1.5"
              title="Refresh incidents"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ── Incidents Table ── */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-navy-900/90 text-slate-400 font-medium border-b border-navy-600 uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Created</th>
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Offender IP : Port</th>
                <th className="py-3 px-4">Destination IP</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Detection Engine</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-center">Hits</th>
                <th className="py-3 px-4 text-right">Triage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-700/50">
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-500">
                    <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                    <p className="text-sm font-medium text-slate-400">No matching incident records found</p>
                    <p className="text-xs text-slate-500 mt-1">
                      Check your filters or trigger simulated attacks in the Live Monitor tab.
                    </p>
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => openTriage(inc)}
                    className={`cursor-pointer transition-colors hover:bg-navy-700/40 ${
                      selectedIncident?.incident_id === inc.incident_id
                        ? 'bg-cyan-950/30 ring-1 ring-cyan-500/50'
                        : ''
                    }`}
                  >
                    <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {inc.created_at ? inc.created_at.split('T')[0] + ' ' + (inc.created_at.split('T')[1]?.substring(0, 8) || '') : '—'}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-300 font-medium">
                      {inc.incident_id.substring(0, 14)}…
                    </td>
                    <td className="py-2.5 px-4 font-mono text-red-400 font-semibold">
                      {inc.src_ip}
                      <span className="text-slate-500">:{inc.src_port}</span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-300">
                      {inc.dst_ip}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-400">{inc.proto}</td>
                    <td className="py-2.5 px-4">{getSeverityBadge(inc.severity)}</td>
                    <td className="py-2.5 px-4 text-slate-400">
                      <span className="text-[11px] truncate max-w-[130px] inline-block" title={inc.detection_source}>
                        {inc.detection_source}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">{getStatusBadge(inc.status)}</td>
                    <td className="py-2.5 px-4 text-center font-mono text-slate-400">
                      {inc.occurrence_count || 1}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          openTriage(inc)
                        }}
                        className="btn-secondary text-[11px] py-1 px-2.5"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Incident Triage & Investigation Modal / Drawer ── */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm p-0">
          <div
            className="w-full max-w-xl h-full bg-navy-800 border-l border-navy-600 flex flex-col shadow-2xl overflow-hidden animate-slide-in"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="p-5 border-b border-navy-600 flex items-center justify-between bg-navy-900/70">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/20 text-red-400">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Incident Investigation Dossier</h3>
                  <p className="text-xs text-slate-400 font-mono">
                    ID: {selectedIncident.incident_id}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-navy-700 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Content Body */}
            <div className="flex-1 overflow-y-auto p-5 space-y-5">
              {saveSuccessMsg && (
                <div className="banner-success text-xs">
                  {saveSuccessMsg}
                </div>
              )}

              {/* Threat Overview */}
              <div className="card p-4 bg-navy-900/60 border border-navy-600 space-y-2.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Incident Severity</span>
                  {getSeverityBadge(selectedIncident.severity)}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Current Lifecycle Status</span>
                  {getStatusBadge(selectedIncident.status)}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Suspect Offender IP</span>
                  <span className="font-mono font-bold text-red-400 text-sm">
                    {selectedIncident.src_ip}:{selectedIncident.src_port}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Target Host</span>
                  <span className="font-mono text-slate-200">
                    {selectedIncident.dst_ip}:{selectedIncident.dst_port} ({selectedIncident.proto})
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">First Detected</span>
                  <span className="font-mono text-slate-300">{selectedIncident.created_at}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Detection Mechanism</span>
                  <span className="text-slate-300 font-medium">{selectedIncident.detection_source}</span>
                </div>
                {selectedIncident.raw_score !== null && selectedIncident.raw_score !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">ML Confidence Score</span>
                    <span className="font-mono font-bold text-cyan-400">
                      {selectedIncident.raw_score.toFixed(4)}
                    </span>
                  </div>
                )}
              </div>

              {/* Evidence Indicators */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Evidence & Indicators of Compromise</span>
                </h4>
                {selectedIncident.evidence && selectedIncident.evidence.length > 0 ? (
                  <div className="space-y-2">
                    {selectedIncident.evidence.map((ev, idx) => (
                      <div key={idx} className="bg-navy-900/80 p-3 rounded-lg border border-navy-700 text-xs">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-medium text-slate-200">{ev.indicator}</span>
                          <span className="badge badge-danger text-[10px] uppercase font-mono">
                            {ev.confidence} Confidence
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px] leading-relaxed">{ev.description}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic bg-navy-900/40 p-3 rounded-lg border border-navy-800">
                    No explicit evidence indicators recorded.
                  </p>
                )}
              </div>

              {/* Limitations & Disclaimers */}
              {selectedIncident.limitations && selectedIncident.limitations.length > 0 && (
                <div className="bg-amber-950/20 border border-amber-500/20 rounded-lg p-3 text-xs">
                  <span className="text-amber-400 font-medium block mb-1">Detection Limitations & Notes</span>
                  <ul className="list-disc list-inside text-slate-400 space-y-1 text-[11px]">
                    {selectedIncident.limitations.map((lim, idx) => (
                      <li key={idx}>{lim}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Analyst Triage Controls */}
              <div className="card p-4 bg-navy-900/60 border border-navy-600 space-y-3">
                <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Analyst Workflow & Notes
                </h4>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1 font-medium">Status Update</label>
                    <select
                      value={triageStatus}
                      onChange={(e) => setTriageStatus(e.target.value)}
                      className="input-field text-xs w-full bg-navy-900 cursor-pointer"
                    >
                      <option value="OPEN">Open</option>
                      <option value="INVESTIGATING">Investigating</option>
                      <option value="RESOLVED">Resolved</option>
                      <option value="FALSE_POSITIVE">False Positive</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-slate-400 mb-1 font-medium">Response Action</label>
                    <select
                      value={triageAction}
                      onChange={(e) => setTriageAction(e.target.value)}
                      className="input-field text-xs w-full bg-navy-900 cursor-pointer"
                    >
                      <option value="NONE">None</option>
                      <option value="BLOCKED">Blocked</option>
                      <option value="MONITORED">Monitored</option>
                      <option value="ESCALATED">Escalated</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-xs font-medium">Analyst Assessment Notes</label>
                  <textarea
                    rows={3}
                    value={triageNotes}
                    onChange={(e) => setTriageNotes(e.target.value)}
                    placeholder="Enter investigation observations, threat actor attribution, or escalation justification..."
                    className="input-field text-xs w-full resize-none"
                  />
                </div>

                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() =>
                      updateMutation.mutate({
                        id: selectedIncident.incident_id,
                        status: triageStatus,
                        notes: triageNotes,
                        action: triageAction,
                      })
                    }
                    disabled={updateMutation.isPending}
                    className="btn-primary text-xs flex items-center gap-1.5 py-1.5 px-3"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>{updateMutation.isPending ? 'Saving…' : 'Save Triage Record'}</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Drawer Action Footer */}
            <div className="p-4 border-t border-navy-600 bg-navy-900/90 flex items-center justify-between gap-3">
              <button
                type="button"
                onClick={() => {
                  navigate(`/response?ip=${encodeURIComponent(selectedIncident.src_ip)}&reason=${encodeURIComponent('Incident ' + selectedIncident.incident_id)}`)
                }}
                className="btn-danger text-xs flex items-center gap-1.5 flex-1 justify-center py-2"
              >
                <Shield className="w-4 h-4" />
                <span>Isolate & Block Offender IP ({selectedIncident.src_ip})</span>
                <ArrowRight className="w-3.5 h-3.5 ml-1" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
