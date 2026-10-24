import React, { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ShieldAlert, ShieldCheck, Undo2, Trash2, AlertTriangle,
  RefreshCw, CheckCircle, Info, Lock, Zap
} from 'lucide-react'
import { api, BlockRule } from '../api/client'

export default function NetworkResponse() {
  const [searchParams] = useSearchParams()
  const queryClient = useQueryClient()

  // Form state
  const [targetIp, setTargetIp] = useState<string>('')
  const [reason, setReason] = useState<string>('Suspicious C2 activity flagged by ML')
  const [direction, setDirection] = useState<string>('inbound')
  const [durationMinutes, setDurationMinutes] = useState<number>(60)
  const [liveRequested, setLiveRequested] = useState<boolean>(false)

  // Status & feedback
  const [recommendationResult, setRecommendationResult] = useState<Record<string, unknown> | null>(null)
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Pre-fill from query params if passed
  useEffect(() => {
    const ip = searchParams.get('ip')
    const r = searchParams.get('reason')
    if (ip) setTargetIp(ip)
    if (r) setReason(r)
  }, [searchParams])

  // Queries
  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
  })

  const rulesQuery = useQuery({
    queryKey: ['responseRules'],
    queryFn: api.listRules,
    refetchInterval: 3000,
  })

  // Recommend block mutation
  const recommendMutation = useMutation({
    mutationFn: () =>
      api.recommendBlock({
        target_ip: targetIp,
        reason,
        direction,
        duration_minutes: durationMinutes,
      }),
    onSuccess: (data) => {
      setRecommendationResult(data)
      setNotification({
        type: 'success',
        message: 'Recommendation analysis generated successfully.',
      })
    },
    onError: (err: Error) => {
      setNotification({ type: 'error', message: err.message })
    },
  })

  // Apply block mutation
  const applyMutation = useMutation({
    mutationFn: () =>
      api.applyBlock({
        target_ip: targetIp,
        reason,
        direction,
        duration_minutes: durationMinutes,
        live_requested: liveRequested,
      }),
    onSuccess: (rule: BlockRule) => {
      setNotification({
        type: 'success',
        message: `Block rule created: ${rule.rule_name} (${rule.is_live ? 'LIVE FIREWALL' : 'SIMULATED'})`,
      })
      setRecommendationResult(null)
      queryClient.invalidateQueries({ queryKey: ['responseRules'] })
      queryClient.invalidateQueries({ queryKey: ['incidentSummary'] })
    },
    onError: (err: Error) => {
      setNotification({ type: 'error', message: err.message })
    },
  })

  // Rollback rule mutation
  const rollbackMutation = useMutation({
    mutationFn: (ruleName: string) => api.rollbackRule(ruleName),
    onSuccess: () => {
      setNotification({ type: 'success', message: 'Rule rolled back successfully.' })
      queryClient.invalidateQueries({ queryKey: ['responseRules'] })
    },
    onError: (err: Error) => {
      setNotification({ type: 'error', message: err.message })
    },
  })

  // Cleanup expired mutation
  const cleanupMutation = useMutation({
    mutationFn: api.cleanupExpired,
    onSuccess: (data) => {
      setNotification({
        type: 'success',
        message: `Cleanup completed: ${data.count} expired rules cleaned.`,
      })
      queryClient.invalidateQueries({ queryKey: ['responseRules'] })
    },
    onError: (err: Error) => {
      setNotification({ type: 'error', message: err.message })
    },
  })

  const rules = rulesQuery.data || []
  const protectedIps = healthQuery.data?.protected_ips || []
  const responseMode = healthQuery.data?.response_mode || 'SIMULATION'

  return (
    <div className="space-y-6">
      {/* ── Mode Banner & Protected IPs ── */}
      <div className="flex flex-col lg:flex-row gap-4">
        <div className="flex-1 card p-4 bg-navy-800/90 border border-navy-600 flex items-start gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 flex-shrink-0">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white">Active Mitigation Architecture</h3>
              <span className="badge-neutral font-mono text-[10px]">MODE: {responseMode}</span>
            </div>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              XShield executes defense mitigations in <strong>Safe Simulation Mode</strong> by default. Rules are fully tracked, timed, and audited in the incident ledger without modifying Windows Firewall tables unless explicitly enabled with administrator privileges.
            </p>
          </div>
        </div>

        <div className="card p-4 bg-navy-800/90 border border-navy-600 lg:w-80">
          <span className="text-xs font-semibold text-slate-300 block mb-2 flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Protected Addresses (Whitelisted)</span>
          </span>
          <div className="flex flex-wrap gap-1.5">
            {protectedIps.map((ip) => (
              <span key={ip} className="font-mono text-[11px] bg-navy-900 border border-navy-700 text-emerald-400 px-2 py-0.5 rounded">
                {ip}
              </span>
            ))}
          </div>
        </div>
      </div>

      {notification && (
        <div
          className={`p-3.5 rounded-lg border text-xs flex items-center justify-between ${
            notification.type === 'success' ? 'banner-success' : 'banner-danger'
          }`}
        >
          <span>{notification.message}</span>
          <button onClick={() => setNotification(null)} className="font-bold ml-2">
            ×
          </button>
        </div>
      )}

      {/* ── Rule Generation & Recommendation Form ── */}
      <div className="card p-5 bg-navy-800/80">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
          <ShieldAlert className="w-4 h-4 text-red-400" />
          <span>Firewall Isolation & Threat Containment</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div>
            <label className="block text-slate-400 mb-1 font-medium">Target Host / IP</label>
            <input
              type="text"
              placeholder="e.g. 192.168.1.105 or 45.33.32.156"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              className="input-field text-xs w-full font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-medium">Direction</label>
            <select
              value={direction}
              onChange={(e) => setDirection(e.target.value)}
              className="input-field text-xs w-full bg-navy-900 cursor-pointer"
            >
              <option value="inbound">Inbound (Block Incoming)</option>
              <option value="outbound">Outbound (Block Exfiltration)</option>
              <option value="both">Both (Total Isolation)</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-medium">Mitigation Duration (Minutes)</label>
            <input
              type="number"
              min="0"
              max="1440"
              value={durationMinutes}
              onChange={(e) => setDurationMinutes(parseInt(e.target.value, 10) || 0)}
              className="input-field text-xs w-full font-mono"
            />
            <span className="text-[10px] text-slate-500 mt-0.5 block">0 = Permanent until rollback</span>
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-medium">Justification / Reason</label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Justification for containment..."
              className="input-field text-xs w-full"
            />
          </div>
        </div>

        {/* Live Safety Checkbox */}
        <div className="mt-4 pt-3 border-t border-navy-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={liveRequested}
              onChange={(e) => setLiveRequested(e.target.checked)}
              className="rounded border-navy-600 text-red-500 focus:ring-0 bg-navy-900 cursor-pointer"
            />
            <span className={liveRequested ? 'text-red-400 font-semibold' : 'text-slate-400'}>
              Request Live Windows Firewall Modification (Requires Admin & Explicit Confirmation)
            </span>
          </label>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => recommendMutation.mutate()}
              disabled={!targetIp || recommendMutation.isPending}
              className="btn-secondary text-xs flex items-center gap-1.5 py-1.5 px-3"
            >
              <Info className="w-3.5 h-3.5 text-cyan-400" />
              <span>{recommendMutation.isPending ? 'Analyzing…' : 'Recommend Dry-Run'}</span>
            </button>
            <button
              type="button"
              onClick={() => applyMutation.mutate()}
              disabled={!targetIp || applyMutation.isPending}
              className="btn-danger text-xs flex items-center gap-1.5 py-1.5 px-4 font-semibold"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>{applyMutation.isPending ? 'Executing…' : 'Enact Isolation Rule'}</span>
            </button>
          </div>
        </div>

        {/* Recommendation Output Display */}
        {recommendationResult && (
          <div className="mt-4 p-4 rounded-lg bg-navy-900 border border-cyan-500/30 text-xs space-y-2 animate-fade-in">
            <div className="flex items-center justify-between text-cyan-700 dark:text-cyan-300 font-semibold">
              <span className="flex items-center gap-1.5">
                <CheckCircle className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                Response Engine Assessment
              </span>
              <button
                onClick={() => setRecommendationResult(null)}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                ×
              </button>
            </div>
            <pre className="p-3 bg-navy-950/80 rounded border border-navy-700/60 font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
              {JSON.stringify(recommendationResult, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* ── Active & Historic Rules Ledger ── */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-navy-600 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span>Response Actions Ledger</span>
              <span className="text-xs text-slate-400 font-normal">({rules.length} total entries)</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Review active containment rules, expiration timelines, or roll back previous blocks.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => cleanupMutation.mutate()}
              disabled={cleanupMutation.isPending}
              className="btn-secondary text-xs flex items-center gap-1.5 py-1.5"
              title="Remove expired rules"
            >
              <Trash2 className="w-3.5 h-3.5 text-amber-400" />
              <span>Purge Expired</span>
            </button>
            <button
              onClick={() => queryClient.invalidateQueries({ queryKey: ['responseRules'] })}
              className="btn-secondary p-1.5"
              title="Refresh rules"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-navy-900/90 text-slate-400 font-medium border-b border-navy-600 uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Created</th>
                <th className="py-3 px-4">Rule Name</th>
                <th className="py-3 px-4">Blocked IP</th>
                <th className="py-3 px-4">Direction</th>
                <th className="py-3 px-4">Engine Mode</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Reason / Notes</th>
                <th className="py-3 px-4">TTL Expiry</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-700/50">
              {rules.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-10 text-center text-slate-500">
                    <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                    <p className="text-sm font-medium text-slate-400">No mitigation rules currently registered</p>
                    <p className="text-xs text-slate-500 mt-1">
                      Use the containment form above to isolate an offender IP.
                    </p>
                  </td>
                </tr>
              ) : (
                rules.map((rule) => {
                  const isActive = rule.status === 'ACTIVE'
                  return (
                    <tr
                      key={rule.action_id}
                      className={`hover:bg-navy-700/40 transition-colors ${
                        isActive ? 'bg-navy-800/30' : 'opacity-60'
                      }`}
                    >
                      <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {rule.created_at ? rule.created_at.split('T')[0] + ' ' + (rule.created_at.split('T')[1]?.substring(0, 8) || '') : '—'}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-300 font-medium">
                        {rule.rule_name}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-red-400 font-bold">
                        {rule.target_ip}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-400 uppercase text-[10px]">
                        {rule.direction}
                      </td>
                      <td className="py-2.5 px-4">
                        {rule.is_live ? (
                          <span className="badge-danger font-mono text-[10px]">LIVE FIREWALL</span>
                        ) : (
                          <span className="badge-neutral font-mono text-[10px]">SIMULATED</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4">
                        {isActive ? (
                          <span className="badge-success text-[10px]">ACTIVE</span>
                        ) : (
                          <span className="badge-neutral text-[10px]">ROLLED BACK</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 text-[11px] max-w-[200px] truncate" title={rule.reason}>
                        {rule.reason}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                        {rule.expires_at ? rule.expires_at.split('T')[1]?.substring(0, 8) || rule.expires_at : 'Permanent'}
                      </td>
                      <td className="py-2.5 px-4 text-right">
                        {isActive && (
                          <button
                            type="button"
                            onClick={() => rollbackMutation.mutate(rule.rule_name)}
                            disabled={rollbackMutation.isPending}
                            className="btn-secondary text-[11px] py-1 px-2.5 text-amber-400 hover:text-amber-300 flex items-center gap-1 ml-auto"
                            title="Roll back this rule"
                          >
                            <Undo2 className="w-3 h-3" />
                            <span>Rollback</span>
                          </button>
                        )}
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
