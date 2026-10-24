/**
 * XShield API Client — typed fetch wrappers for the FastAPI backend.
 */

const API_BASE = 'http://127.0.0.1:8000/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HealthData {
  status: string;
  api_version: string;
  timestamp: string;
  is_npcap_installed: boolean;
  is_admin: boolean;
  can_capture_live: boolean;
  recommended_mode: string;
  status_message: string;
  interfaces: Array<Record<string, unknown>>;
  runtime_active: boolean;
  incident_store_available: boolean;
  response_mode: string;
  protected_ips: string[];
  models: Record<string, { is_available: boolean; feature_count: number; port_policy: string }>;
}

export interface MonitorStatus {
  is_active: boolean;
  replay_running: boolean;
  replay_finished: boolean;
  replay_source: string;
  flows_streamed: number;
  elapsed_seconds: number;
  delay_seconds: number;
  capture_running: boolean;
  last_error: string | null;
}

export interface FlowStats {
  total: number;
  suspicious: number;
  benign: number;
  insufficient: number;
}

export interface FlowData {
  flow_id: string;
  start_time: string;
  last_seen: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  duration: number;
  orig_pkts: number;
  resp_pkts: number;
  tot_pkts: number;
  orig_bytes: number;
  resp_bytes: number;
  tot_bytes: number;
  conn_state: string;
  sni: string;
  ja4: string;
  is_replayed: boolean;
  is_synthetic: boolean;
}

export interface VerdictData {
  flow_id: string;
  status: string;
  is_suspicious: boolean;
  risk_tier: string;
  raw_score: number | null;
  score_label: string;
  detection_source: string;
  model_name: string | null;
  threshold_applied: number;
  evidence: Array<{ indicator: string; description: string; confidence: string }>;
  limitations: string[];
  is_synthetic: boolean;
  evaluated_at: string;
}

export interface FlowItem {
  flow: FlowData;
  verdict: VerdictData;
}

export interface IncidentData {
  incident_id: string;
  created_at: string;
  last_seen: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: string;
  severity: string;
  detection_source: string;
  raw_score: number | null;
  model_name: string | null;
  evidence: Array<{ indicator: string; description: string; confidence: string }>;
  limitations: string[];
  status: string;
  analyst_notes: string;
  response_action: string;
  occurrence_count: number;
  is_synthetic: boolean;
}

export interface IncidentSummary {
  total_incidents: number;
  high_severity: number;
  active_investigations: number;
  resolved: number;
  blocks_recorded: number;
}

export interface BlockRule {
  action_id: string;
  rule_name: string;
  target_ip: string;
  direction: string;
  status: string;
  is_live: boolean;
  reason: string;
  incident_id: string | null;
  created_at: string;
  details: string;
  duration_minutes: number;
  expires_at: string | null;
  rolled_back_at: string | null;
}

// ---------------------------------------------------------------------------
// API Functions
// ---------------------------------------------------------------------------

export const api = {
  health: () => request<HealthData>('/health'),
  monitorStatus: () => request<MonitorStatus>('/monitor/status'),
  monitorStats: () => request<FlowStats>('/monitor/stats'),
  flows: (limit = 50) => request<FlowItem[]>(`/flows?limit=${limit}`),

  incidentSummary: () => request<IncidentSummary>('/incidents/summary'),
  incidents: (params?: { status_filter?: string; severity_filter?: string; search_query?: string; limit?: number }) => {
    const sp = new URLSearchParams();
    if (params?.status_filter && params.status_filter !== 'All') sp.set('status_filter', params.status_filter);
    if (params?.severity_filter && params.severity_filter !== 'All') sp.set('severity_filter', params.severity_filter);
    if (params?.search_query) sp.set('search_query', params.search_query);
    if (params?.limit) sp.set('limit', String(params.limit));
    const qs = sp.toString();
    return request<IncidentData[]>(`/incidents${qs ? '?' + qs : ''}`);
  },
  incident: (id: string) => request<IncidentData>(`/incidents/${id}`),
  updateIncident: (id: string, body: { status: string; analyst_notes?: string; response_action?: string }) =>
    request<{ success: boolean }>(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  exportIncidentsCsv: (anonymize = false) =>
    fetch(`${API_BASE}/incidents/export/csv?anonymize=${anonymize}`).then(r => r.text()),

  startReplay: (body: { mode: string; delay_seconds?: number; total_flows?: number; c2_ratio?: number; max_rows?: number }) =>
    request<{ success: boolean; message: string; mode: string }>('/replay/start', { method: 'POST', body: JSON.stringify(body) }),
  stopReplay: () => request<{ success: boolean }>('/replay/stop', { method: 'POST' }),

  startLiveCapture: (body?: { interface?: string; bpf_filter?: string }) =>
    request<{ success: boolean; message: string }>('/capture/start', { method: 'POST', body: JSON.stringify(body || {}) }),
  stopLiveCapture: () =>
    request<{ success: boolean; message: string }>('/capture/stop', { method: 'POST' }),

  recommendBlock: (body: { target_ip: string; reason: string; direction?: string; duration_minutes?: number }) =>
    request<Record<string, unknown>>('/response/recommend', { method: 'POST', body: JSON.stringify(body) }),
  applyBlock: (body: { target_ip: string; reason: string; direction?: string; duration_minutes?: number; live_requested?: boolean }) =>
    request<BlockRule>('/response/apply', { method: 'POST', body: JSON.stringify(body) }),
  listRules: () => request<BlockRule[]>('/response/rules'),
  rollbackRule: (rule_name: string) =>
    request<{ success: boolean }>('/response/rollback', { method: 'POST', body: JSON.stringify({ rule_name }) }),
  cleanupExpired: () =>
    request<{ cleaned: string[]; count: number }>('/response/cleanup', { method: 'POST' }),

  trafficAnalytics: () => request<TrafficAnalytics>('/analytics/traffic'),
  simulateThreat: (threatType = 'c2_beacon') =>
    request<{ success: boolean; flow_id: string; threat_type: string; verdict: any }>(`/traffic/simulate-incident?threat_type=${threatType}`, { method: 'POST' }),
  seedIncidents: (force = false) =>
    request<{ success: boolean; count: number }>(`/incidents/seed-sample?force=${force}`, { method: 'POST' }),
  getDetectionPolicy: () =>
    request<{ model_name: string; threshold: number; min_packets_required: number; enable_heuristics: boolean; alert_on_heuristics_alone: boolean }>('/detection/policy'),
  updateDetectionPolicy: (body: { threshold?: number; enable_heuristics?: boolean; alert_on_heuristics_alone?: boolean }) =>
    request<{ success: boolean; threshold: number; enable_heuristics: boolean; alert_on_heuristics_alone: boolean }>('/detection/policy', { method: 'POST', body: JSON.stringify(body) }),
};

export interface TrafficAnalytics {
  total_flows: number;
  benign_count: number;
  suspicious_count: number;
  insufficient_count: number;
  total_packets: number;
  total_bytes: number;
  protocols: Array<{ name: string; flows: number; packets: number; bytes: number }>;
  score_distribution: Array<{ bracket: string; count: number }>;
  top_endpoints: Array<{
    dst_ip: string;
    dst_port: number;
    proto: string;
    flows: number;
    packets: number;
    bytes: number;
    max_score: number;
    risk_tier: string;
    sni: string;
  }>;
  host_network: {
    driver: string;
    active_interface: string;
    host_ip: string;
    is_capturing: boolean;
  };
}
