import React, { useEffect, useMemo, useState, useCallback } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts';
import { useAppStore, Alert } from '../store/useAppStore';
import { connectWebSocket } from '../services/api';
import AlertFeed from '../components/AlertFeed';
import ThreatGlobe from '../components/ThreatGlobe';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#3B82F6',
};

const MITRE_MATRIX: Array<{ tactic: string; techniques: string[] }> = [
  { tactic: 'Initial Access', techniques: ['T1566', 'T1190', 'T1078'] },
  { tactic: 'Execution', techniques: ['T1059', 'T1204', 'T1053'] },
  { tactic: 'Persistence', techniques: ['T1547', 'T1098', 'T1136'] },
  { tactic: 'Credential Access', techniques: ['T1003', 'T1110', 'T1555'] },
  { tactic: 'Lateral Movement', techniques: ['T1021', 'T1570', 'T1210'] },
  { tactic: 'Command & Control', techniques: ['T1071', 'T1095', 'T1105'] },
  { tactic: 'Exfiltration', techniques: ['T1041', 'T1567', 'T1020'] },
  { tactic: 'Impact', techniques: ['T1486', 'T1499', 'T1531'] },
];

type BioTrust = {
  score: number;
  confidence: number;
  driftRisk: number;
  lastCheck: string;
};

type PodTTL = {
  name: string;
  namespace: string;
  ageSec: number;
  ttlSec: number;
  fetchedAtEpochSec: number;
};

// ── Fallback mock data ─────────────────────────

function generateMockMetrics() {
  return {
    total_events_24h: 2_847_391,
    active_threats: 47,
    blocked_attacks: 1_293,
    mean_detect_time_ms: 12,
    alerts_by_severity: { critical: 8, high: 23, medium: 67, low: 142 },
    top_attack_types: [
      { name: 'Lateral Movement', count: 312 },
      { name: 'C2 Beacon', count: 187 },
      { name: 'Credential Theft', count: 156 },
      { name: 'Ransomware', count: 89 },
      { name: 'Data Exfiltration', count: 74 },
      { name: 'Phishing', count: 201 },
    ],
  };
}

function generateMockAlerts(): Alert[] {
  return Array.from({ length: 30 }, (_, i) => ({
    id: `alert-mock-${i}`,
    severity: (['critical', 'high', 'high', 'medium', 'medium', 'low'] as const)[i % 6],
    type: ['Lateral Movement', 'C2 Beacon', 'Credential Theft', 'Ransomware', 'Data Exfiltration', 'Phishing'][i % 6],
    source_ip: `10.${(i * 17) % 255}.${(i * 31) % 255}.${(i * 7) % 255}`,
    description: `Detected suspicious activity — matches known ${['APT29', 'APT28', 'Lazarus', 'FIN7'][i % 4]} TTPs`,
    timestamp: new Date(Date.now() - i * 4 * 60_000).toISOString(),
    mitre_technique: ['T1021', 'T1071', 'T1003', 'T1486', 'T1041', 'T1566'][i % 6],
    status: 'open',
  }));
}

function generateTimeSeriesData(baseEvents = 90000) {
  const now = Date.now();
  return Array.from({ length: 24 }, (_, i) => ({
    time: new Date(now - (23 - i) * 3600_000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    }),
    events: Math.floor(baseEvents + (Math.sin(i / 3) * baseEvents * 0.15) + Math.random() * 5000),
    blocked: Math.floor(baseEvents * 0.0004 + Math.random() * 20),
  }));
}

// ── Service health badge ───────────────────────

function ServiceBadge({ name, status, latency }: { name: string; status: string; latency: number }) {
  const color = status === 'healthy' ? 'bg-green-500' : status === 'degraded' ? 'bg-yellow-500' : 'bg-red-500';
  return (
    <div className="flex items-center gap-2 text-xs py-1">
      <span className={`w-2 h-2 rounded-full ${color} flex-shrink-0`} />
      <span className="text-gray-300 truncate">{name}</span>
      {latency > 0 && <span className="text-gray-500 ml-auto">{latency}ms</span>}
    </div>
  );
}

// ── Component ──────────────────────────────────

export default function Dashboard() {
  const { alerts, setAlerts, addAlert, metrics, setMetrics, setWsConnected } = useAppStore();
  const [isLive, setIsLive] = useState(false);
  const [services, setServices] = useState<any[]>([]);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [nowMs, setNowMs] = useState(Date.now());

  // ── Anti-phishing extended stats ─────────────────
  const [phishingStats, setPhishingStats] = useState<any>(null);
  const [modelStatus, setModelStatus] = useState<any>(null);
  const [bioTrust, setBioTrust] = useState<BioTrust | null>(null);
  const [podTtls, setPodTtls] = useState<PodTTL[]>([]);

  const fetchPhishingStats = useCallback(async () => {
    try {
      const [statsRes, modelRes] = await Promise.all([
        fetch(`${API_BASE}/api/phishing/stats`),
        fetch(`${API_BASE}/api/phishing/model/status`),
      ]);
      if (statsRes.ok) setPhishingStats(await statsRes.json());
      if (modelRes.ok) setModelStatus(await modelRes.json());
    } catch {
      // Provide demo values if backend unavailable
      setPhishingStats({
        emails_analyzed: 18_245,
        urls_analyzed: 9_302,
        phishing_blocked: 4_561,
        voice_analyzed: 872,
        deepfakes_detected: 34,
        psychographic_assessed: 1_203,
        images_analyzed: 456,
        detonations_run: 2_107,
        iocs_enriched: 6_890,
        feedback_submitted: 312,
      });
      setModelStatus({
        model_version: '1.0.0',
        last_retrained: null,
        pending_feedback_count: 312,
        status: 'active',
      });
    }
  }, []);

  const fetchBioTrust = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/bio-auth/stats`);
      if (res.ok) {
        const data = await res.json();
        setBioTrust({
          score: Number(data.trust_score ?? data.score ?? 86),
          confidence: Number(data.confidence ?? 92),
          driftRisk: Number(data.drift_risk ?? 14),
          lastCheck: data.last_check ?? new Date().toISOString(),
        });
        return;
      }
    } catch {
      // fallback below
    }

    setBioTrust({
      score: 86,
      confidence: 92,
      driftRisk: 14,
      lastCheck: new Date().toISOString(),
    });
  }, []);

  const fetchPodTtl = useCallback(async () => {
    const nowEpochSec = Math.floor(Date.now() / 1000);
    try {
      const res = await fetch(`${API_BASE}/api/v1/infra/pods/ttl`);
      if (res.ok) {
        const data = await res.json();
        const pods = Array.isArray(data?.pods) ? data.pods : [];
        setPodTtls(
          pods.slice(0, 5).map((p: any) => ({
            name: String(p.name ?? 'unknown-pod'),
            namespace: String(p.namespace ?? 'cybershield'),
            ageSec: Number(p.age_sec ?? 0),
            ttlSec: Number(p.ttl_sec ?? 3600),
            fetchedAtEpochSec: nowEpochSec,
          })),
        );
        return;
      }
    } catch {
      // fallback below
    }

    setPodTtls([
      { name: 'threat-detection-ephem-7b9d', namespace: 'cybershield', ageSec: 1460, ttlSec: 3600, fetchedAtEpochSec: nowEpochSec },
      { name: 'sandbox-runner-ephem-33c1', namespace: 'cybershield', ageSec: 2920, ttlSec: 3600, fetchedAtEpochSec: nowEpochSec },
      { name: 'forensics-job-ephem-a2f0', namespace: 'cybershield', ageSec: 810, ttlSec: 1800, fetchedAtEpochSec: nowEpochSec },
    ]);
  }, []);

  const fetchLiveData = useCallback(async () => {
    try {
      const [dashRes, alertsRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/dashboard`),
        fetch(`${API_BASE}/api/v1/alerts`),
      ]);

      if (dashRes.ok) {
        const data = await dashRes.json();
        setMetrics({
          total_events_24h: data.total_events_24h,
          active_threats: data.active_threats,
          blocked_attacks: data.blocked_attacks,
          mean_detect_time_ms: data.mean_detect_time_ms,
          alerts_by_severity: data.alerts_by_severity,
          top_attack_types: data.top_attack_types,
        });
        setServices(data.services || []);
        setIsLive(true);
        setLastUpdated(new Date());
      }

      if (alertsRes.ok) {
        const data = await alertsRes.json();
        const liveAlerts: Alert[] = (data.alerts || []).map((a: any) => ({
          id: a.id,
          severity: a.severity,
          type: a.type,
          source_ip: a.source_ip,
          description: a.description,
          timestamp: a.timestamp,
          mitre_technique: a.mitre_technique,
          status: a.status,
        }));
        setAlerts(liveAlerts);
      }
    } catch {
      // Backend unreachable — use mock data
      if (!metrics) {
        setMetrics(generateMockMetrics());
        setAlerts(generateMockAlerts());
      }
      setIsLive(false);
    }
  }, []);

  // Initial load + poll every 30s
  useEffect(() => {
    fetchLiveData();
    fetchPhishingStats();
    fetchBioTrust();
    fetchPodTtl();
    const interval = setInterval(() => {
      fetchLiveData();
      fetchPhishingStats();
      fetchBioTrust();
      fetchPodTtl();
    }, 30_000);
    return () => clearInterval(interval);
  }, [fetchLiveData, fetchPhishingStats, fetchBioTrust, fetchPodTtl]);

  useEffect(() => {
    const timer = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  // WebSocket connection
  useEffect(() => {
    let ws: WebSocket;
    try {
      ws = connectWebSocket(
        (data: any) => {
          if (data.type === 'alert') addAlert(data.alert);
          if (data.type === 'metrics') setMetrics(data.metrics);
        },
        () => setWsConnected(true),
        () => setWsConnected(false),
      );
    } catch { /* ws not available */ }
    return () => ws?.close();
  }, []);

  const timeSeriesData = useMemo(
    () => generateTimeSeriesData(metrics?.total_events_24h ? metrics.total_events_24h / 24 : 90000),
    [metrics?.total_events_24h],
  );

  const severityPieData = useMemo(() => {
    if (!metrics) return [];
    return Object.entries(metrics.alerts_by_severity)
      .filter(([, v]) => (v as number) > 0)
      .map(([name, value]) => ({ name, value }));
  }, [metrics]);

  const mitreHeatmap = useMemo(() => {
    const counts = new Map<string, number>();
    alerts.forEach((a) => {
      if (!a.mitre_technique) return;
      counts.set(a.mitre_technique, (counts.get(a.mitre_technique) || 0) + 1);
    });

    const rows = MITRE_MATRIX.map((row) => {
      const cells = row.techniques.map((tech) => ({
        technique: tech,
        count: counts.get(tech) || 0,
      }));
      const covered = cells.filter((c) => c.count > 0).length;
      return {
        tactic: row.tactic,
        coverage: Math.round((covered / row.techniques.length) * 100),
        cells,
      };
    });

    const overall = Math.round(
      rows.reduce((acc, r) => acc + r.coverage, 0) / (rows.length || 1),
    );

    return { rows, overall };
  }, [alerts]);

  if (!metrics) return <div className="text-center mt-20 text-gray-400">Connecting to backend...</div>;

  return (
    <div className="space-y-6">
      {/* Page header + live/demo badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <h1 className="text-lg sm:text-xl font-bold text-white tracking-wide">Security Operations Center</h1>
        <div className="flex items-center gap-2 text-xs flex-wrap">
          {lastUpdated && (
            <span className="text-gray-500">Updated {lastUpdated.toLocaleTimeString()}</span>
          )}
          <button
            onClick={fetchLiveData}
            className="px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-gray-300 transition"
          >
            ↻ Refresh
          </button>
          <span
            className={`px-3 py-1 rounded-full font-semibold uppercase tracking-widest ${
              isLive
                ? 'bg-green-500/20 text-green-400 border border-green-500/40'
                : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
            }`}
          >
            {isLive ? '● LIVE' : '○ DEMO'}
          </span>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <KPICard
          label="Events (24h)"
          value={metrics.total_events_24h.toLocaleString()}
          color="text-[#6C63FF]"
        />
        <KPICard
          label="Active Threats"
          value={metrics.active_threats.toString()}
          color="text-red-400"
          glow
        />
        <KPICard
          label="Blocked Attacks"
          value={metrics.blocked_attacks.toLocaleString()}
          color="text-green-400"
        />
        <KPICard
          label="Mean Detect Time"
          value={`${metrics.mean_detect_time_ms}ms`}
          color="text-cyan-400"
        />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-3 sm:gap-4">
        {/* Threat Globe */}
        <div className="col-span-12 lg:col-span-5 card">
          <div className="card-header">Global Threat Map</div>
          <ThreatGlobe />
        </div>

        {/* Event Timeline */}
        <div className="col-span-12 lg:col-span-7 card">
          <div className="card-header">Event Volume (24h)</div>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={timeSeriesData}>
              <defs>
                <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6C63FF" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6C63FF" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" tick={{ fill: '#94A3B8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: 8 }}
                labelStyle={{ color: '#94A3B8' }}
              />
              <Area
                type="monotone"
                dataKey="events"
                stroke="#6C63FF"
                fill="url(#colorEvents)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke="#10B981"
                fill="transparent"
                strokeWidth={1.5}
                strokeDasharray="4 4"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Alert Severity Breakdown */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 card">
          <div className="card-header">Alert Severity</div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severityPieData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                dataKey="value"
                paddingAngle={3}
              >
                {severityPieData.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={SEVERITY_COLORS[entry.name] || '#6C63FF'}
                  />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 text-xs">
            {severityPieData.map((s) => (
              <span key={s.name} className="flex items-center gap-1">
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ background: SEVERITY_COLORS[s.name] }}
                />
                {s.name}: {s.value}
              </span>
            ))}
          </div>
        </div>

        {/* Top Attack Types */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 card">
          <div className="card-header">Top Attack Types</div>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={metrics.top_attack_types} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis type="number" tick={{ fill: '#94A3B8', fontSize: 11 }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#94A3B8', fontSize: 11 }}
                width={120}
              />
              <Tooltip
                contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: 8 }}
              />
              <Bar dataKey="count" fill="#6C63FF" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Live Alert Feed */}
        <div className="col-span-12 lg:col-span-4 card">
          <div className="card-header">Live Alerts</div>
          <AlertFeed alerts={alerts.slice(0, 15)} />
        </div>

        {/* MITRE ATT&CK Heatmap */}
        <div className="col-span-12 lg:col-span-8 card">
          <div className="card-header flex items-center justify-between">
            <span>MITRE ATT&amp;CK Coverage Heatmap</span>
            <span className="text-xs text-gray-400">Overall: {mitreHeatmap.overall}%</span>
          </div>
          <div className="space-y-2">
            {mitreHeatmap.rows.map((row) => (
              <div key={row.tactic} className="grid grid-cols-12 gap-2 items-center">
                <div className="col-span-12 sm:col-span-3 text-xs text-gray-300">{row.tactic}</div>
                <div className="col-span-9 sm:col-span-7 grid grid-cols-3 gap-1">
                  {row.cells.map((cell) => {
                    const intensity = Math.min(cell.count, 6);
                    const classes = [
                      'bg-slate-800/70 border-slate-700',
                      'bg-emerald-900/30 border-emerald-700/40',
                      'bg-amber-900/30 border-amber-700/50',
                      'bg-red-900/35 border-red-700/60',
                    ];
                    const level = intensity === 0 ? 0 : intensity <= 2 ? 1 : intensity <= 4 ? 2 : 3;
                    return (
                      <div
                        key={cell.technique}
                        className={`text-[11px] px-2 py-1 rounded border ${classes[level]}`}
                        title={`${cell.technique} • ${cell.count} detections`}
                      >
                        {cell.technique}
                      </div>
                    );
                  })}
                </div>
                <div className="col-span-3 sm:col-span-2 text-right text-xs text-gray-400">{row.coverage}%</div>
              </div>
            ))}
          </div>
        </div>

        {/* Bio-Auth Trust Score */}
        {bioTrust && (
          <div className="col-span-12 md:col-span-6 lg:col-span-4 card">
            <div className="card-header">Bio-Auth Trust Score</div>
            <div className="space-y-3">
              <div>
                <div className="flex items-end gap-2">
                  <span className="text-3xl font-bold text-cyan-300">{bioTrust.score}</span>
                  <span className="text-sm text-gray-400">/100</span>
                </div>
                <div className="mt-2 h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full ${bioTrust.score >= 80 ? 'bg-green-500' : bioTrust.score >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`}
                    style={{ width: `${Math.min(Math.max(bioTrust.score, 0), 100)}%` }}
                  />
                </div>
              </div>
              <StatRow label="Confidence" value={`${bioTrust.confidence}%`} color="text-emerald-400" />
              <StatRow
                label="Drift risk"
                value={`${bioTrust.driftRisk}%`}
                color={bioTrust.driftRisk > 30 ? 'text-red-400' : 'text-yellow-400'}
              />
              <StatRow
                label="Last check"
                value={new Date(bioTrust.lastCheck).toLocaleTimeString()}
                color="text-gray-300"
              />
            </div>
          </div>
        )}

        {/* Ephemeral Pod TTL Countdown */}
        <div className="col-span-12 md:col-span-6 lg:col-span-8 card">
          <div className="card-header">Ephemeral Pod Age / TTL Countdown</div>
          <div className="space-y-2">
            {podTtls.length === 0 && <p className="text-sm text-gray-500">No ephemeral pods reported.</p>}
            {podTtls.map((pod) => {
              const elapsed = Math.max(Math.floor(nowMs / 1000) - pod.fetchedAtEpochSec, 0);
              const remaining = Math.max(pod.ttlSec - pod.ageSec - elapsed, 0);
              const pct = Math.max(Math.min((remaining / Math.max(pod.ttlSec, 1)) * 100, 100), 0);
              return (
                <div key={pod.name} className="p-2 rounded-lg bg-[#0F172A] border border-slate-800">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-300 font-mono truncate mr-2">{pod.name}</span>
                    <span className={remaining < 300 ? 'text-red-400' : 'text-gray-400'}>
                      {formatDuration(remaining)} left
                    </span>
                  </div>
                  <div className="mt-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full ${remaining < 300 ? 'bg-red-500' : remaining < 900 ? 'bg-yellow-500' : 'bg-emerald-500'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <div className="mt-1 text-[11px] text-gray-500">
                    ns: {pod.namespace} • age {formatDuration(pod.ageSec)} / ttl {formatDuration(pod.ttlSec)}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Service Health */}
        {services.length > 0 && (
          <div className="col-span-12 card">
            <div className="card-header">Backend Service Health</div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 sm:gap-x-8 gap-y-1">
              {services.map((svc: any) => (
                <ServiceBadge
                  key={svc.name}
                  name={svc.name}
                  status={svc.status}
                  latency={svc.latency_ms}
                />
              ))}
            </div>
          </div>
        )}

        {/* ── Phase 1: Social Engineering Panel ──────────── */}
        {phishingStats && (
          <div className="col-span-12 md:col-span-6 lg:col-span-4 card"  id="social-engineering-panel">
            <div className="card-header">🎭 Social Engineering Detection</div>
            <div className="space-y-2 text-sm">
              <StatRow label="Voice samples analyzed" value={phishingStats.voice_analyzed?.toLocaleString() ?? '—'} color="text-purple-400" />
              <StatRow label="Deepfakes detected" value={phishingStats.deepfakes_detected?.toLocaleString() ?? '—'} color="text-red-400" />
              <StatRow label="Images analyzed" value={phishingStats.images_analyzed?.toLocaleString() ?? '—'} color="text-blue-300" />
              <StatRow label="Psychographic profiles assessed" value={phishingStats.psychographic_assessed?.toLocaleString() ?? '—'} color="text-yellow-400" />
            </div>
          </div>
        )}

        {/* ── Phase 2: Sandbox & Threat Intel Panel ──────── */}
        {phishingStats && (
          <div className="col-span-12 md:col-span-6 lg:col-span-4 card" id="sandbox-intel-panel">
            <div className="card-header">🔬 Sandbox &amp; Threat Intel</div>
            <div className="space-y-2 text-sm">
              <StatRow label="URLs detonated" value={phishingStats.detonations_run?.toLocaleString() ?? '—'} color="text-orange-400" />
              <StatRow label="IOCs enriched" value={phishingStats.iocs_enriched?.toLocaleString() ?? '—'} color="text-cyan-400" />
              <StatRow label="Emails analyzed" value={phishingStats.emails_analyzed?.toLocaleString() ?? '—'} color="text-green-400" />
              <StatRow label="Phishing blocked" value={phishingStats.phishing_blocked?.toLocaleString() ?? '—'} color="text-red-400" />
            </div>
          </div>
        )}

        {/* ── Phase 3: Model Health Panel ─────────────────── */}
        {modelStatus && (
          <div className="col-span-12 md:col-span-6 lg:col-span-4 card" id="model-health-panel">
            <div className="card-header">🧠 Phishing Model Health</div>
            <div className="space-y-2 text-sm">
              <StatRow label="Model version" value={modelStatus.model_version ?? '—'} color="text-indigo-400" />
              <StatRow
                label="Last retrained"
                value={modelStatus.last_retrained
                  ? new Date(modelStatus.last_retrained).toLocaleDateString()
                  : 'Never'}
                color="text-gray-300"
              />
              <StatRow
                label="Pending feedback"
                value={(modelStatus.pending_feedback_count ?? phishingStats?.feedback_submitted ?? 0).toLocaleString()}
                color={modelStatus.pending_feedback_count >= 100 ? 'text-yellow-400' : 'text-green-400'}
              />
              <StatRow
                label="Status"
                value={modelStatus.status ?? 'unknown'}
                color={modelStatus.status === 'active' ? 'text-green-400' : 'text-yellow-400'}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Sub-components ─────────────────────────────

function KPICard({
  label,
  value,
  color,
  glow,
}: {
  label: string;
  value: string;
  color: string;
  glow?: boolean;
}) {
  return (
    <div className={`card ${glow ? 'animate-glow' : ''}`}>
      <div className={`metric-value ${color}`}>{value}</div>
      <div className="metric-label">{label}</div>
    </div>
  );
}

function StatRow({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-700 pb-1">
      <span className="text-gray-400">{label}</span>
      <span className={`font-semibold tabular-nums ${color}`}>{value}</span>
    </div>
  );
}

function formatDuration(seconds: number) {
  const s = Math.max(seconds, 0);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  return `${m}m ${sec}s`;
}
