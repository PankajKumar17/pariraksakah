import { create } from 'zustand';

// ── Types ──────────────────────────────────────

export interface Alert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  source_ip: string;
  description: string;
  timestamp: string;
  mitre_technique?: string;
  status: 'open' | 'investigating' | 'resolved';
}

export interface ThreatMetrics {
  total_events_24h: number;
  active_threats: number;
  blocked_attacks: number;
  mean_detect_time_ms: number;
  alerts_by_severity: Record<string, number>;
  top_attack_types: { name: string; count: number }[];
}

export interface SwarmAgent {
  id: string;
  role: string;
  zone: string;
  reputation: number;
  alive: boolean;
  detections: number;
}

export interface DreamReport {
  report_id: string;
  total_findings: number;
  critical_findings: number;
  executive_summary: string;
  generated_at: string;
}

export interface InnovationStatus {
  name: string;
  status: 'active' | 'degraded' | 'offline';
  metrics: Record<string, number | string>;
}

// ── Store ──────────────────────────────────────

interface AppState {
  // Alerts
  alerts: Alert[];
  setAlerts: (alerts: Alert[]) => void;
  addAlert: (alert: Alert) => void;
  updateAlertStatus: (id: string, status: Alert['status']) => void;

  // Metrics
  metrics: ThreatMetrics | null;
  setMetrics: (m: ThreatMetrics) => void;

  // Swarm
  swarmAgents: SwarmAgent[];
  setSwarmAgents: (agents: SwarmAgent[]) => void;

  // Dream reports
  dreamReports: DreamReport[];
  setDreamReports: (reports: DreamReport[]) => void;

  // Innovations
  innovations: InnovationStatus[];
  setInnovations: (items: InnovationStatus[]) => void;

  // WebSocket connection
  wsConnected: boolean;
  setWsConnected: (connected: boolean) => void;

  // Theme
  darkMode: boolean;
  toggleDarkMode: () => void;
}

export const useAppStore = create<AppState>((set) => ({
  alerts: [],
  setAlerts: (alerts) => set({ alerts }),
  addAlert: (alert) =>
    set((state) => ({ alerts: [alert, ...state.alerts].slice(0, 500) })),
  updateAlertStatus: (id, status) =>
    set((state) => ({
      alerts: state.alerts.map((a) => (a.id === id ? { ...a, status } : a)),
    })),

  metrics: null,
  setMetrics: (metrics) => set({ metrics }),

  swarmAgents: [],
  setSwarmAgents: (swarmAgents) => set({ swarmAgents }),

  dreamReports: [],
  setDreamReports: (dreamReports) => set({ dreamReports }),

  innovations: [],
  setInnovations: (innovations) => set({ innovations }),

  wsConnected: false,
  setWsConnected: (wsConnected) => set({ wsConnected }),

  darkMode: true,
  toggleDarkMode: () => set((state) => ({ darkMode: !state.darkMode })),
}));
