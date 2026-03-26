import React, { useState, useEffect, useRef, useCallback } from 'react';

// ── Types ──────────────────────────────────────────────

interface ThreatAnalysis {
  is_threat:           boolean;
  severity:            string;
  score:               number;
  techniques_detected: string[];
}

interface LogEvent {
  event_id:         string;
  timestamp:        string;
  hostname:         string;
  app_name:         string;
  severity:         string;
  message:          string;
  raw?:             string;
  _simulated?:      boolean;
  threat_analysis?: ThreatAnalysis;
}

interface LogStatus {
  running:       boolean;
  mode:          string;
  port:          number;
  logs_received: number;
  uptime_s:      number;
}

// ── Constants ──────────────────────────────────────────

const API = 'http://localhost:8001';
const WS  = 'ws://localhost:8001/ws/live-logs';
const MAX_LOGS = 200;

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
  WARN:     'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  INFO:     'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
  DEBUG:    'text-gray-400 bg-gray-500/10 border-gray-500/30',
};

// ── Component ──────────────────────────────────────────

export default function LogAggregation() {
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [status, setStatus] = useState<LogStatus>({ running: false, mode: 'unknown', port: 5140, logs_received: 0, uptime_s: 0 });
  const [wsState, setWsState] = useState<'connecting' | 'connected' | 'offline'>('offline');
  const [isPaused, setIsPaused] = useState(false);
  const [filterSev, setFilterSev] = useState<string>('ALL');
  const [search, setSearch] = useState('');
  
  const wsRef = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  // Poll status
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const r = await fetch(`${API}/logs/status`);
        if (r.ok) setStatus(await r.json());
      } catch {}
    };
    fetchStatus();
    const t = setInterval(fetchStatus, 3000);
    return () => clearInterval(t);
  }, []);

  // WebSocket
  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    setWsState('connecting');
    try {
      const ws = new WebSocket(WS);
      wsRef.current = ws;

      ws.onopen = () => setWsState('connected');
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'ping') return;
          setLogs(prev => {
            if (isPaused) return prev;
            return [msg, ...prev].slice(0, MAX_LOGS);
          });
        } catch {}
      };
      ws.onclose = () => {
        setWsState('offline');
        setTimeout(connectWS, 5000);
      };
      ws.onerror = () => setWsState('offline');
    } catch {
      setWsState('offline');
    }
  }, [isPaused]);

  useEffect(() => {
    connectWS();
    return () => wsRef.current?.close();
  }, [connectWS]);

  // Derived state
  const filteredLogs = logs.filter(l => {
    if (filterSev !== 'ALL' && l.severity !== filterSev) return false;
    if (search && !l.message.toLowerCase().includes(search.toLowerCase()) && !l.app_name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const threatCount = logs.filter(l => l.threat_analysis?.is_threat).length;

  return (
    <div className="space-y-4 h-[calc(100vh-6rem)] flex flex-col">
      {/* Header */}
      <div className="flex flex-wrap justify-between items-center gap-4 flex-shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <span>📑</span> Real-Time Log Aggregation
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Streaming Syslog & JSON ingestion with instant threat classification
          </p>
        </div>

        <div className="flex gap-4 items-center">
          <div className="text-right text-xs text-gray-400">
            <div>UDP {status.port}</div>
            <div className="text-gray-500 font-mono">{status.logs_received.toLocaleString()} logs</div>
          </div>
          <span className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full border font-semibold ${
            wsState === 'connected' ? 'border-green-500/30 text-green-400 bg-green-500/10' :
            wsState === 'connecting' ? 'border-yellow-500/30 text-yellow-400 bg-yellow-500/10' :
                                       'border-gray-600 text-gray-500 bg-gray-800/50'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${wsState === 'connected' ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`} />
            {wsState === 'connected' ? 'Streaming' : wsState === 'connecting' ? 'Connecting…' : 'Offline'}
          </span>
          {status.mode === 'simulated' && (
            <span className="text-[10px] bg-blue-500/20 text-blue-400 border border-blue-500/30 px-2 py-1 rounded">SIMULATOR ON</span>
          )}
        </div>
      </div>

      {/* KPI & Controls Strip */}
      <div className="flex flex-wrap gap-4 items-center bg-slate-800/50 p-3 rounded-lg border border-slate-700/50 flex-shrink-0">
        <div className="flex items-center gap-2 mr-4">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`px-3 py-1.5 rounded text-xs font-semibold transition-colors ${
              isPaused ? 'bg-amber-600 hover:bg-amber-500 text-white' : 'bg-slate-700 hover:bg-slate-600 text-gray-200'
            }`}
          >
            {isPaused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button onClick={() => setLogs([])} className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded text-xs text-gray-200">
            Clear
          </button>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500 uppercase tracking-wider">Level:</span>
          <select 
            value={filterSev} 
            onChange={e => setFilterSev(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded text-sm text-gray-200 px-2 py-1 outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Levels</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="WARN">WARN</option>
            <option value="INFO">INFO</option>
          </select>
        </div>

        <div className="flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Search logs..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-4 text-xs ml-auto ps-4 border-l border-slate-700">
          <div className="text-center">
            <div className="text-gray-500 uppercase tracking-wider text-[10px]">Buffer</div>
            <div className="text-gray-300 font-mono">{logs.length} / {MAX_LOGS}</div>
          </div>
          <div className="text-center">
            <div className="text-gray-500 uppercase tracking-wider text-[10px]">Threats</div>
            <div className="text-red-400 font-mono font-bold">{threatCount}</div>
          </div>
        </div>
      </div>

      {/* Main Log Viewer */}
      <div className="flex-1 bg-[#0A0E17] rounded-lg border border-slate-800 overflow-hidden flex flex-col shadow-2xl">
        <div className="grid grid-cols-12 gap-2 bg-slate-900/80 px-4 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider border-b border-slate-800">
          <div className="col-span-2">Timestamp</div>
          <div className="col-span-1">Level</div>
          <div className="col-span-2">Source / App</div>
          <div className="col-span-6">Message</div>
          <div className="col-span-1 text-right">Analysis</div>
        </div>
        
        <div ref={feedRef} className="flex-1 overflow-y-auto font-mono text-xs">
          {filteredLogs.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-gray-600">
              <span className="text-2xl mb-2">⏳</span>
              Waiting for log events...
            </div>
          ) : (
            filteredLogs.map(log => {
              const sevClass = SEV_COLORS[log.severity] || SEV_COLORS['INFO'];
              const isThreat = log.threat_analysis?.is_threat;
              return (
                <div 
                  key={log.event_id} 
                  className={`grid grid-cols-12 gap-2 px-4 py-2 border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors ${
                    isThreat ? 'bg-red-900/10' : ''
                  }`}
                >
                  <div className="col-span-2 text-gray-500 flex items-center">
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString(undefined, { hour12: false, fractionalSecondDigits: 3 }) : '—'}
                  </div>
                  <div className="col-span-1 flex items-center">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${sevClass}`}>
                      {log.severity}
                    </span>
                  </div>
                  <div className="col-span-2 flex flex-col justify-center">
                    <span className="text-gray-400 truncate" title={log.hostname}>{log.hostname}</span>
                    <span className="text-cyan-600/60 truncate" title={log.app_name}>{log.app_name}</span>
                  </div>
                  <div className="col-span-6 text-gray-300 break-all flex items-center">
                    {log.message}
                  </div>
                  <div className="col-span-1 flex items-center justify-end">
                    {isThreat ? (
                      <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[9px] font-bold" title={(log.threat_analysis?.techniques_detected || []).join(', ')}>
                        THREAT
                      </span>
                    ) : (
                      <span className="text-gray-600 text-[9px] font-bold">CLEAN</span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
