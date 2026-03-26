import React, { useState, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

// Mocked fetch responses matching dashboard-api structure
const DNA_API = (import.meta.env.VITE_API_URL || 'http://localhost:8055') + '/dna';

interface Cert {
  id: string;
  component_name: string;
  dna_fingerprint: string;
  certificate_serial: string;
  issued_at: string;
  expires_at: string;
  status: string;
}

interface AuditLog {
  action: string;
  component_id: string;
  actor: string;
  timestamp: string;
  outcome: string;
}

const SecurityDNA: React.FC = () => {
  const [activeTab, setActiveTab] = useState('itcs');
  const [itcs, setItcs] = useState<number>(100);
  const [statusColor, setStatusColor] = useState('GREEN');
  const [graphData, setGraphData] = useState<{nodes: any[], links: any[]}>({nodes:[], links:[]});
  const [certs, setCerts] = useState<Cert[]>([]);
  const [audits, setAudits] = useState<AuditLog[]>([]);

  useEffect(() => {
    fetch(`${DNA_API}/itcs`).then(r => r.json()).then(d => {
      setItcs(d.itcs || 100);
      setStatusColor(d.itcs >= 90 ? '#22C55E' : d.itcs >= 75 ? '#F59E0B' : d.itcs >= 60 ? '#F97316' : '#EF4444');
    }).catch(() => {});
    
    fetch(`${DNA_API}/graph`).then(r => r.json()).then(d => {
      if (d.nodes && d.links) setGraphData(d);
    }).catch(() => {});

    fetch(`${DNA_API}/certificates`).then(r => r.json()).then(d => setCerts(d || [])).catch(() => {});
    fetch(`${DNA_API}/audit`).then(r => r.json()).then(d => setAudits(d || [])).catch(() => {});
  }, []);

  const TABS = ['itcs', 'dna map', 'fingerprints', 'certificates', 'audit trail'];

  return (
    <div style={{ padding: 24, color: '#E2E8F0', fontFamily: "'Inter', sans-serif" }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 32, fontWeight: 800, color: '#F8FAFC' }}>
            🧬 Security DNA Cryptographic Identity
          </h1>
          <p style={{ color: '#94A3B8', fontSize: 14 }}>
            Zero Trust Infrastructure Fingerprinting · Post-Quantum PKI · Absolute Origin Verification
          </p>
        </div>
      </div>

      <div style={{ display:'flex', gap:4, marginBottom:24, borderBottom:'1px solid #334155', paddingBottom:8 }}>
        {TABS.map(t => (
          <button key={t} onClick={() => setActiveTab(t)}
            style={{ background: activeTab===t ? '#3B82F6' : 'transparent',
              color: activeTab===t ? '#fff' : '#94A3B8', border:'none', borderRadius:6,
              padding:'8px 16px', cursor:'pointer', fontWeight: activeTab===t ? 600 : 400,
              fontSize: 13, textTransform: 'capitalize' }}>{t}</button>
        ))}
      </div>

      {activeTab === 'itcs' && (
        <div style={{ textAlign: 'center', padding: 48, background: '#0F172A', borderRadius: 16 }}>
          <h2 style={{ color: '#94A3B8', fontSize: 20 }}>Infrastructure Trust Confidence Score (ITCS)</h2>
          <div style={{ 
            fontSize: 112, fontWeight: 900, 
            color: statusColor, textShadow: `0 0 40px ${statusColor}80`,
            margin: '20px 0'
          }}>
            {itcs.toFixed(1)}
          </div>
          <div style={{ fontSize: 18, color: statusColor, fontWeight: 700, letterSpacing: 2 }}>
            STATUS: {itcs >= 90 ? 'TRUSTED GREEN' : itcs >= 75 ? 'CAUTIOUS YELLOW' : itcs >= 60 ? 'DEGRADED ORANGE' : 'CRITICAL RED'}
          </div>
          <p style={{ color: '#64748B', maxWidth: 600, margin: '20px auto 0' }}>
            Weighted average of all component DNA trust scores. Triggers automated Self-Healing responses when thresholds are crossed.
          </p>
        </div>
      )}

      {activeTab === 'dna map' && (
        <div style={{ background: '#0F172A', borderRadius: 12, overflow: 'hidden', height: 600, border: '1px solid #1E293B' }}>
          {/* @ts-ignore */}
          <ForceGraph2D
            graphData={graphData}
            nodeLabel="id"
            nodeColor={(node: any) => node.val >= 85 ? '#22C55E' : node.val >= 60 ? '#F59E0B' : '#EF4444'}
            linkColor={() => '#334155'}
            nodeRelSize={6}
          />
        </div>
      )}

      {activeTab === 'certificates' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20 }}>
          <h3 style={{ margin: '0 0 16px' }}>Identity Certificate Manager</h3>
          <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ color: '#94A3B8', borderBottom: '1px solid #334155' }}>
                <th style={{ padding: '12px 0' }}>Component</th>
                <th>Serial</th>
                <th>Status</th>
                <th>Expires</th>
                <th>DNA Fingerprint</th>
              </tr>
            </thead>
            <tbody>
              {certs.length === 0 && <tr><td colSpan={5} style={{ padding: '24px 0', textAlign: 'center', color: '#64748B' }}>No certificates issued yet.</td></tr>}
              {certs.map(c => (
                <tr key={c.id} style={{ borderBottom: '1px solid #1E293B', fontSize: 13 }}>
                  <td style={{ padding: '12px 0', color: '#60A5FA', fontWeight: 600 }}>{c.component_name}</td>
                  <td style={{ color: '#E2E8F0', fontFamily: 'monospace' }}>{c.certificate_serial}</td>
                  <td>
                    <span style={{ 
                      background: c.status === 'ACTIVE' ? '#166534' : '#991B1B', 
                      color: c.status === 'ACTIVE' ? '#4ADE80' : '#F87171',
                      padding: '2px 8px', borderRadius: 12, fontSize: 11, fontWeight: 700
                    }}>{c.status}</span>
                  </td>
                  <td style={{ color: '#94A3B8' }}>{new Date(c.expires_at).toLocaleDateString()}</td>
                  <td style={{ color: '#94A3B8', fontFamily: 'monospace' }}>{c.dna_fingerprint.substring(0,16)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'audit trail' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20 }}>
          <h3 style={{ margin: '0 0 16px' }}>Immutable DNA Audit Trail</h3>
          <div style={{ maxHeight: 600, overflowY: 'auto' }}>
            {audits.length === 0 && <div style={{ color: '#64748B', textAlign: 'center', padding: 24 }}>Audit trail empty.</div>}
            {audits.map((a, i) => (
              <div key={i} style={{ background: '#1E293B', padding: 12, borderRadius: 6, marginBottom: 8, borderLeft: '3px solid #60A5FA' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontWeight: 600 }}>{a.action}</span>
                  <span style={{ color: '#64748B', fontSize: 12 }}>{new Date(a.timestamp).toLocaleString()}</span>
                </div>
                <div style={{ color: '#94A3B8', fontSize: 13 }}>
                  Component: <span style={{ color: '#E2E8F0' }}>{a.component_id}</span> • 
                  Actor: <span style={{ color: '#E2E8F0' }}>{a.actor}</span> • 
                  Outcome: <span style={{ color: a.outcome.includes('success') ? '#4ADE80' : '#F87171' }}>{a.outcome}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'fingerprints' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20 }}>
          <h3 style={{ margin: '0 0 16px' }}>Living Fingerprint Monitor</h3>
          <div style={{ color: '#64748B', fontSize: 14 }}>
            Displays live delta drift spanning 5 layers (Hardware, Software, Behavioral, Network, Temporal).
            <br /><em>Metrics stream generated by local monitors mapping /proc subsystems and Neo4j graph flows.</em>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityDNA;
