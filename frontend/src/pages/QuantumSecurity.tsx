import React, { useState, useEffect } from 'react';
import { useAppStore } from '../store/useAppStore';

// Mock Interfaces defining API Response shapes
interface QKDStatus {
  active_sessions: number;
  quantum_bit_error_rate: number;
  eavesdropping_detected: boolean;
  total_keys_exchanged: number;
}

interface PQCMetrics {
  kyber_ops: number;
  dilithium_ops: number;
  falcon_ops: number;
  sphincs_ops: number;
  active_key_encapsulations: number;
}

export default function QuantumSecurity() {
  const { darkMode } = useAppStore();
  const [qkd, setQkd] = useState<QKDStatus>({ active_sessions: 42, quantum_bit_error_rate: 4.1, eavesdropping_detected: false, total_keys_exchanged: 15420 });
  const [pqc, setPqc] = useState<PQCMetrics>({ kyber_ops: 843, dilithium_ops: 1205, falcon_ops: 432, sphincs_ops: 198, active_key_encapsulations: 156 });
  const [entropy, setEntropy] = useState<number>(0.9998);
  
  // Real-time chart simulation
  const [entropyData, setEntropyData] = useState<number[]>(Array(20).fill(0.999));
  
  useEffect(() => {
    const timer = setInterval(() => {
        setEntropyData(prev => [...prev.slice(1), 0.9990 + (Math.random() * 0.0009)]);
        setQkd(prev => ({ ...prev, total_keys_exchanged: prev.total_keys_exchanged + Math.floor(Math.random() * 10) }));
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  const cardBg = darkMode ? 'bg-[#1E293B]/80 hover:bg-[#1E293B]' : 'bg-white hover:bg-gray-50';
  const textMuted = darkMode ? 'text-gray-400' : 'text-gray-500';
  const textHighlight = '#8B5CF6'; 

  return (
    <div className={`space-y-6 ${darkMode ? 'text-gray-100' : 'text-gray-900'} antialiased`}>
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-purple-500 to-indigo-500">
            Quantum Security Suite
          </h1>
          <p className={textMuted}>Post-Quantum Cryptography & Quantum-Enhanced Analytics</p>
        </div>
        <div className="flex gap-4">
          <div className="flex items-center gap-2 px-4 py-2 rounded-full border border-purple-500/30 bg-purple-500/10 text-purple-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-purple-500 animate-pulse"></span>
            Superposition Active
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        
        {/* 1. Readiness Gauge */}
        <div className={`col-span-1 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
          <h3 className="text-lg font-semibold mb-2">Q-Readiness Score</h3>
          <div className="flex items-center justify-center py-6">
            <div className="relative w-32 h-32 flex items-center justify-center rounded-full bg-gradient-to-tr from-indigo-500 to-purple-500 p-1 shadow-[0_0_30px_rgba(139,92,246,0.3)]">
              <div className={`w-full h-full rounded-full flex items-center justify-center ${darkMode ? 'bg-[#1E293B]' : 'bg-white'}`}>
                <span className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-400 to-indigo-400">92%</span>
              </div>
            </div>
          </div>
          <p className={`text-sm text-center mt-2 ${textMuted}`}>Fully protected against Shor's algorithm attacks.</p>
        </div>

        {/* 2. Crypto Inventory */}
        <div className={`col-span-1 md:col-span-2 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold">Post-Quantum Algorithms</h3>
            <span className="text-xs px-2 py-1 rounded bg-indigo-500/20 text-indigo-400 font-medium border border-indigo-500/30">NIST PQC STANDARDS</span>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-4">
             {Object.entries(pqc).map(([key, value]) => (
                <div key={key} className={`p-4 rounded-xl border ${darkMode ? 'border-gray-700/50 bg-[#0F172A]/50' : 'border-gray-100 bg-gray-50'}`}>
                  <div className={`text-xs uppercase tracking-wider mb-1 ${textMuted}`}>{key.replace('_ops', '').replace('_', ' ')}</div>
                  <div className="text-xl font-bold">{value.toLocaleString()}</div>
                  <div className="text-[10px] text-green-400 mt-1">Ops/sec</div>
                </div>
             ))}
          </div>
        </div>

        {/* 3. QRNG Monitor */}
        <div className={`col-span-1 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
          <h3 className="text-lg font-semibold mb-2">QRNG Entropy Quality</h3>
          <div className="flex flex-col gap-3 py-2">
             <div className="flex justify-between items-end">
                <span className="text-3xl font-mono text-purple-400">{entropyData[entropyData.length-1].toFixed(5)}</span>
                <span className={`text-sm ${textMuted}`}>SP 800-22 Pass</span>
             </div>
             {/* Simple sparkline */}
             <div className="h-16 flex items-end gap-1 mt-2">
                {entropyData.map((val, i) => (
                  <div key={i} className="flex-1 bg-purple-500/40 rounded-t-sm" style={{ height: `${(val - 0.999) * 100000}%`, minHeight: '10%' }}></div>
                ))}
             </div>
          </div>
        </div>

        {/* 4. QKD Visualizer */}
        <div className={`col-span-1 md:col-span-2 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold">Quantum Key Distribution (BB84/E91)</h3>
            <div className="flex items-center gap-2">
               <span className={`w-3 h-3 rounded-full ${qkd.eavesdropping_detected ? 'bg-red-500 animate-ping' : 'bg-green-500'}`}></span>
               <span className="text-sm font-medium">{qkd.eavesdropping_detected ? 'Eavesdropping Detected!' : 'Channel Secure'}</span>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-4">
             <div className={`p-4 rounded-xl text-center border ${darkMode ? 'border-gray-700/50 bg-[#0F172A]' : 'border-gray-100 bg-gray-50'}`}>
                <div className={`text-sm ${textMuted}`}>Active Tunnels</div>
                <div className="text-2xl font-bold mt-1 text-indigo-400">{qkd.active_sessions}</div>
             </div>
             <div className={`p-4 rounded-xl text-center border ${darkMode ? 'border-gray-700/50 bg-[#0F172A]' : 'border-gray-100 bg-gray-50'}`}>
                <div className={`text-sm ${textMuted}`}>QBER Threshold</div>
                <div className="text-2xl font-bold mt-1 text-green-400">{qkd.quantum_bit_error_rate}%</div>
             </div>
             <div className={`p-4 rounded-xl text-center border ${darkMode ? 'border-gray-700/50 bg-[#0F172A]' : 'border-gray-100 bg-gray-50'}`}>
                <div className={`text-sm ${textMuted}`}>Keys Exchanged</div>
                <div className="text-2xl font-bold mt-1 text-purple-400">{qkd.total_keys_exchanged}</div>
             </div>
          </div>
        </div>

        {/* 5. Quantum ML Performance */}
        <div className={`col-span-1 md:col-span-2 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
            <h3 className="text-lg font-semibold mb-4">Quantum Machine Learning (QML) Anomaly Detection</h3>
            <div className="space-y-4">
                <div>
                   <div className="flex justify-between text-sm mb-1">
                      <span className={textMuted}>QSVM (Quantum Support Vector Machine) Accuracy</span>
                      <span className="font-medium text-purple-400">98.4%</span>
                   </div>
                   <div className="h-2 w-full bg-gray-700 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 w-[98.4%]"></div>
                   </div>
                </div>
                <div>
                   <div className="flex justify-between text-sm mb-1">
                      <span className={textMuted}>VQE Energy Landscape Optimization</span>
                      <span className="font-medium text-pink-400">94.2%</span>
                   </div>
                   <div className="h-2 w-full bg-gray-700 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-purple-500 to-pink-500 w-[94.2%]"></div>
                   </div>
                </div>
                <div>
                   <div className="flex justify-between text-sm mb-1">
                      <span className={textMuted}>Quantum Graph Neural Network (QGNN) Correlation</span>
                      <span className="font-medium text-blue-400">96.8%</span>
                   </div>
                   <div className="h-2 w-full bg-gray-700 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 w-[96.8%]"></div>
                   </div>
                </div>
            </div>
        </div>

        {/* 6. Quantum Zero Trust Pipeline */}
        <div className={`col-span-1 md:col-span-2 lg:col-span-4 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300`}>
          <h3 className="text-lg font-semibold mb-4">QZT (Quantum Zero Trust) 5-Step Verification Pipeline</h3>
          <div className="flex flex-col md:flex-row justify-between items-center gap-4 relative">
             <div className="absolute top-1/2 left-0 w-full h-0.5 bg-gray-700/50 -z-10 hidden md:block"></div>
             {[
               { step: 1, label: 'Classical Auth', desc: 'JWT / mTLS', status: 'verified', color: 'text-green-400' },
               { step: 2, label: 'PQC Subject ID', desc: 'Dilithium Sig', status: 'verified', color: 'text-green-400' },
               { step: 3, label: 'Resource Policy', desc: 'RBAC + ABAC', status: 'verified', color: 'text-green-400' },
               { step: 4, label: 'QRNG Challenge', desc: 'Symmetric HMAC', status: 'verifying', color: 'text-yellow-400 animate-pulse' },
               { step: 5, label: 'Entanglement Check', desc: 'QKD Path', status: 'pending', color: 'text-gray-500' }
             ].map(s => (
                <div key={s.step} className={`flex flex-col items-center bg-[#0F172A] p-4 rounded-xl border ${darkMode ? 'border-gray-700/50' : 'border-gray-200'} z-10 w-full md:w-1/5 shadow-lg`}>
                   <div className={`w-8 h-8 rounded-full border-2 flex items-center justify-center font-bold mb-2 
                      ${s.status === 'verified' ? 'border-green-500 text-green-500 bg-green-500/10' : 
                        s.status === 'verifying' ? 'border-yellow-500 text-yellow-500 bg-yellow-500/10' : 
                        'border-gray-600 text-gray-600 bg-gray-800'}`}>
                      {s.step}
                   </div>
                   <div className="font-semibold text-center mt-1">{s.label}</div>
                   <div className={`text-xs text-center mt-1 ${s.color}`}>{s.desc}</div>
                </div>
             ))}
          </div>
        </div>

        {/* 7. Quantum Supply Chain Merkle Tree */}
        <div className={`col-span-1 md:col-span-2 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
          <h3 className="text-lg font-semibold mb-4">Software Supply Chain (Merkle Root)</h3>
          <div className={`p-4 rounded-xl border font-mono text-sm break-all ${darkMode ? 'bg-[#0F172A] border-gray-700/50 text-gray-400' : 'bg-gray-50 border-gray-100 text-gray-600'}`}>
             <div className="mb-2 text-indigo-400 font-semibold">Current Root Hash (SPHINCS+ Signed)</div>
             QMerkle_a9f23e8b4c09d761a2...f33<br/>
             <div className="mt-4 flex items-center gap-2 text-green-400 font-medium text-xs">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Trivy BOM Integrity Verified
             </div>
          </div>
        </div>

        {/* 8. Quantum Attack Simulation Timeline */}
        <div className={`col-span-1 md:col-span-2 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold">Attack Simulation Timeline</h3>
            <span className="text-xs px-2 py-1 rounded bg-red-500/20 text-red-400 font-medium">RED TEAM</span>
          </div>
          <div className="space-y-3">
             {['Shor\'s Demo (RSA 2048)', 'Grover Search on AES-256', 'HNDL Vulnerability Scan'].map((attack, i) => (
                <div key={i} className={`flex items-center gap-3 p-3 rounded-lg border ${darkMode ? 'border-gray-700/50 bg-[#0F172A]' : 'border-gray-100 bg-white'}`}>
                   <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                   <div className="flex-1 text-sm font-medium">{attack}</div>
                   <div className="text-xs text-red-400">0.0{i+1}s ago</div>
                </div>
             ))}
          </div>
        </div>

        {/* 9. Threat Landscape */}
        <div className={`col-span-1 md:col-span-2 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
          <h3 className="text-lg font-semibold mb-4">Threat Landscape Map</h3>
          <div className={`h-40 rounded-xl border flex items-center justify-center relative overflow-hidden ${darkMode ? 'border-gray-700/50 bg-[#0F172A]' : 'border-gray-100 bg-gray-50'}`}>
             <div className="absolute inset-0 opacity-20" style={{ backgroundImage: 'radial-gradient(circle at center, #8B5CF6 2px, transparent 2px)', backgroundSize: '20px 20px' }}></div>
             <div className="absolute w-4 h-4 bg-red-500 rounded-full animate-ping" style={{ top: '30%', left: '40%' }}></div>
             <div className="absolute w-3 h-3 bg-yellow-400 rounded-full animate-pulse" style={{ top: '60%', left: '70%' }}></div>
             <div className="absolute w-5 h-5 bg-indigo-500 rounded-full animate-bounce" style={{ top: '45%', left: '50%' }}></div>
             <span className={`z-10 text-sm font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>3 Active Global Vectors</span>
          </div>
        </div>

        {/* 10. Compute Budget Monitor */}
        <div className={`col-span-1 md:col-span-2 rounded-2xl p-6 shadow-sm border ${darkMode ? 'border-gray-700/50' : 'border-gray-100'} ${cardBg} transition-all duration-300 transform hover:-translate-y-1`}>
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold">QPU Budget Allocation</h3>
          </div>
          <div className="flex flex-col gap-4">
             <div className="flex items-center justify-between">
                 <span className={`text-sm ${textMuted}`}>Simulated Qubits Active</span>
                 <span className="font-mono text-purple-400 font-semibold">512 / 1024</span>
             </div>
             <div className="h-4 w-full bg-gray-700 rounded-full overflow-hidden">
                 <div className="h-full bg-gradient-to-r from-purple-600 to-indigo-500 w-[50%] animate-pulse"></div>
             </div>
             <div className="flex justify-between text-xs mt-2">
                 <span className="text-gray-500">Utilization: 50%</span>
                 <span className="text-indigo-400">Optimal Range</span>
             </div>
          </div>
        </div>

      </div>
    </div>
  );
}
