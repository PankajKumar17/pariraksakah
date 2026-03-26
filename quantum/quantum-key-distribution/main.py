from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from qkd_protocols import QKDProtocols
import time

app = FastAPI(title="Quantum Key Distribution Simulator")
qkd = QKDProtocols()
sessions_store: dict = {}

class SessionStartRequest(BaseModel):
    protocol: str = "BB84"
    num_qubits: int = 256
    alice_endpoint: str = "gateway-alpha"
    bob_endpoint: str = "gateway-beta"

class EavesdropRequest(BaseModel):
    protocol: str = "BB84"
    num_qubits: int = 256
    eve_intercept_pct: float = 0.5

@app.post("/quantum/qkd/session/start")
async def start_session(req: SessionStartRequest):
    proto = req.protocol.upper()
    if proto == "BB84":
        result = qkd.bb84_session(req.num_qubits)
    elif proto == "E91":
        result = qkd.e91_session(req.num_qubits)
    elif proto == "B92":
        result = qkd.b92_session(req.num_qubits)
    else:
        return {"error": f"Unknown protocol: {proto}", "supported": ["BB84", "E91", "B92"]}
    
    result["alice_endpoint"] = req.alice_endpoint
    result["bob_endpoint"] = req.bob_endpoint
    sessions_store[result["session_id"]] = result
    return result

@app.get("/quantum/qkd/session/{session_id}")
async def get_session(session_id: str):
    session = sessions_store.get(session_id)
    if not session:
        return {"error": "Session not found"}
    return session

@app.get("/quantum/qkd/keys/available")
async def keys_available():
    secure_sessions = [s for s in sessions_store.values() if not s.get("eavesdrop_detected")]
    total_bits = sum(s.get("key_bits_generated", 0) for s in secure_sessions)
    return {"available_key_bits": total_bits, "secure_sessions": len(secure_sessions)}

@app.post("/quantum/qkd/eavesdrop/simulate")
async def simulate_eavesdrop(req: EavesdropRequest):
    proto = req.protocol.upper()
    if proto == "BB84":
        result = qkd.bb84_session(req.num_qubits, req.eve_intercept_pct)
    elif proto == "E91":
        result = qkd.e91_session(req.num_qubits, req.eve_intercept_pct)
    elif proto == "B92":
        result = qkd.b92_session(req.num_qubits, req.eve_intercept_pct)
    else:
        return {"error": "Unsupported protocol"}
    
    sessions_store[result["session_id"]] = result
    return result

@app.get("/quantum/qkd/stats")
async def stats():
    total = len(sessions_store)
    secure = sum(1 for s in sessions_store.values() if not s.get("eavesdrop_detected"))
    compromised = total - secure
    avg_qber = 0.0
    if total > 0:
        avg_qber = sum(s.get("qber_rate", 0) for s in sessions_store.values()) / total
    return {
        "total_sessions": total,
        "secure_sessions": secure,
        "compromised_sessions": compromised,
        "average_qber": round(avg_qber, 6)
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "quantum-qkd-simulator"}

@app.get("/metrics")
async def metrics():
    return f"# QKD Metrics\nqkd_sessions_total {len(sessions_store)}\n"
