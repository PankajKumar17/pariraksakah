from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
import time
import uuid

app = FastAPI(title="Quantum Attack Simulator")

class ShorRequest(BaseModel):
    key_size_bits: int = 2048
    crypto_type: str = "RSA"

class GroverRequest(BaseModel):
    algo: str = "AES-128"

class HNDLRequest(BaseModel):
    data_classification: str = "top_secret"

@app.post("/quantum/attack/shor")
async def simulate_shor(req: ShorRequest):
    """Simulate Shor's algorithm for factoring/discrete log."""
    sim_id = f"sim-{uuid.uuid4().hex[:8]}"
    
    # 2n logical qubits for RSA 
    qubits_required = req.key_size_bits * 2 + 1
    # Physical qubits ~ 1000x to 10000x logical due to surface code error correction
    physical_qubits_estimated = qubits_required * 1000 
    
    # Depth ~ O(n^3)
    circuit_depth = req.key_size_bits ** 3
    
    # Timeline estimate based on roadmap (IBM/Google/etc)
    years_to_break = max(0, int((physical_qubits_estimated / 100000) * 5))
    if years_to_break < 5:
        urgency = "CRITICAL"
    elif years_to_break < 10:
        urgency = "HIGH"
    else:
        urgency = "MEDIUM"
        
    return {
        "simulation_id": sim_id,
        "attack_type": "Shor's Algorithm",
        "target_crypto": f"{req.crypto_type}-{req.key_size_bits}",
        "logical_qubits_required": qubits_required,
        "physical_qubits_estimated": physical_qubits_estimated,
        "circuit_depth": circuit_depth,
        "years_to_break_estimate": years_to_break,
        "migration_urgency": urgency,
        "mitigation_recommended": "Migrate to CRYSTALS-Kyber or McEliece",
        "success_probability": 0.99
    }

@app.post("/quantum/attack/grover")
async def simulate_grover(req: GroverRequest):
    """Simulate Grover's algorithm lowering symmetric bit security by half."""
    sim_id = f"sim-{uuid.uuid4().hex[:8]}"
    
    bit_strength = 128
    if "256" in req.algo:
        bit_strength = 256
    elif "192" in req.algo:
        bit_strength = 192
        
    quantum_effective_strength = bit_strength // 2
    
    safe = quantum_effective_strength >= 128
    
    return {
        "simulation_id": sim_id,
        "attack_type": "Grover's Algorithm",
        "target_crypto": req.algo,
        "original_bit_strength": bit_strength,
        "quantum_effective_strength": quantum_effective_strength,
        "is_quantum_safe": safe,
        "mitigation_recommended": f"Upgrade to AES-{bit_strength*2}" if not safe else "None required",
        "success_probability": 1.0
    }

@app.post("/quantum/attack/hndl")
async def hndl_risk(req: HNDLRequest):
    """Harvest Now, Decrypt Later (HNDL) risk assessment."""
    threat_life = 20 if req.data_classification == "top_secret" else 5
    quantum_timeline = 10 # Estimated years until CRQC
    
    at_risk = threat_life > quantum_timeline
    
    return {
        "assessment": "Harvest Now Decrypt Later",
        "data_classification": req.data_classification,
        "data_shelf_life_years": threat_life,
        "expected_quantum_timeline_years": quantum_timeline,
        "is_at_risk": at_risk,
        "mitigation_recommended": "Immediate re-encryption with Kyber-1024 hybrid architecture" if at_risk else "Monitor quantum advances"
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "quantum-attack-simulator"}

@app.get("/metrics")
async def metrics():
    return "# Quantum Attack Simulator Metrics\nquantum_attack_simulations_total 0\n"
