"""
P10 — Bio-Cyber Fusion Authentication API
FastAPI service with 5 endpoints:
  POST /enroll/ecg          — Enroll ECG biometric template
  POST /enroll/keystroke    — Enroll keystroke dynamics profile
  POST /verify/ecg          — Verify ECG identity
  POST /verify/keystroke    — Verify keystroke identity
  POST /verify/fusion       — Multi-modal fusion verification
"""

import logging
from typing import List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..ecg_processor import ECGProcessor
from ..keystroke_dynamics import KeyEvent, KeystrokeDynamics
from ..siamese_network import HeuristicSiamese

logger = logging.getLogger("cybershield.bioauth.api")

app = FastAPI(title="CyberShield-X Bio-Auth", version="1.0.0")

# ── Service singletons ──────────────────────────

ecg_processor = ECGProcessor(sample_rate=500)
keystroke_engine = KeystrokeDynamics(threshold=0.65)
siamese = HeuristicSiamese(threshold=0.85)
ecg_templates: dict = {}  # user_id → np.ndarray embedding


# ── Request / Response schemas ──────────────────

class ECGEnrollRequest(BaseModel):
    user_id: str
    signal: List[float]
    sample_rate: int = 500


class ECGVerifyRequest(BaseModel):
    user_id: str
    signal: List[float]
    sample_rate: int = 500


class KeystrokeEvent(BaseModel):
    key: str
    press_time: float
    release_time: float


class KeystrokeEnrollRequest(BaseModel):
    user_id: str
    sessions: List[List[KeystrokeEvent]]


class KeystrokeVerifyRequest(BaseModel):
    user_id: str
    events: List[KeystrokeEvent]


class FusionVerifyRequest(BaseModel):
    user_id: str
    ecg_signal: Optional[List[float]] = None
    ecg_sample_rate: int = 500
    keystroke_events: Optional[List[KeystrokeEvent]] = None


class VerifyResponse(BaseModel):
    user_id: str
    is_authentic: bool
    confidence: float
    modality: str


# ── Endpoints ───────────────────────────────────

@app.post("/enroll/ecg", response_model=dict)
async def enroll_ecg(req: ECGEnrollRequest):
    """Enroll an ECG biometric template for a user."""
    signal = np.array(req.signal)
    features = ecg_processor.process(signal)
    embedding = siamese.get_embedding(np.array(features.morphology_vector))
    ecg_templates[req.user_id] = embedding
    return {"user_id": req.user_id, "status": "enrolled", "features_dim": len(embedding)}


@app.post("/enroll/keystroke", response_model=dict)
async def enroll_keystroke(req: KeystrokeEnrollRequest):
    """Enroll keystroke dynamics profile for a user."""
    sessions = [
        [KeyEvent(key=e.key, press_time=e.press_time, release_time=e.release_time) for e in sess]
        for sess in req.sessions
    ]
    profile = keystroke_engine.enroll(req.user_id, sessions)
    return {"user_id": req.user_id, "status": "enrolled", "samples": profile.sample_count}


@app.post("/verify/ecg", response_model=VerifyResponse)
async def verify_ecg(req: ECGVerifyRequest):
    """Verify user identity via ECG signal."""
    if req.user_id not in ecg_templates:
        raise HTTPException(status_code=404, detail="No ECG template enrolled")

    signal = np.array(req.signal)
    features = ecg_processor.process(signal)
    sample_emb = siamese.get_embedding(np.array(features.morphology_vector))
    template = ecg_templates[req.user_id]
    is_auth, score = siamese.verify(template, sample_emb)

    return VerifyResponse(
        user_id=req.user_id,
        is_authentic=is_auth,
        confidence=float(score),
        modality="ecg",
    )


@app.post("/verify/keystroke", response_model=VerifyResponse)
async def verify_keystroke(req: KeystrokeVerifyRequest):
    """Verify user identity via keystroke dynamics."""
    events = [KeyEvent(key=e.key, press_time=e.press_time, release_time=e.release_time) for e in req.events]
    result = keystroke_engine.authenticate(req.user_id, events)

    return VerifyResponse(
        user_id=req.user_id,
        is_authentic=result.is_authentic,
        confidence=result.confidence,
        modality="keystroke",
    )


@app.post("/verify/fusion", response_model=VerifyResponse)
async def verify_fusion(req: FusionVerifyRequest):
    """Multi-modal biometric fusion verification.
    
    Combines ECG and keystroke scores with weighted averaging:
    - ECG weight: 0.6 (higher physiological uniqueness)
    - Keystroke weight: 0.4 (behavioral complement)
    """
    scores = []
    weights = []

    # ECG modality
    if req.ecg_signal and req.user_id in ecg_templates:
        signal = np.array(req.ecg_signal)
        features = ecg_processor.process(signal)
        sample_emb = siamese.get_embedding(np.array(features.morphology_vector))
        template = ecg_templates[req.user_id]
        _, ecg_score = siamese.verify(template, sample_emb)
        scores.append(ecg_score)
        weights.append(0.6)

    # Keystroke modality
    if req.keystroke_events:
        events = [KeyEvent(key=e.key, press_time=e.press_time, release_time=e.release_time) for e in req.keystroke_events]
        ks_result = keystroke_engine.authenticate(req.user_id, events)
        scores.append(ks_result.confidence)
        weights.append(0.4)

    if not scores:
        raise HTTPException(status_code=400, detail="At least one biometric modality required")

    # Weighted fusion
    total_weight = sum(weights)
    fused_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
    is_auth = fused_score >= 0.7

    return VerifyResponse(
        user_id=req.user_id,
        is_authentic=is_auth,
        confidence=float(fused_score),
        modality="fusion",
    )


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "bio-auth", "version": "1.0.0"}
