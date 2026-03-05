"""
CyberShield-X — Real-time ML Inference Service
FastAPI endpoint for threat scoring with SHAP explainability.
Processes Kafka stream in real-time and exposes POST /predict.
Target latency: <5ms per inference.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import torch
import torch.nn.functional as F
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("cybershield.inference.ml_inference")

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────

MODEL_DIR = Path(os.getenv("MODEL_DIR", "/app/ml-models/saved"))
GNN_PATH = MODEL_DIR / "gnn_threat_detection.pt"
UEBA_PATH = MODEL_DIR / "ueba_autoencoder.pt"

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

ATTACK_LABELS = [
    "BENIGN", "DDoS", "PortScan", "BruteForce", "Botnet",
    "Infiltration", "WebAttack", "Ransomware", "C2", "Exfiltration",
]

MITRE_TECHNIQUE_MAP = {
    "DDoS": "T1498",
    "PortScan": "T1046",
    "BruteForce": "T1110",
    "Botnet": "T1583.005",
    "Infiltration": "T1078",
    "WebAttack": "T1190",
    "Ransomware": "T1486",
    "C2": "T1071",
    "Exfiltration": "T1041",
}


# ──────────────────────────────────────────────
# Request / Response models
# ──────────────────────────────────────────────

class PredictRequest(BaseModel):
    """Input event for threat prediction."""

    event_id: str
    features: List[float] = Field(..., min_length=1, max_length=64)
    event_type: str = "NETWORK"


class SHAPExplanation(BaseModel):
    """Top contributing features for this prediction."""

    feature_index: int
    feature_name: str
    shap_value: float


class PredictResponse(BaseModel):
    """Inference result."""

    event_id: str
    threat_score: float = Field(..., ge=0, le=1)
    is_threat: bool
    attack_type: str
    confidence: float
    mitre_technique: Optional[str] = None
    explanations: List[SHAPExplanation] = []
    inference_latency_ms: float


# ──────────────────────────────────────────────
# Model Manager
# ──────────────────────────────────────────────

class ModelManager:
    """Loads and caches PyTorch models for inference."""

    def __init__(self) -> None:
        self.gnn_model = None
        self.ueba_model = None
        self._shap_explainer = None

    def load_models(self) -> None:
        """Load saved model checkpoints."""
        # GNN
        if GNN_PATH.exists():
            from ml_models.threat_detection.gnn_model import ThreatDetectionGNN

            self.gnn_model = ThreatDetectionGNN().to(DEVICE)
            self.gnn_model.load_state_dict(
                torch.load(GNN_PATH, map_location=DEVICE, weights_only=True)
            )
            self.gnn_model.eval()
            logger.info("GNN model loaded from %s", GNN_PATH)
        else:
            logger.warning("GNN model not found at %s", GNN_PATH)

        # UEBA
        if UEBA_PATH.exists():
            from ml_models.threat_detection.ueba_model import UEBAAutoencoder

            self.ueba_model = UEBAAutoencoder(input_dim=50).to(DEVICE)
            self.ueba_model.load_state_dict(
                torch.load(UEBA_PATH, map_location=DEVICE, weights_only=True)
            )
            self.ueba_model.eval()
            logger.info("UEBA model loaded from %s", UEBA_PATH)
        else:
            logger.warning("UEBA model not found at %s", UEBA_PATH)

    def _init_shap(self) -> None:
        """Lazily initialize SHAP explainer (expensive)."""
        if self._shap_explainer is None and self.gnn_model is not None:
            try:
                import shap  # type: ignore[import-untyped]

                # Simple wrapper for SHAP: features → threat score
                def model_fn(x_np):
                    x_t = torch.tensor(x_np, dtype=torch.float, device=DEVICE)
                    if x_t.dim() == 1:
                        x_t = x_t.unsqueeze(0)
                    # Dummy edge_index (self-loops) for single-node inference
                    n = x_t.size(0)
                    ei = torch.stack([torch.arange(n), torch.arange(n)]).to(DEVICE)
                    with torch.no_grad():
                        b_logits, _ = self.gnn_model(x_t, ei)
                    return F.softmax(b_logits, dim=1)[:, 1].cpu().numpy()

                background = np.zeros((10, 32), dtype=np.float32)
                self._shap_explainer = shap.KernelExplainer(model_fn, background)
                logger.info("SHAP explainer initialised")
            except Exception:
                logger.warning("SHAP explainer init failed", exc_info=True)

    @torch.no_grad()
    def predict_gnn(self, features: List[float]) -> Dict[str, Any]:
        """Run GNN inference on a single event.

        Returns dict with threat_score, attack_type, confidence.
        """
        if self.gnn_model is None:
            raise RuntimeError("GNN model not loaded")

        x = torch.tensor([features[:32]], dtype=torch.float, device=DEVICE)
        if x.size(1) < 32:
            x = F.pad(x, (0, 32 - x.size(1)))

        # Single-node inference: self-loop edge
        edge_index = torch.tensor([[0], [0]], dtype=torch.long, device=DEVICE)

        b_logits, a_logits = self.gnn_model(x, edge_index)
        threat_prob = F.softmax(b_logits, dim=1)[0, 1].item()
        attack_probs = F.softmax(a_logits, dim=1)[0]
        attack_idx = attack_probs.argmax().item()
        attack_type = ATTACK_LABELS[attack_idx] if attack_idx < len(ATTACK_LABELS) else "UNKNOWN"
        confidence = attack_probs[attack_idx].item()

        return {
            "threat_score": threat_prob,
            "is_threat": threat_prob > 0.5,
            "attack_type": attack_type,
            "confidence": confidence,
            "mitre_technique": MITRE_TECHNIQUE_MAP.get(attack_type),
        }

    def explain(self, features: List[float], top_k: int = 5) -> List[SHAPExplanation]:
        """Generate SHAP explanations for prediction.

        Returns top-k contributing features.
        """
        self._init_shap()
        if self._shap_explainer is None:
            return []

        x = np.array(features[:32], dtype=np.float32).reshape(1, -1)
        if x.shape[1] < 32:
            x = np.pad(x, ((0, 0), (0, 32 - x.shape[1])))

        try:
            shap_values = self._shap_explainer.shap_values(x, nsamples=50)
            if isinstance(shap_values, list):
                vals = shap_values[0][0]
            else:
                vals = shap_values[0]

            top_indices = np.argsort(np.abs(vals))[-top_k:][::-1]
            return [
                SHAPExplanation(
                    feature_index=int(i),
                    feature_name=f"feature_{i}",
                    shap_value=float(vals[i]),
                )
                for i in top_indices
            ]
        except Exception:
            logger.warning("SHAP explanation failed", exc_info=True)
            return []


# ──────────────────────────────────────────────
# FastAPI app
# ──────────────────────────────────────────────

app = FastAPI(title="CyberShield-X Inference", version="1.0.0")
model_manager = ModelManager()


@app.on_event("startup")
async def startup() -> None:
    model_manager.load_models()


@app.post("/predict", response_model=PredictResponse)
async def predict(request: PredictRequest) -> PredictResponse:
    """Run threat prediction on a security event.

    Returns threat score, attack type, confidence, MITRE technique,
    and SHAP explanations for top 5 contributing features.
    """
    t0 = time.perf_counter()
    try:
        result = model_manager.predict_gnn(request.features)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    explanations = model_manager.explain(request.features)
    latency_ms = (time.perf_counter() - t0) * 1000

    return PredictResponse(
        event_id=request.event_id,
        threat_score=round(result["threat_score"], 6),
        is_threat=result["is_threat"],
        attack_type=result["attack_type"],
        confidence=round(result["confidence"], 6),
        mitre_technique=result.get("mitre_technique"),
        explanations=explanations,
        inference_latency_ms=round(latency_ms, 3),
    )


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "gnn": "loaded" if model_manager.gnn_model else "missing"}
