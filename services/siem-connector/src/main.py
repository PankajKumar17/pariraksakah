"""
CyberShield-X — SIEM Connector Service.
FastAPI entrypoint exposing:
  POST /forward      — receive alert and dispatch to all SIEM destinations
  GET  /health       — adapter health check
  GET  /stats        — forwarding statistics and recent event history
  POST /test         — inject a synthetic test alert
"""

from __future__ import annotations

import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Add src/ to path for adapter imports
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, make_asgi_app
from pydantic import BaseModel

from dispatcher import SIEMDispatcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("siem-connector")

ALERTS_FORWARDED = Counter("siem_alerts_forwarded_total",  "Total alerts forwarded to SIEM", ["destination", "status"])
FORWARD_LATENCY  = Histogram("siem_forward_latency_seconds","Forwarding latency per destination", ["destination"])

app = FastAPI(
    title="CyberShield-X SIEM Connector",
    version="1.0.0",
    description="Multi-destination SIEM forwarding service (Splunk, Elastic, CEF/Syslog)",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())

dispatcher = SIEMDispatcher()


# ── Schemas ────────────────────────────────────

class AlertPayload(BaseModel):
    alert_id:        Optional[str] = None
    timestamp:       Optional[str] = None
    severity:        str = "LOW"
    attack_type:     str = "UNKNOWN"
    threat_score:    float = 0.0
    confidence:      float = 0.0
    source_ip:       Optional[str] = None
    destination_ip:  Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic:    Optional[str] = None
    event_ids:       List[str] = []
    threat_intel:    Optional[Dict[str, Any]] = None


class ForwardResponse(BaseModel):
    alert_id:         str
    dispatched_to:    int
    results:          List[Dict[str, Any]]
    total_latency_ms: float


# ── Endpoints ──────────────────────────────────

@app.post("/forward", response_model=ForwardResponse)
async def forward_alert(payload: AlertPayload) -> ForwardResponse:
    """Receive a security alert and fan it out to all configured SIEM destinations."""
    import time
    t0 = time.perf_counter()

    alert = payload.dict()
    if not alert.get("alert_id"):
        alert["alert_id"] = str(uuid.uuid4())
    if not alert.get("timestamp"):
        alert["timestamp"] = datetime.now(timezone.utc).isoformat()

    results = await dispatcher.dispatch(alert)

    # Record Prometheus metrics
    for r in results:
        dest   = r.get("destination", "unknown")
        status = r.get("status", "error")
        lat    = r.get("latency_ms", 0) / 1000
        ALERTS_FORWARDED.labels(destination=dest, status=status).inc()
        FORWARD_LATENCY.labels(destination=dest).observe(lat)

    total_latency = (time.perf_counter() - t0) * 1000
    return ForwardResponse(
        alert_id=alert["alert_id"],
        dispatched_to=len(results),
        results=results,
        total_latency_ms=round(total_latency, 2),
    )


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Check connectivity to all SIEM destinations."""
    return await dispatcher.health_check()


@app.get("/stats")
async def get_stats() -> Dict[str, Any]:
    """Return forwarding statistics and recent event history."""
    return dispatcher.get_stats()


@app.post("/test")
async def send_test_alert() -> ForwardResponse:
    """Inject a synthetic test alert to validate all adapters."""
    test_alert = AlertPayload(
        alert_id=f"test-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        severity="HIGH",
        attack_type="PortScan",
        threat_score=0.87,
        confidence=0.92,
        source_ip="203.0.113.42",
        destination_ip="10.1.1.50",
        mitre_technique="T1046",
        mitre_tactic="discovery",
        event_ids=[f"evt-{uuid.uuid4().hex[:8]}"],
        threat_intel={"reputation": -3, "malicious_votes": 12, "source": "test"},
    )
    return await forward_alert(test_alert)


@app.on_event("startup")
async def startup() -> None:
    logger.info("SIEM Connector Service v1.0.0 starting up")
    health = await dispatcher.health_check()
    for adapter in health.get("adapters", []):
        status = "✓ healthy" if adapter.get("healthy") else "⚠ degraded"
        logger.info("  Adapter [%s] → %s (mode=%s)", adapter.get("adapter","?"), status, adapter.get("mode","?"))


@app.on_event("shutdown")
async def shutdown() -> None:
    logger.info("SIEM Connector Service shutting down")
