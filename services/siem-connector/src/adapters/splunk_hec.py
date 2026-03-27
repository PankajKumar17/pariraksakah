"""
CyberShield-X — Splunk HTTP Event Collector (HEC) Adapter.
Forwards enriched security alerts to Splunk Enterprise / Splunk Cloud.
Falls back to simulated dry-run logging if HEC credentials are not set.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("siem.splunk_hec")

SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL",   "http://splunk:8088")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN",  "")
SPLUNK_INDEX     = os.getenv("SPLUNK_INDEX",       "cybershield")
SPLUNK_SOURCETYPE= os.getenv("SPLUNK_SOURCETYPE",  "cybershield:alert")

SIMULATE = not bool(SPLUNK_HEC_TOKEN)


def _build_hec_payload(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Format an alert as a Splunk HEC JSON event payload."""
    return {
        "time":       time.time(),
        "host":       alert.get("source_ip", "unknown"),
        "source":     "cybershield-x",
        "sourcetype": SPLUNK_SOURCETYPE,
        "index":      SPLUNK_INDEX,
        "event": {
            "alert_id":        alert.get("alert_id"),
            "timestamp":       alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "severity":        alert.get("severity", "LOW"),
            "attack_type":     alert.get("attack_type", "UNKNOWN"),
            "threat_score":    alert.get("threat_score", 0.0),
            "confidence":      alert.get("confidence", 0.0),
            "source_ip":       alert.get("source_ip"),
            "destination_ip":  alert.get("destination_ip"),
            "mitre_technique": alert.get("mitre_technique"),
            "mitre_tactic":    alert.get("mitre_tactic"),
            "event_ids":       alert.get("event_ids", []),
            "threat_intel":    alert.get("threat_intel"),
        },
    }


async def forward(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Forward a security alert to Splunk via HEC.

    Returns a result dict with status, destination, and latency_ms.
    """
    payload = _build_hec_payload(alert)
    t0 = time.perf_counter()

    if SIMULATE:
        logger.info(
            "[Splunk HEC] (simulated) Would forward alert %s | severity=%s | attack=%s",
            alert.get("alert_id", "?")[:8],
            alert.get("severity"),
            alert.get("attack_type"),
        )
        latency = (time.perf_counter() - t0) * 1000
        return {
            "destination": "splunk",
            "status":      "simulated",
            "latency_ms":  round(latency, 2),
            "message":     "Dry-run: set SPLUNK_HEC_TOKEN to enable real forwarding",
        }

    url = f"{SPLUNK_HEC_URL}/services/collector/event"
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type":  "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, headers=headers, content=json.dumps(payload))
            latency = (time.perf_counter() - t0) * 1000
            if resp.status_code == 200:
                logger.info("[Splunk HEC] Alert %s forwarded. HTTP 200", alert.get("alert_id", "?")[:8])
                return {"destination": "splunk", "status": "success", "latency_ms": round(latency, 2)}
            else:
                logger.warning("[Splunk HEC] HTTP %d: %s", resp.status_code, resp.text[:200])
                return {"destination": "splunk", "status": "error", "http_code": resp.status_code, "latency_ms": round(latency, 2)}
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000
        logger.error("[Splunk HEC] Request failed: %s", exc)
        return {"destination": "splunk", "status": "error", "error": str(exc), "latency_ms": round(latency, 2)}


async def health() -> Dict[str, Any]:
    """Check connectivity to the Splunk HEC endpoint."""
    if SIMULATE:
        return {"adapter": "splunk", "mode": "simulated", "healthy": True}
    url = f"{SPLUNK_HEC_URL}/services/collector/health"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url, headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"})
            return {"adapter": "splunk", "mode": "live", "healthy": resp.status_code == 200, "http_code": resp.status_code}
    except Exception as exc:
        return {"adapter": "splunk", "mode": "live", "healthy": False, "error": str(exc)}
