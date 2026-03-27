"""
CyberShield-X — Elasticsearch / OpenSearch SIEM Adapter.
Indexes security alerts using Elastic Common Schema (ECS) format
into rolling daily indices: cybershield-alerts-YYYY.MM.DD
Falls back to simulated dry-run if ELASTIC_URL is not configured.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict

import httpx

logger = logging.getLogger("siem.elastic")

ELASTIC_URL   = os.getenv("ELASTIC_URL",      "")  # e.g. http://elasticsearch:9200
ELASTIC_USER  = os.getenv("ELASTIC_USER",     "elastic")
ELASTIC_PASS  = os.getenv("ELASTIC_PASSWORD", "")
SIMULATE      = not bool(ELASTIC_URL)


def _index_name() -> str:
    """Generate rolling daily index name."""
    return f"cybershield-alerts-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


def _ecs_document(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an internal alert to an ECS-compliant document."""
    return {
        "@timestamp":      alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "event": {
            "kind":     "alert",
            "category": ["intrusion_detection"],
            "type":     ["indicator"],
            "severity": _severity_to_int(alert.get("severity", "LOW")),
            "outcome":  "unknown",
            "id":       alert.get("alert_id"),
        },
        "source": {
            "ip": alert.get("source_ip"),
        },
        "destination": {
            "ip": alert.get("destination_ip"),
        },
        "threat": {
            "technique": {
                "id":   [alert.get("mitre_technique")] if alert.get("mitre_technique") else [],
                "name": [alert.get("attack_type", "UNKNOWN")],
            },
            "tactic": {
                "name": [alert.get("mitre_tactic")] if alert.get("mitre_tactic") else [],
            },
            "indicator": {
                "confidence": str(round(alert.get("confidence", 0.0) * 100)),
            },
        },
        "labels": {
            "attack_type":  alert.get("attack_type"),
            "severity":     alert.get("severity"),
            "threat_score": str(alert.get("threat_score", 0.0)),
            "origin":       "cybershield-x",
        },
        "cybershield": {
            "alert_id":     alert.get("alert_id"),
            "threat_score": alert.get("threat_score", 0.0),
            "confidence":   alert.get("confidence", 0.0),
            "event_ids":    alert.get("event_ids", []),
            "threat_intel": alert.get("threat_intel"),
        },
    }


def _severity_to_int(severity: str) -> int:
    return {"CRITICAL": 99, "HIGH": 73, "MEDIUM": 47, "LOW": 21}.get(severity.upper(), 21)


async def forward(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Index alert into Elasticsearch/OpenSearch."""
    doc   = _ecs_document(alert)
    index = _index_name()
    t0    = time.perf_counter()

    if SIMULATE:
        logger.info(
            "[Elastic] (simulated) Would index alert %s into %s | severity=%s",
            alert.get("alert_id", "?")[:8], index, alert.get("severity"),
        )
        return {
            "destination": "elasticsearch",
            "status":      "simulated",
            "index":       index,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "message":     "Dry-run: set ELASTIC_URL to enable real indexing",
        }

    url = f"{ELASTIC_URL}/{index}/_doc"
    auth = (ELASTIC_USER, ELASTIC_PASS) if ELASTIC_PASS else None

    try:
        async with httpx.AsyncClient(timeout=10, auth=auth) as client:
            resp = await client.post(
                url,
                headers={"Content-Type": "application/json"},
                content=json.dumps(doc),
            )
            latency = (time.perf_counter() - t0) * 1000
            if resp.status_code in (200, 201):
                doc_id = resp.json().get("_id", "?")
                logger.info("[Elastic] Alert indexed as %s in %s", doc_id, index)
                return {"destination": "elasticsearch", "status": "success", "doc_id": doc_id, "index": index, "latency_ms": round(latency, 2)}
            else:
                logger.warning("[Elastic] HTTP %d: %s", resp.status_code, resp.text[:200])
                return {"destination": "elasticsearch", "status": "error", "http_code": resp.status_code, "latency_ms": round(latency, 2)}
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000
        logger.error("[Elastic] Request failed: %s", exc)
        return {"destination": "elasticsearch", "status": "error", "error": str(exc), "latency_ms": round(latency, 2)}


async def health() -> Dict[str, Any]:
    """Check Elasticsearch cluster health."""
    if SIMULATE:
        return {"adapter": "elasticsearch", "mode": "simulated", "healthy": True}
    try:
        auth = (ELASTIC_USER, ELASTIC_PASS) if ELASTIC_PASS else None
        async with httpx.AsyncClient(timeout=5, auth=auth) as client:
            resp = await client.get(f"{ELASTIC_URL}/_cluster/health")
            data = resp.json()
            return {
                "adapter": "elasticsearch",
                "mode":    "live",
                "healthy": data.get("status") in ("green", "yellow"),
                "cluster": data.get("cluster_name"),
                "status":  data.get("status"),
            }
    except Exception as exc:
        return {"adapter": "elasticsearch", "mode": "live", "healthy": False, "error": str(exc)}
