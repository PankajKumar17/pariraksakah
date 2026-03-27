"""
CyberShield-X — CEF (Common Event Format) over Syslog Adapter.
Formats alerts as ArcSight-compatible CEF strings and sends them
via UDP syslog (RFC 5424) to a configurable SIEM target.
Falls back to stdout logging if SYSLOG_HOST is not configured.
"""

from __future__ import annotations

import logging
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger("siem.cef_syslog")

SYSLOG_HOST = os.getenv("SYSLOG_HOST", "")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
SIMULATE    = not bool(SYSLOG_HOST)

# CEF severity mapping (0=lowest, 10=highest)
CEF_SEVERITY = {"LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}

# Syslog PRI: facility=1 (user-level), severity=5 (notice) → <13>
SYSLOG_PRI = "<13>"

VENDOR      = "CyberShield-X"
PRODUCT     = "Pariraksakah"
VERSION     = "1.0"
DEVICE_HOST = "cybershield-siem"


def _build_cef(alert: Dict[str, Any]) -> str:
    """Format alert as a CEF string.

    CEF format:
      CEF:Version|Device Vendor|Device Product|Device Version|
      Signature ID|Name|Severity|[Extension]
    """
    sig_id   = alert.get("mitre_technique") or alert.get("alert_id", "UNKNOWN")[:12]
    name     = alert.get("attack_type", "UNKNOWN").replace("|", "/")
    severity = CEF_SEVERITY.get(alert.get("severity", "LOW").upper(), 3)

    # Extension key=value pairs (CEF allows no spaces in keys, pipe-escape in values)
    ext_parts = []
    if alert.get("source_ip"):
        ext_parts.append(f"src={alert['source_ip']}")
    if alert.get("destination_ip"):
        ext_parts.append(f"dst={alert['destination_ip']}")
    ext_parts.append(f"cs1={alert.get('alert_id', '')}")
    ext_parts.append(f"cs1Label=AlertID")
    ext_parts.append(f"cs2={alert.get('threat_score', 0.0):.4f}")
    ext_parts.append(f"cs2Label=ThreatScore")
    ext_parts.append(f"cs3={alert.get('confidence', 0.0):.4f}")
    ext_parts.append(f"cs3Label=Confidence")
    if alert.get("mitre_tactic"):
        ext_parts.append(f"cs4={alert['mitre_tactic']}")
        ext_parts.append(f"cs4Label=MITRETactic")
    ext_parts.append(f"rt={int(time.time() * 1000)}")

    ext = " ".join(ext_parts)
    cef = f"CEF:0|{VENDOR}|{PRODUCT}|{VERSION}|{sig_id}|{name}|{severity}|{ext}"
    return cef


def _build_syslog_message(cef: str) -> str:
    """Wrap CEF in RFC 5424 syslog header."""
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{SYSLOG_PRI}1 {ts} {DEVICE_HOST} CyberShieldX - - - {cef}"


async def forward(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Forward alert as CEF over UDP syslog."""
    cef     = _build_cef(alert)
    message = _build_syslog_message(cef)
    t0      = time.perf_counter()

    if SIMULATE:
        logger.info(
            "[CEF/Syslog] (simulated) %s", message
        )
        return {
            "destination": "syslog",
            "status":      "simulated",
            "cef_message": message,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "message":     "Dry-run: set SYSLOG_HOST to enable real forwarding",
        }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(message.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
        sock.close()
        latency = (time.perf_counter() - t0) * 1000
        logger.info(
            "[CEF/Syslog] Alert %s sent to %s:%d",
            alert.get("alert_id", "?")[:8], SYSLOG_HOST, SYSLOG_PORT,
        )
        return {
            "destination": "syslog",
            "status":      "success",
            "target":      f"{SYSLOG_HOST}:{SYSLOG_PORT}",
            "latency_ms":  round(latency, 2),
        }
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000
        logger.error("[CEF/Syslog] Send failed: %s", exc)
        return {"destination": "syslog", "status": "error", "error": str(exc), "latency_ms": round(latency, 2)}


async def health() -> Dict[str, Any]:
    """Check reachability of the syslog target."""
    if SIMULATE:
        return {"adapter": "syslog", "mode": "simulated", "healthy": True}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"<13>1 - - - - - - CyberShieldX health-check", (SYSLOG_HOST, SYSLOG_PORT))
        sock.close()
        return {"adapter": "syslog", "mode": "live", "healthy": True, "target": f"{SYSLOG_HOST}:{SYSLOG_PORT}"}
    except Exception as exc:
        return {"adapter": "syslog", "mode": "live", "healthy": False, "error": str(exc)}
