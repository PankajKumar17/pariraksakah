"""
CyberShield-X — Real-Time Log Aggregation Engine.

Listens for Syslog (RFC 3164/5424) over UDP and JSON structured logs.
Parses, normalizes, and feeds logs into the ATDE pipeline for threat detection.

Includes a realistic log simulator for demonstration and testing purposes.

Environment variables:
  SYSLOG_LISTEN_HOST  Bind address for syslog server (default: "0.0.0.0")
  SYSLOG_LISTEN_PORT  UDP port for syslog server (default: 5140)
  SIMULATE_LOGS       Set to "1" to force realistic log simulation (default: "0")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("cybershield.ingestion.log_collector")

SYSLOG_HOST   = os.getenv("SYSLOG_LISTEN_HOST", "0.0.0.0")
SYSLOG_PORT   = int(os.getenv("SYSLOG_LISTEN_PORT", "5140"))
FORCE_SIMULATE= os.getenv("SIMULATE_LOGS", "0") == "1"

# ─────────────────────────────────────────
# Regex Patterns & Parsing
# ─────────────────────────────────────────

# RFC 3164: <PRI>TIMESTAMP HOSTNAME APP[PID]: MESSAGE
RFC3164_REGEX = re.compile(
    r"^<(?P<pri>\d+)>(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>[^\s]+)\s+(?P<app>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)"
)

# Crude severity mapping from PRI (facility/severity)
def _severity_from_pri(pri_str: str) -> str:
    try:
        pri = int(pri_str)
        sev = pri & 0x07
        if sev <= 2: return "CRITICAL"
        if sev <= 4: return "WARN"
        return "INFO"
    except Exception:
        return "INFO"


def parse_syslog(data: str) -> Optional[Dict[str, Any]]:
    """Parse raw syslog line into a structured event dict."""
    m = RFC3164_REGEX.match(data)
    if not m:
        # Fallback raw log
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": "unknown",
            "app_name": "syslog",
            "severity": "INFO",
            "message": data.strip(),
            "raw": data.strip(),
        }
    
    match = m.groupdict()
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": match.get("host", "unknown"),
        "app_name": match.get("app", "unknown"),
        "severity": _severity_from_pri(match.get("pri", "13")),
        "message": match.get("msg", "").strip(),
        "raw": data.strip(),
    }


# ─────────────────────────────────────────
# Log Simulator
# ─────────────────────────────────────────

_SIM_HOSTS = ["web-prod-01", "web-prod-02", "db-primary", "auth-gateway", "k8s-worker-1"]

def _simulate_log() -> Dict[str, Any]:
    """Generate realistic synthetic logs for demo purposes.
    20% chance of an 'attack' log (e.g. brute force, SQLi).
    """
    host = random.choice(_SIM_HOSTS)
    now = datetime.now(timezone.utc).isoformat()
    evt_id = str(uuid.uuid4())

    is_attack = random.random() < 0.20

    if is_attack:
        scenarios = [
            {
                "app": "sshd", "sev": "WARN",
                "msg": f"Failed password for invalid user admin from {random.randint(100,200)}.{random.randint(1,254)}.{random.randint(1,254)}.42 port {random.randint(30000, 60000)} ssh2",
                "_label": "brute_force"
            },
            {
                "app": "nginx", "sev": "CRITICAL",
                "msg": "10.0.0.5 - - [GET /api/v1/users?id=1%20OR%201=1 HTTP/1.1] 500 1202 \"-\" \"sqlmap/1.5\"",
                "_label": "sqli"
            },
            {
                "app": "auth-service", "sev": "WARN",
                "msg": f"Multiple failed login attempts detected for service account 'backup_mgr' ({random.randint(5, 50)} failures in 1m)",
                "_label": "brute_force"
            },
            {
                "app": "kernel", "sev": "CRITICAL",
                "msg": "grsec: denied untrusted exec of /tmp/.X11-unix/.r rootk by /bin/bash[bash:3412] uid/euid:33/33",
                "_label": "privilege_escalation"
            }
        ]
        s = random.choice(scenarios)
        return {
            "event_id": evt_id, "timestamp": now, "hostname": host,
            "app_name": s["app"], "severity": s["sev"], "message": s["msg"],
            "raw": f"<{random.randint(10,50)}>{now} {host} {s['app']}[1]: {s['msg']}",
            "_simulated": True, "_label": s["_label"]
        }
    else:
        scenarios = [
            {"app": "nginx", "sev": "INFO", "msg": "10.0.0.100 - - [GET /health HTTP/1.1] 200 45 \"-\" \"Consul Health Check\""},
            {"app": "systemd", "sev": "INFO", "msg": "Started Session 44 of user prometheus."},
            {"app": "dockerd", "sev": "INFO", "msg": "time=\"2026-03-26T12:00:00Z\" level=info msg=\"Container created: nginx\""},
            {"app": "postgres", "sev": "INFO", "msg": "LOG:  checkpoint complete: wrote 14 buffers (0.0%); 0 WAL file(s) added"},
            {"app": "auth-service", "sev": "INFO", "msg": "User john.doe successfully authenticated via SSO"},
        ]
        s = random.choice(scenarios)
        return {
            "event_id": evt_id, "timestamp": now, "hostname": host,
            "app_name": s["app"], "severity": s["sev"], "message": s["msg"],
            "raw": f"<13>{now} {host} {s['app']}[1]: {s['msg']}",
            "_simulated": True, "_label": "benign"
        }


# ─────────────────────────────────────────
# Async Syslog Server / Collector
# ─────────────────────────────────────────

class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue, counter_ref: list) -> None:
        self.queue = queue
        self.counter_ref = counter_ref  # [total_received]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        try:
            line = data.decode("utf-8", errors="replace").strip()
            if not line:
                return
            event = parse_syslog(line)
            if event:
                event["source_ip"] = addr[0]
                self.queue.put_nowait(event)
                self.counter_ref[0] += 1
        except asyncio.QueueFull:
            pass
        except Exception as exc:
            logger.debug("[LogCollector] Error parsing sysog from %s: %s", addr, exc)


class LogCollectorManager:
    """Manages the log ingestion pipeline (Syslog UDP + Simulator)."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._sim_task: Optional[asyncio.Task] = None
        self.logs_received = [0]  # List for mutability in protocol
        self._start_ts = 0.0
        self.mode = "simulated" if FORCE_SIMULATE else "live"

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._loop = asyncio.get_running_loop()
        self._start_ts = time.time()

        if self.mode == "simulated":
            logger.info("[LogCollector] Starting in SIMULATION mode.")
            self._sim_task = asyncio.create_task(self._simulate_loop())
        else:
            try:
                self._transport, _ = await self._loop.create_datagram_endpoint(
                    lambda: SyslogProtocol(self.queue, self.logs_received),
                    local_addr=(SYSLOG_HOST, SYSLOG_PORT)
                )
                logger.info("[LogCollector] Listening for UDP Syslog on %s:%d", SYSLOG_HOST, SYSLOG_PORT)
            except Exception as e:
                logger.warning("[LogCollector] Failed to bind syslog to %s:%d (%s). Falling back to SIMULATION.", SYSLOG_HOST, SYSLOG_PORT, e)
                self.mode = "simulated"
                self._sim_task = asyncio.create_task(self._simulate_loop())

    async def stop(self) -> None:
        self._running = False
        if self._transport:
            self._transport.close()
            self._transport = None
        if self._sim_task:
            self._sim_task.cancel()
            self._sim_task = None
        logger.info("[LogCollector] Stopped. Total logs: %d", self.logs_received[0])

    async def get_event(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def push_http_event(self, event: Dict[str, Any]) -> None:
        """Allow manual push of HTTP JSON logs."""
        try:
            event["event_id"] = event.get("event_id") or str(uuid.uuid4())
            event["timestamp"] = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
            self.queue.put_nowait(event)
            self.logs_received[0] += 1
        except asyncio.QueueFull:
            pass

    async def _simulate_loop(self) -> None:
        """Generates synthetic logs at ~5 EPS."""
        while self._running:
            evt = _simulate_log()
            try:
                self.queue.put_nowait(evt)
                self.logs_received[0] += 1
            except asyncio.QueueFull:
                pass
            # Random jitter 100ms - 400ms
            await asyncio.sleep(random.uniform(0.1, 0.4))

    def status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "mode": self.mode,
            "port": SYSLOG_PORT,
            "logs_received": self.logs_received[0],
            "uptime_s": round(time.time() - self._start_ts) if self._start_ts else 0
        }
