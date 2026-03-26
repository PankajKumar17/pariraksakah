"""
CyberShield-X — SIEM Dispatcher.
Fans out a security alert to all configured SIEM adapters concurrently.
Tracks per-adapter success/failure counts and uptime.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

from adapters import splunk_hec, elastic_adapter, cef_syslog

logger = logging.getLogger("siem.dispatcher")


@dataclass
class DispatchStats:
    destination: str
    total_forwarded: int = 0
    total_errors:    int = 0
    last_success_at: str = ""
    last_error:      str = ""
    average_latency_ms: float = 0.0
    _latencies: List[float] = field(default_factory=list, repr=False)

    def record_success(self, latency_ms: float) -> None:
        self.total_forwarded += 1
        self.last_success_at = datetime.now(timezone.utc).isoformat()
        self._latencies.append(latency_ms)
        if len(self._latencies) > 100:
            self._latencies.pop(0)
        self.average_latency_ms = sum(self._latencies) / len(self._latencies)

    def record_error(self, error: str) -> None:
        self.total_errors += 1
        self.last_error = error


class SIEMDispatcher:
    """Dispatch alerts to all SIEM adapters concurrently."""

    def __init__(self) -> None:
        self._stats: Dict[str, DispatchStats] = {
            "splunk":          DispatchStats(destination="splunk"),
            "elasticsearch":   DispatchStats(destination="elasticsearch"),
            "syslog":          DispatchStats(destination="syslog"),
        }
        self._dispatch_history: List[Dict[str, Any]] = []
        self._start_time = time.time()

    async def dispatch(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fan out alert to all adapters and collect results."""
        tasks = [
            splunk_hec.forward(alert),
            elastic_adapter.forward(alert),
            cef_syslog.forward(alert),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed = []
        for res in results:
            if isinstance(res, Exception):
                res = {"status": "error", "error": str(res), "latency_ms": 0}

            dest  = res.get("destination", "unknown")
            stats = self._stats.get(dest)

            if stats:
                if res.get("status") in ("success", "simulated"):
                    stats.record_success(res.get("latency_ms", 0))
                else:
                    stats.record_error(res.get("error", "unknown error"))

            processed.append(res)

        # Record in history (keep last 200)
        self._dispatch_history.append({
            "alert_id":    alert.get("alert_id", "?"),
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "severity":    alert.get("severity"),
            "attack_type": alert.get("attack_type"),
            "results":     processed,
        })
        if len(self._dispatch_history) > 200:
            self._dispatch_history.pop(0)

        logger.info(
            "[Dispatcher] Alert %s dispatched to %d adapters",
            alert.get("alert_id", "?")[:8], len(processed),
        )
        return processed

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all adapters."""
        results = await asyncio.gather(
            splunk_hec.health(),
            elastic_adapter.health(),
            cef_syslog.health(),
            return_exceptions=True,
        )
        adapters = []
        for r in results:
            if isinstance(r, Exception):
                adapters.append({"healthy": False, "error": str(r)})
            else:
                adapters.append(r)
        return {
            "status":   "healthy" if all(a.get("healthy") for a in adapters) else "degraded",
            "adapters": adapters,
            "uptime_s": round(time.time() - self._start_time),
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "destinations":  [
                {
                    "destination":      s.destination,
                    "total_forwarded":  s.total_forwarded,
                    "total_errors":     s.total_errors,
                    "avg_latency_ms":   round(s.average_latency_ms, 2),
                    "last_success_at":  s.last_success_at,
                    "last_error":       s.last_error or None,
                }
                for s in self._stats.values()
            ],
            "recent_events": self._dispatch_history[-20:][::-1],
            "uptime_s":      round(time.time() - self._start_time),
        }
