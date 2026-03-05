"""
P14 — Runtime Monitor
Python companion to the Rust code_genome module.
Monitors running service health and triggers self-healing
via the Rust API when anomalies are detected.
"""

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger("cybershield.self_healing.runtime_monitor")


@dataclass
class ServiceHealth:
    service_name: str
    endpoint: str
    healthy: bool = True
    last_check: str = ""
    response_time_ms: float = 0.0
    error: Optional[str] = None
    consecutive_failures: int = 0


@dataclass
class FileIntegrity:
    path: str
    expected_hash: str
    current_hash: str
    match: bool
    last_checked: str


class RuntimeMonitor:
    """Monitors service health and file integrity at runtime."""

    def __init__(self, self_healing_url: str = "http://self-healing:8008"):
        self.self_healing_url = self_healing_url
        self.services: Dict[str, ServiceHealth] = {}
        self.file_watches: Dict[str, str] = {}  # path -> expected hash
        self.check_interval = 30  # seconds
        self._running = False

    def register_service(self, name: str, health_endpoint: str):
        """Register a service to monitor."""
        self.services[name] = ServiceHealth(
            service_name=name,
            endpoint=health_endpoint,
        )
        logger.info("Registered service for monitoring: %s at %s", name, health_endpoint)

    def register_file(self, path: str, expected_hash: Optional[str] = None):
        """Register a file for integrity monitoring."""
        if expected_hash is None:
            expected_hash = self._compute_file_hash(path)
        self.file_watches[path] = expected_hash
        logger.info("Registered file watch: %s (hash=%s...)", path, expected_hash[:16])

    async def start(self):
        """Start the monitoring loop."""
        self._running = True
        logger.info("Runtime monitor started (interval=%ds)", self.check_interval)
        while self._running:
            await self._check_services()
            self._check_files()
            await asyncio.sleep(self.check_interval)

    def stop(self):
        self._running = False

    async def _check_services(self):
        """Health-check all registered services."""
        async with httpx.AsyncClient(timeout=10) as client:
            for name, svc in self.services.items():
                try:
                    start = asyncio.get_event_loop().time()
                    resp = await client.get(svc.endpoint)
                    elapsed = (asyncio.get_event_loop().time() - start) * 1000

                    svc.response_time_ms = elapsed
                    svc.last_check = datetime.now(timezone.utc).isoformat()

                    if resp.status_code == 200:
                        svc.healthy = True
                        svc.consecutive_failures = 0
                        svc.error = None
                    else:
                        svc.healthy = False
                        svc.consecutive_failures += 1
                        svc.error = f"HTTP {resp.status_code}"

                except Exception as e:
                    svc.healthy = False
                    svc.consecutive_failures += 1
                    svc.error = str(e)
                    svc.last_check = datetime.now(timezone.utc).isoformat()

                # Trigger self-healing after 3 consecutive failures
                if svc.consecutive_failures >= 3:
                    await self._trigger_healing(name, f"3 consecutive health check failures: {svc.error}")

    def _check_files(self):
        """Verify file integrity against expected hashes."""
        for path, expected in self.file_watches.items():
            current = self._compute_file_hash(path)
            if current and current != expected:
                logger.warning("FILE INTEGRITY VIOLATION: %s (expected=%s, got=%s)", path, expected[:16], current[:16])
                # In production: trigger Rust self-healing API
                asyncio.ensure_future(self._trigger_healing(
                    f"file:{path}",
                    f"Hash mismatch: expected {expected[:16]}..., got {current[:16]}...",
                ))

    async def _trigger_healing(self, target: str, reason: str):
        """Notify the self-healing service to initiate recovery."""
        logger.warning("Triggering self-healing for %s: %s", target, reason)
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    f"{self.self_healing_url}/self-healing/heal",
                    json={"target": target, "reason": reason},
                )
        except Exception as e:
            logger.error("Failed to trigger self-healing: %s", e)

    @staticmethod
    def _compute_file_hash(path: str) -> Optional[str]:
        """Compute SHA-256 hash of a file."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (FileNotFoundError, PermissionError):
            return None

    def get_status(self) -> Dict:
        """Return current monitoring status."""
        healthy = sum(1 for s in self.services.values() if s.healthy)
        return {
            "total_services": len(self.services),
            "healthy_services": healthy,
            "unhealthy_services": len(self.services) - healthy,
            "watched_files": len(self.file_watches),
            "services": {
                name: {
                    "healthy": svc.healthy,
                    "response_time_ms": svc.response_time_ms,
                    "consecutive_failures": svc.consecutive_failures,
                    "error": svc.error,
                }
                for name, svc in self.services.items()
            },
        }
