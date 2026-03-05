"""
P13 — Retroactive Scanner
Applies newly updated threat intelligence and detection rules to
historical events, finding threats that were unknown at the time
of original analysis.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

logger = logging.getLogger("cybershield.dream_hunter.retroactive")


@dataclass
class ThreatIntelUpdate:
    ioc_type: str          # ip, domain, hash, yara_rule
    ioc_value: str
    source: str            # e.g., "CISA-AA23-347A", "VT", "MISP"
    published_at: str
    severity: str
    tags: List[str] = field(default_factory=list)


@dataclass
class HistoricalEvent:
    event_id: str
    timestamp: str
    source_ip: str
    dest_ip: str
    domain: Optional[str] = None
    file_hash: Optional[str] = None
    url: Optional[str] = None
    raw_log: Optional[str] = None


@dataclass
class RetroactiveMatch:
    event_id: str
    ioc_matched: str
    ioc_type: str
    intel_source: str
    original_timestamp: str
    detection_gap_hours: float   # Time between event and intel publication
    severity: str
    recommendation: str


class RetroactiveScanner:
    """Scans historical events against new threat intelligence."""

    def __init__(self):
        self.intel_db: Dict[str, List[ThreatIntelUpdate]] = {
            "ip": [], "domain": [], "hash": [], "yara_rule": [],
        }
        self.matches: List[RetroactiveMatch] = []
        self.scanned_events: int = 0

    def ingest_intel(self, updates: List[ThreatIntelUpdate]):
        """Ingest new threat intelligence indicators."""
        for update in updates:
            self.intel_db.setdefault(update.ioc_type, []).append(update)
        logger.info("Ingested %d new threat intel indicators", len(updates))

    def scan(self, events: List[HistoricalEvent]) -> List[RetroactiveMatch]:
        """Scan historical events against threat intelligence."""
        matches = []
        ip_set = {i.ioc_value for i in self.intel_db.get("ip", [])}
        domain_set = {i.ioc_value.lower() for i in self.intel_db.get("domain", [])}
        hash_set = {i.ioc_value.lower() for i in self.intel_db.get("hash", [])}

        for event in events:
            self.scanned_events += 1

            # IP matching
            if event.source_ip in ip_set or event.dest_ip in ip_set:
                matched_ip = event.source_ip if event.source_ip in ip_set else event.dest_ip
                intel = self._find_intel("ip", matched_ip)
                if intel:
                    gap = self._compute_gap(event.timestamp, intel.published_at)
                    matches.append(RetroactiveMatch(
                        event_id=event.event_id,
                        ioc_matched=matched_ip,
                        ioc_type="ip",
                        intel_source=intel.source,
                        original_timestamp=event.timestamp,
                        detection_gap_hours=gap,
                        severity=intel.severity,
                        recommendation="Investigate host for compromise indicators",
                    ))

            # Domain matching
            if event.domain and event.domain.lower() in domain_set:
                intel = self._find_intel("domain", event.domain.lower())
                if intel:
                    gap = self._compute_gap(event.timestamp, intel.published_at)
                    matches.append(RetroactiveMatch(
                        event_id=event.event_id,
                        ioc_matched=event.domain,
                        ioc_type="domain",
                        intel_source=intel.source,
                        original_timestamp=event.timestamp,
                        detection_gap_hours=gap,
                        severity=intel.severity,
                        recommendation="Review DNS logs and block domain",
                    ))

            # Hash matching
            if event.file_hash and event.file_hash.lower() in hash_set:
                intel = self._find_intel("hash", event.file_hash.lower())
                if intel:
                    gap = self._compute_gap(event.timestamp, intel.published_at)
                    matches.append(RetroactiveMatch(
                        event_id=event.event_id,
                        ioc_matched=event.file_hash,
                        ioc_type="hash",
                        intel_source=intel.source,
                        original_timestamp=event.timestamp,
                        detection_gap_hours=gap,
                        severity=intel.severity,
                        recommendation="Quarantine file and scan affected systems",
                    ))

        self.matches.extend(matches)
        logger.info("Retroactive scan: %d events → %d matches", len(events), len(matches))
        return matches

    def _find_intel(self, ioc_type: str, value: str) -> Optional[ThreatIntelUpdate]:
        for intel in self.intel_db.get(ioc_type, []):
            if intel.ioc_value.lower() == value.lower():
                return intel
        return None

    def _compute_gap(self, event_ts: str, intel_ts: str) -> float:
        """Compute hours between event and intel publication."""
        try:
            evt = datetime.fromisoformat(event_ts.replace("Z", "+00:00"))
            pub = datetime.fromisoformat(intel_ts.replace("Z", "+00:00"))
            return abs((pub - evt).total_seconds()) / 3600
        except (ValueError, AttributeError):
            return 0.0

    def get_statistics(self) -> Dict:
        return {
            "total_scanned": self.scanned_events,
            "total_matches": len(self.matches),
            "by_type": {
                "ip": sum(1 for m in self.matches if m.ioc_type == "ip"),
                "domain": sum(1 for m in self.matches if m.ioc_type == "domain"),
                "hash": sum(1 for m in self.matches if m.ioc_type == "hash"),
            },
            "avg_detection_gap_hours": (
                sum(m.detection_gap_hours for m in self.matches) / len(self.matches)
                if self.matches else 0
            ),
        }
