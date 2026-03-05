"""
P13 — Dream-State Night Processor
Off-peak hours deep analysis engine that replays and re-analyzes
the day's security events with more computationally expensive models,
searching for threats that real-time detection may have missed.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("cybershield.dream_hunter.night_processor")


@dataclass
class DreamSession:
    session_id: str
    started_at: str
    completed_at: Optional[str] = None
    events_replayed: int = 0
    threats_found: int = 0
    weak_signals_amplified: int = 0
    retroactive_matches: int = 0
    status: str = "running"  # running, completed, failed


@dataclass
class ReplayEvent:
    event_id: str
    original_timestamp: str
    event_type: str
    source_ip: str
    dest_ip: str
    severity: str
    original_verdict: str   # clean, suspicious, malicious
    features: Dict = field(default_factory=dict)


@dataclass
class DreamFinding:
    finding_id: str
    event_ids: List[str]
    finding_type: str       # missed_threat, weak_signal, pattern_correlation
    description: str
    confidence: float
    severity: str
    evidence: Dict = field(default_factory=dict)
    recommended_action: str = ""


class NightProcessor:
    """Processes the day's events during off-peak hours with deep analysis."""

    def __init__(self, reanalysis_threshold: float = 0.3):
        self.reanalysis_threshold = reanalysis_threshold
        self.sessions: List[DreamSession] = []
        self.findings: List[DreamFinding] = []

    def start_dream_session(self, events: List[ReplayEvent]) -> DreamSession:
        """Begin a dream-state analysis session."""
        session = DreamSession(
            session_id=f"dream-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self.sessions.append(session)
        logger.info("Dream session %s started with %d events", session.session_id, len(events))

        findings = []

        # Phase 1: Re-score all events with ensemble models
        rescored = self._rescore_events(events)
        for event, new_score in rescored:
            if event.original_verdict == "clean" and new_score >= 0.6:
                finding = DreamFinding(
                    finding_id=f"dream-missed-{event.event_id}",
                    event_ids=[event.event_id],
                    finding_type="missed_threat",
                    description=f"Event {event.event_id} was classified clean but deep analysis scores {new_score:.2f}",
                    confidence=new_score,
                    severity="high" if new_score > 0.8 else "medium",
                    evidence={"original_verdict": event.original_verdict, "dream_score": new_score},
                    recommended_action="re-investigate and update detection rules",
                )
                findings.append(finding)
                session.threats_found += 1

        # Phase 2: Temporal pattern correlation
        temporal_findings = self._correlate_temporal_patterns(events)
        findings.extend(temporal_findings)

        # Phase 3: Statistical anomaly detection on aggregates
        anomaly_findings = self._detect_aggregate_anomalies(events)
        findings.extend(anomaly_findings)

        session.events_replayed = len(events)
        session.weak_signals_amplified = sum(1 for f in findings if f.finding_type == "weak_signal")
        session.retroactive_matches = sum(1 for f in findings if f.finding_type == "pattern_correlation")
        session.completed_at = datetime.now(timezone.utc).isoformat()
        session.status = "completed"

        self.findings.extend(findings)
        logger.info(
            "Dream session %s complete: %d threats, %d weak signals, %d patterns",
            session.session_id, session.threats_found,
            session.weak_signals_amplified, session.retroactive_matches,
        )
        return session

    def _rescore_events(self, events: List[ReplayEvent]) -> List[tuple]:
        """Re-score events with computationally expensive analysis."""
        rescored = []
        for event in events:
            # Simulate deep model scoring (in production: run full GAT + UEBA ensemble)
            features = event.features
            base_score = features.get("original_score", 0.0)

            # Deep analysis heuristics
            bonus = 0.0
            if features.get("unusual_port", False):
                bonus += 0.15
            if features.get("off_hours", False):
                bonus += 0.1
            if features.get("new_destination", False):
                bonus += 0.12
            if features.get("encoded_payload", False):
                bonus += 0.2
            if features.get("dns_tunnel_indicators", 0) > 0:
                bonus += 0.25

            new_score = min(base_score + bonus, 1.0)
            if new_score >= self.reanalysis_threshold:
                rescored.append((event, new_score))

        return rescored

    def _correlate_temporal_patterns(self, events: List[ReplayEvent]) -> List[DreamFinding]:
        """Find temporal correlations between events that individually seem harmless."""
        findings = []
        # Group events by source IP
        ip_events: Dict[str, List[ReplayEvent]] = {}
        for e in events:
            ip_events.setdefault(e.source_ip, []).append(e)

        for ip, ip_evts in ip_events.items():
            if len(ip_evts) < 3:
                continue

            # Detect slow-and-low patterns: many events spread over time
            event_types = [e.event_type for e in ip_evts]
            unique_types = set(event_types)

            # If an IP touches many different event types → possible kill chain
            if len(unique_types) >= 4:
                findings.append(DreamFinding(
                    finding_id=f"dream-pattern-{ip}",
                    event_ids=[e.event_id for e in ip_evts],
                    finding_type="pattern_correlation",
                    description=f"IP {ip} shows multi-stage activity across {len(unique_types)} event types",
                    confidence=min(len(unique_types) / 7.0, 0.95),
                    severity="high",
                    evidence={"event_types": list(unique_types), "event_count": len(ip_evts)},
                    recommended_action="investigate as potential kill chain progression",
                ))

        return findings

    def _detect_aggregate_anomalies(self, events: List[ReplayEvent]) -> List[DreamFinding]:
        """Statistical anomaly detection on aggregate event properties."""
        findings = []
        if len(events) < 10:
            return findings

        # Analyze event volume per hour
        hour_counts: Dict[int, int] = {}
        for e in events:
            try:
                ts = datetime.fromisoformat(e.original_timestamp.replace("Z", "+00:00"))
                hour_counts[ts.hour] = hour_counts.get(ts.hour, 0) + 1
            except (ValueError, AttributeError):
                pass

        if hour_counts:
            counts = list(hour_counts.values())
            mean_c = np.mean(counts)
            std_c = np.std(counts) + 1e-6

            for hour, count in hour_counts.items():
                z_score = (count - mean_c) / std_c
                if z_score > 2.5:  # Significant spike
                    findings.append(DreamFinding(
                        finding_id=f"dream-spike-hour{hour}",
                        event_ids=[],
                        finding_type="weak_signal",
                        description=f"Anomalous event spike at hour {hour}: {count} events (z={z_score:.1f})",
                        confidence=min(z_score / 5.0, 0.9),
                        severity="medium",
                        evidence={"hour": hour, "count": count, "z_score": float(z_score)},
                        recommended_action="review events during this time window",
                    ))

        return findings

    def get_findings(self, min_confidence: float = 0.0) -> List[DreamFinding]:
        """Retrieve dream findings above a confidence threshold."""
        return [f for f in self.findings if f.confidence >= min_confidence]
