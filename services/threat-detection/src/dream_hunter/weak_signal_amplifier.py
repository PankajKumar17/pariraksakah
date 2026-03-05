"""
P13 — Weak Signal Amplifier
Amplifies individually insignificant signals that, when combined,
reveal coordinated or stealthy attacks. Uses statistical methods
to surface buried threat indicators.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("cybershield.dream_hunter.weak_signal")


@dataclass
class WeakSignal:
    signal_id: str
    event_id: str
    signal_type: str       # dns_noise, low_volume_scan, timing_anomaly, etc.
    source_ip: str
    value: float           # Individual signal strength (0-1, typically <0.3)
    context: Dict = field(default_factory=dict)


@dataclass
class AmplifiedSignal:
    signal_ids: List[str]
    source_ips: List[str]
    combined_score: float
    pattern: str
    description: str
    event_count: int
    confidence: float
    severity: str


class WeakSignalAmplifier:
    """Combines weak signals to detect stealthy threats."""

    def __init__(
        self,
        correlation_window: int = 100,
        amplification_threshold: float = 0.6,
        min_signals: int = 3,
    ):
        self.correlation_window = correlation_window
        self.amplification_threshold = amplification_threshold
        self.min_signals = min_signals
        self.signal_buffer: List[WeakSignal] = []
        self.amplified: List[AmplifiedSignal] = []

    def ingest(self, signal: WeakSignal):
        """Add a weak signal to the processing buffer."""
        self.signal_buffer.append(signal)
        if len(self.signal_buffer) > self.correlation_window * 10:
            self.signal_buffer = self.signal_buffer[-self.correlation_window * 5:]

    def ingest_batch(self, signals: List[WeakSignal]):
        for s in signals:
            self.ingest(s)

    def amplify(self) -> List[AmplifiedSignal]:
        """Analyze buffered signals for amplifiable patterns."""
        if len(self.signal_buffer) < self.min_signals:
            return []

        results = []

        # Strategy 1: Cluster by source IP
        ip_clusters = self._cluster_by_ip()
        for ip, signals in ip_clusters.items():
            if len(signals) >= self.min_signals:
                amp = self._amplify_cluster(signals, f"ip_cluster:{ip}")
                if amp and amp.combined_score >= self.amplification_threshold:
                    results.append(amp)

        # Strategy 2: Temporal burst detection
        temporal = self._detect_temporal_bursts()
        results.extend(temporal)

        # Strategy 3: Cross-IP correlation (distributed attacks)
        distributed = self._detect_distributed_patterns()
        results.extend(distributed)

        self.amplified.extend(results)
        return results

    def _cluster_by_ip(self) -> Dict[str, List[WeakSignal]]:
        """Group signals by source IP for per-source amplification."""
        clusters: Dict[str, List[WeakSignal]] = defaultdict(list)
        for sig in self.signal_buffer[-self.correlation_window:]:
            clusters[sig.source_ip].append(sig)
        return dict(clusters)

    def _amplify_cluster(self, signals: List[WeakSignal], pattern: str) -> Optional[AmplifiedSignal]:
        """Combine weak signals from the same source using weighted aggregation."""
        if not signals:
            return None

        # Diversity bonus: more unique signal types = more suspicious
        unique_types = set(s.signal_type for s in signals)
        diversity_factor = len(unique_types) / max(len(signals), 1)

        # Sum of individual values with diminishing returns
        values = sorted([s.value for s in signals], reverse=True)
        combined = 0.0
        for i, v in enumerate(values):
            combined += v * (0.8 ** i)  # Diminishing contribution

        # Normalize and apply diversity bonus
        combined = min(combined * (1 + diversity_factor), 1.0)

        confidence = min(len(signals) / 10.0, 0.95)  # More signals = more confident

        severity = "low"
        if combined >= 0.8:
            severity = "high"
        elif combined >= 0.5:
            severity = "medium"

        return AmplifiedSignal(
            signal_ids=[s.signal_id for s in signals],
            source_ips=list(set(s.source_ip for s in signals)),
            combined_score=float(combined),
            pattern=pattern,
            description=f"Amplified {len(signals)} weak signals ({len(unique_types)} types) → score {combined:.2f}",
            event_count=len(signals),
            confidence=float(confidence),
            severity=severity,
        )

    def _detect_temporal_bursts(self) -> List[AmplifiedSignal]:
        """Find bursts of weak signals in short time windows."""
        results = []
        window = self.signal_buffer[-self.correlation_window:]
        if len(window) < self.min_signals:
            return results

        # Sliding window of 10 signals
        stride = 5
        for i in range(0, len(window) - 10, stride):
            chunk = window[i:i + 10]
            total_value = sum(s.value for s in chunk)
            if total_value >= self.amplification_threshold * 3:
                amp = self._amplify_cluster(chunk, "temporal_burst")
                if amp:
                    results.append(amp)
                    break  # One burst per cycle

        return results

    def _detect_distributed_patterns(self) -> List[AmplifiedSignal]:
        """Detect coordinated weak signals from multiple sources targeting same dest."""
        results = []
        # Group by signal type
        type_groups: Dict[str, List[WeakSignal]] = defaultdict(list)
        for sig in self.signal_buffer[-self.correlation_window:]:
            type_groups[sig.signal_type].append(sig)

        for sig_type, signals in type_groups.items():
            unique_ips = set(s.source_ip for s in signals)
            if len(unique_ips) >= 3 and len(signals) >= self.min_signals:
                amp = self._amplify_cluster(signals, f"distributed:{sig_type}")
                if amp and amp.combined_score >= self.amplification_threshold:
                    amp.description = (
                        f"Distributed {sig_type} from {len(unique_ips)} unique IPs — "
                        f"possible coordinated attack"
                    )
                    results.append(amp)

        return results

    def get_statistics(self) -> Dict:
        return {
            "buffer_size": len(self.signal_buffer),
            "amplified_count": len(self.amplified),
            "avg_combined_score": (
                float(np.mean([a.combined_score for a in self.amplified]))
                if self.amplified else 0.0
            ),
        }
