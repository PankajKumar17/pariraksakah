"""
P10 — Keystroke Dynamics Analyzer
Continuous authentication via typing rhythm analysis.
Extracts dwell time, flight time, and n-graph features to build
a per-user typing profile for identity verification.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("cybershield.bioauth.keystroke")


@dataclass
class KeyEvent:
    key: str
    press_time: float    # timestamp in seconds
    release_time: float  # timestamp in seconds


@dataclass
class KeystrokeProfile:
    user_id: str
    dwell_means: Dict[str, float] = field(default_factory=dict)
    dwell_stds: Dict[str, float] = field(default_factory=dict)
    flight_means: Dict[str, float] = field(default_factory=dict)
    flight_stds: Dict[str, float] = field(default_factory=dict)
    digraph_means: Dict[str, float] = field(default_factory=dict)
    typing_speed_wpm: float = 0.0
    sample_count: int = 0


@dataclass
class AuthResult:
    user_id: str
    is_authentic: bool
    confidence: float
    anomaly_score: float
    features_compared: int


class KeystrokeDynamics:
    """Behavioral biometric authentication via keystroke timing analysis."""

    def __init__(self, threshold: float = 0.65):
        self.threshold = threshold
        self.profiles: Dict[str, KeystrokeProfile] = {}

    def enroll(self, user_id: str, sessions: List[List[KeyEvent]]) -> KeystrokeProfile:
        """Build a typing profile from multiple enrollment sessions."""
        all_dwells: Dict[str, List[float]] = {}
        all_flights: Dict[str, List[float]] = {}
        all_digraphs: Dict[str, List[float]] = {}
        total_chars = 0
        total_time = 0.0

        for events in sessions:
            if len(events) < 2:
                continue

            total_chars += len(events)
            total_time += events[-1].release_time - events[0].press_time

            for evt in events:
                dwell = evt.release_time - evt.press_time
                key = evt.key.lower()
                all_dwells.setdefault(key, []).append(dwell)

            for i in range(1, len(events)):
                flight = events[i].press_time - events[i - 1].release_time
                pair = events[i - 1].key.lower() + events[i].key.lower()
                all_flights.setdefault(pair, []).append(flight)
                all_digraphs.setdefault(pair, []).append(
                    events[i].press_time - events[i - 1].press_time
                )

        profile = KeystrokeProfile(
            user_id=user_id,
            sample_count=len(sessions),
        )

        for k, vals in all_dwells.items():
            profile.dwell_means[k] = float(np.mean(vals))
            profile.dwell_stds[k] = float(np.std(vals)) + 1e-6

        for k, vals in all_flights.items():
            profile.flight_means[k] = float(np.mean(vals))
            profile.flight_stds[k] = float(np.std(vals)) + 1e-6

        for k, vals in all_digraphs.items():
            profile.digraph_means[k] = float(np.mean(vals))

        if total_time > 0:
            profile.typing_speed_wpm = (total_chars / 5) / (total_time / 60)

        self.profiles[user_id] = profile
        logger.info("Enrolled user %s with %d sessions", user_id, len(sessions))
        return profile

    def authenticate(self, user_id: str, events: List[KeyEvent]) -> AuthResult:
        """Verify identity by comparing typing rhythm against stored profile."""
        profile = self.profiles.get(user_id)
        if not profile:
            return AuthResult(user_id=user_id, is_authentic=False, confidence=0.0,
                              anomaly_score=1.0, features_compared=0)

        scores: List[float] = []

        # Compare dwell times
        for evt in events:
            key = evt.key.lower()
            if key in profile.dwell_means:
                dwell = evt.release_time - evt.press_time
                z = abs(dwell - profile.dwell_means[key]) / profile.dwell_stds[key]
                scores.append(max(0, 1 - z / 3))  # z-score normalized to [0,1]

        # Compare flight times
        for i in range(1, len(events)):
            pair = events[i - 1].key.lower() + events[i].key.lower()
            if pair in profile.flight_means:
                flight = events[i].press_time - events[i - 1].release_time
                z = abs(flight - profile.flight_means[pair]) / profile.flight_stds[pair]
                scores.append(max(0, 1 - z / 3))

        if not scores:
            return AuthResult(user_id=user_id, is_authentic=False, confidence=0.0,
                              anomaly_score=1.0, features_compared=0)

        similarity = float(np.mean(scores))
        anomaly = 1.0 - similarity
        is_auth = similarity >= self.threshold

        return AuthResult(
            user_id=user_id,
            is_authentic=is_auth,
            confidence=similarity,
            anomaly_score=anomaly,
            features_compared=len(scores),
        )
