"""
P12 — Cognitive Firewall Controller
Intent-aware firewall that uses Theory of Mind predictions to
proactively block traffic based on predicted attacker behavior,
not just observed patterns.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set

from .theory_of_mind import AttackerHMM, IntentPrediction

logger = logging.getLogger("cybershield.cognitive.firewall")


class FirewallAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    THROTTLE = "throttle"
    REDIRECT_TO_HONEYPOT = "redirect_honeypot"
    DEEP_INSPECT = "deep_inspect"
    ALERT = "alert"


@dataclass
class FirewallRule:
    rule_id: str
    source_ip: str
    action: FirewallAction
    reason: str
    confidence: float
    predicted_state: str
    created_at: str = ""
    expires_at: Optional[str] = None
    auto_generated: bool = True

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class TrafficEvent:
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    event_type: str        # Maps to HMM observation
    payload_size: int = 0
    timestamp: str = ""


@dataclass
class FirewallStats:
    total_events: int = 0
    blocked: int = 0
    allowed: int = 0
    throttled: int = 0
    redirected: int = 0
    active_rules: int = 0
    active_threats: int = 0


class CognitiveFirewall:
    """Intent-aware firewall controller using Theory of Mind HMM."""

    def __init__(self, urgency_threshold: float = 0.4, block_threshold: float = 0.7):
        self.hmm = AttackerHMM()
        self.urgency_threshold = urgency_threshold
        self.block_threshold = block_threshold

        # Track observation sequences per source IP
        self.ip_sequences: Dict[str, List[str]] = {}
        self.ip_predictions: Dict[str, IntentPrediction] = {}
        self.active_rules: Dict[str, FirewallRule] = {}
        self.blocked_ips: Set[str] = set()
        self.stats = FirewallStats()

    async def process_event(self, event: TrafficEvent) -> FirewallAction:
        """Process a traffic event through the cognitive firewall."""
        self.stats.total_events += 1

        # Check existing block rules
        if event.source_ip in self.blocked_ips:
            self.stats.blocked += 1
            return FirewallAction.BLOCK

        # Update observation sequence for this IP
        if event.source_ip not in self.ip_sequences:
            self.ip_sequences[event.source_ip] = []
        self.ip_sequences[event.source_ip].append(event.event_type)

        # Trim sequence to last 50 events
        if len(self.ip_sequences[event.source_ip]) > 50:
            self.ip_sequences[event.source_ip] = self.ip_sequences[event.source_ip][-50:]

        # Run intent prediction
        seq = self.ip_sequences[event.source_ip]
        if len(seq) >= 2:
            prediction = self.hmm.predict_intent(seq)
            self.ip_predictions[event.source_ip] = prediction
            action = self._decide_action(event.source_ip, prediction)
        else:
            action = FirewallAction.ALLOW

        # Update stats
        if action == FirewallAction.BLOCK:
            self.stats.blocked += 1
        elif action == FirewallAction.THROTTLE:
            self.stats.throttled += 1
        elif action == FirewallAction.REDIRECT_TO_HONEYPOT:
            self.stats.redirected += 1
        else:
            self.stats.allowed += 1

        return action

    def _decide_action(self, source_ip: str, prediction: IntentPrediction) -> FirewallAction:
        """Decide firewall action based on intent prediction."""
        # Late kill chain stages with high confidence → block
        if prediction.urgency_score >= self.block_threshold and prediction.confidence >= 0.6:
            rule = FirewallRule(
                rule_id=f"auto-block-{source_ip}",
                source_ip=source_ip,
                action=FirewallAction.BLOCK,
                reason=f"Predicted state: {prediction.current_state} (urgency={prediction.urgency_score:.2f})",
                confidence=prediction.confidence,
                predicted_state=prediction.current_state,
            )
            self.active_rules[rule.rule_id] = rule
            self.blocked_ips.add(source_ip)
            self.stats.active_rules = len(self.active_rules)
            logger.warning(
                "BLOCKING %s — predicted state: %s, urgency: %.2f, next: %s",
                source_ip, prediction.current_state,
                prediction.urgency_score, prediction.predicted_next_state,
            )
            return FirewallAction.BLOCK

        # Mid-stage reconnaissance → redirect to honeypot
        if prediction.current_state in ("reconnaissance", "delivery") and prediction.urgency_score >= self.urgency_threshold:
            logger.info("Redirecting %s to honeypot (state=%s)", source_ip, prediction.current_state)
            return FirewallAction.REDIRECT_TO_HONEYPOT

        # Early stage with some signals → throttle and inspect
        if prediction.urgency_score >= 0.2:
            return FirewallAction.DEEP_INSPECT

        return FirewallAction.ALLOW

    def get_threat_summary(self) -> List[Dict]:
        """Return summary of current threat predictions per IP."""
        summary = []
        for ip, pred in self.ip_predictions.items():
            summary.append({
                "source_ip": ip,
                "current_state": pred.current_state,
                "predicted_next": pred.predicted_next_state,
                "urgency": pred.urgency_score,
                "confidence": pred.confidence,
                "sequence_length": len(self.ip_sequences.get(ip, [])),
                "is_blocked": ip in self.blocked_ips,
            })
        summary.sort(key=lambda x: x["urgency"], reverse=True)
        return summary

    def unblock_ip(self, ip: str):
        """Manually unblock an IP address."""
        self.blocked_ips.discard(ip)
        rule_id = f"auto-block-{ip}"
        self.active_rules.pop(rule_id, None)
        self.stats.active_rules = len(self.active_rules)
        logger.info("Unblocked IP: %s", ip)

    def get_stats(self) -> FirewallStats:
        self.stats.active_rules = len(self.active_rules)
        self.stats.active_threats = len(self.ip_predictions)
        return self.stats
