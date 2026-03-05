"""
P08 — Psychographic Attack Prediction Engine (PAPE)
Predicts which individuals will be targeted before the attack happens
by analyzing behavioral patterns, social media exposure, organizational
role, and historical attack vectors.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("cybershield.antiphishing.pape")


class RiskTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class UserProfile:
    """Aggregated user profile for psychographic analysis."""
    user_id: str
    display_name: str
    department: str = ""
    role: str = ""
    seniority_level: int = 0          # 0-10 scale
    financial_authority: bool = False
    public_exposure_score: float = 0.0  # 0-1: social media, conferences, press
    email_open_rate: float = 0.5
    phishing_sim_fail_rate: float = 0.0
    past_incidents: int = 0
    access_level: int = 0              # 0-5 privilege levels
    travel_frequency: float = 0.0      # trips per month
    work_hours_variance: float = 0.0   # irregular schedule indicator
    social_connections: int = 0        # internal network size


@dataclass
class PredictionResult:
    user_id: str
    risk_tier: RiskTier
    risk_score: float
    attack_vectors: List[str]
    contributing_factors: List[str]
    recommended_interventions: List[str]
    predicted_at: str = ""

    def __post_init__(self):
        if not self.predicted_at:
            self.predicted_at = datetime.now(timezone.utc).isoformat()


# ── Feature weights (tunable by SOC teams) ─────

FEATURE_WEIGHTS = {
    "seniority_level": 0.12,
    "financial_authority": 0.15,
    "public_exposure_score": 0.13,
    "phishing_sim_fail_rate": 0.18,
    "past_incidents": 0.10,
    "access_level": 0.12,
    "travel_frequency": 0.05,
    "work_hours_variance": 0.05,
    "social_connections": 0.05,
    "email_open_rate": 0.05,
}


class PsychographicPredictor:
    """Predicts attack targeting likelihood per user."""

    def __init__(self, org_avg_fail_rate: float = 0.15):
        self.org_avg_fail_rate = org_avg_fail_rate
        self.attack_vector_map = self._build_attack_vector_map()

    def predict(self, profile: UserProfile) -> PredictionResult:
        """Score a user and predict most likely attack vectors."""
        features = self._extract_features(profile)
        risk_score = self._compute_risk_score(features)
        vectors = self._predict_attack_vectors(profile, features)
        factors = self._identify_contributing_factors(features)
        interventions = self._recommend_interventions(profile, vectors, risk_score)
        tier = self._classify_tier(risk_score)

        return PredictionResult(
            user_id=profile.user_id,
            risk_tier=tier,
            risk_score=round(risk_score, 4),
            attack_vectors=vectors,
            contributing_factors=factors,
            recommended_interventions=interventions,
        )

    def predict_batch(self, profiles: List[UserProfile]) -> List[PredictionResult]:
        """Batch prediction with organization-wide context."""
        results = [self.predict(p) for p in profiles]
        results.sort(key=lambda r: r.risk_score, reverse=True)
        return results

    # ── Internal scoring ────────────────────────

    def _extract_features(self, p: UserProfile) -> Dict[str, float]:
        return {
            "seniority_level": p.seniority_level / 10.0,
            "financial_authority": 1.0 if p.financial_authority else 0.0,
            "public_exposure_score": p.public_exposure_score,
            "phishing_sim_fail_rate": p.phishing_sim_fail_rate,
            "past_incidents": min(p.past_incidents / 5.0, 1.0),
            "access_level": p.access_level / 5.0,
            "travel_frequency": min(p.travel_frequency / 10.0, 1.0),
            "work_hours_variance": min(p.work_hours_variance, 1.0),
            "social_connections": min(p.social_connections / 500.0, 1.0),
            "email_open_rate": p.email_open_rate,
        }

    def _compute_risk_score(self, features: Dict[str, float]) -> float:
        score = sum(features[k] * FEATURE_WEIGHTS[k] for k in FEATURE_WEIGHTS)
        return float(np.clip(score, 0.0, 1.0))

    def _classify_tier(self, score: float) -> RiskTier:
        if score >= 0.8:
            return RiskTier.CRITICAL
        if score >= 0.6:
            return RiskTier.HIGH
        if score >= 0.35:
            return RiskTier.MEDIUM
        return RiskTier.LOW

    def _predict_attack_vectors(self, p: UserProfile, feats: Dict[str, float]) -> List[str]:
        vectors = []
        if p.financial_authority:
            vectors.append("business_email_compromise")
        if feats["public_exposure_score"] > 0.6:
            vectors.append("spear_phishing_via_osint")
        if feats["phishing_sim_fail_rate"] > self.org_avg_fail_rate:
            vectors.append("credential_harvesting")
        if feats["access_level"] > 0.6:
            vectors.append("privilege_escalation_social_engineering")
        if feats["travel_frequency"] > 0.3:
            vectors.append("evil_twin_wifi_attack")
        if p.seniority_level >= 7:
            vectors.append("whaling_attack")
        if not vectors:
            vectors.append("generic_phishing")
        return vectors

    def _identify_contributing_factors(self, feats: Dict[str, float]) -> List[str]:
        sorted_feats = sorted(feats.items(), key=lambda x: x[1] * FEATURE_WEIGHTS.get(x[0], 0), reverse=True)
        return [f"{name}={val:.2f}" for name, val in sorted_feats[:5]]

    def _recommend_interventions(
        self, p: UserProfile, vectors: List[str], score: float
    ) -> List[str]:
        interventions = []
        if score >= 0.6:
            interventions.append("mandatory_security_awareness_training")
            interventions.append("enable_hardware_mfa_token")
        if "business_email_compromise" in vectors:
            interventions.append("dual_approval_for_financial_transactions")
        if "credential_harvesting" in vectors:
            interventions.append("phishing_simulation_enrollment")
        if p.public_exposure_score > 0.5:
            interventions.append("social_media_exposure_review")
        if "evil_twin_wifi_attack" in vectors:
            interventions.append("vpn_always_on_policy")
        if score >= 0.8:
            interventions.append("dedicated_soc_monitoring")
        return interventions

    def _build_attack_vector_map(self) -> Dict[str, Dict]:
        return {
            "business_email_compromise": {
                "description": "Attacker impersonates executive to authorize financial transfers",
                "mitre": "T1566.001",
            },
            "spear_phishing_via_osint": {
                "description": "Targeted phishing using publicly gathered intelligence",
                "mitre": "T1598.003",
            },
            "credential_harvesting": {
                "description": "Fake login pages to steal credentials",
                "mitre": "T1556",
            },
            "whaling_attack": {
                "description": "High-value executive targeted phishing",
                "mitre": "T1566.002",
            },
        }
