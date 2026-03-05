"""
CyberShield-X — Attack Chain Builder
Groups related alerts into attack campaigns using Neo4j graph queries,
identifies kill-chain stages, and computes campaign risk scores.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cybershield.alerting.attack_chain_builder")

# ──────────────────────────────────────────────
# Kill Chain stages (Lockheed Martin + extensions)
# ──────────────────────────────────────────────

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponisation",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]

STAGE_WEIGHTS = {
    "Reconnaissance": 0.05,
    "Weaponisation": 0.10,
    "Delivery": 0.20,
    "Exploitation": 0.35,
    "Installation": 0.45,
    "Command & Control": 0.70,
    "Actions on Objectives": 1.00,
}

# Map ATT&CK tactics to kill-chain stages
TACTIC_TO_STAGE: Dict[str, str] = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Weaponisation",
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Persistence": "Installation",
    "Privilege Escalation": "Exploitation",
    "Defense Evasion": "Installation",
    "Credential Access": "Exploitation",
    "Discovery": "Reconnaissance",
    "Lateral Movement": "Command & Control",
    "Collection": "Actions on Objectives",
    "Command and Control": "Command & Control",
    "Exfiltration": "Actions on Objectives",
    "Impact": "Actions on Objectives",
}

ATTACK_TYPE_TO_STAGE: Dict[str, str] = {
    "PortScan": "Reconnaissance",
    "Phishing": "Delivery",
    "SPEAR_PHISHING": "Delivery",
    "BEC": "Delivery",
    "WebAttack": "Exploitation",
    "BruteForce": "Exploitation",
    "Infiltration": "Installation",
    "Botnet": "Command & Control",
    "C2": "Command & Control",
    "Ransomware": "Actions on Objectives",
    "Exfiltration": "Actions on Objectives",
    "DDoS": "Actions on Objectives",
    "LateralMovement": "Command & Control",
}


# ──────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────

@dataclass
class AttackChainAlert:
    """Alert within an attack campaign."""

    alert_id: str
    timestamp: str
    source_ip: str
    destination_ip: Optional[str]
    attack_type: str
    threat_score: float
    kill_chain_stage: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None


@dataclass
class AttackCampaign:
    """A correlated attack campaign grouping related alerts."""

    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    alerts: List[AttackChainAlert] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    target_ips: List[str] = field(default_factory=list)
    stages_reached: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    status: str = "ACTIVE"  # ACTIVE | CONTAINED | RESOLVED

    def add_alert(self, alert: AttackChainAlert) -> None:
        self.alerts.append(alert)
        if alert.source_ip not in self.source_ips:
            self.source_ips.append(alert.source_ip)
        if alert.destination_ip and alert.destination_ip not in self.target_ips:
            self.target_ips.append(alert.destination_ip)
        if alert.kill_chain_stage not in self.stages_reached:
            self.stages_reached.append(alert.kill_chain_stage)
        self._recalculate_risk()

    def _recalculate_risk(self) -> None:
        """Risk score = max stage weight × alert density factor."""
        if not self.stages_reached:
            self.risk_score = 0.0
            return
        max_stage_weight = max(
            STAGE_WEIGHTS.get(s, 0.0) for s in self.stages_reached
        )
        # Density: more alerts = higher confidence
        density_factor = min(1.0, len(self.alerts) / 10.0)
        # Stage progression bonus
        progression = len(self.stages_reached) / len(KILL_CHAIN_STAGES)
        self.risk_score = round(
            max_stage_weight * 0.5 + progression * 0.3 + density_factor * 0.2,
            4,
        )


# ──────────────────────────────────────────────
# Neo4j Attack Chain Queries
# ──────────────────────────────────────────────

class Neo4jCampaignStore:
    """Manages attack-campaign graph in Neo4j.

    Nodes: Alert, IP, Campaign
    Edges: PART_OF, TARGETED, ORIGINATED_FROM
    """

    CREATE_ALERT_QUERY = """
        MERGE (a:Alert {alert_id: $alert_id})
        SET a.timestamp = $timestamp,
            a.attack_type = $attack_type,
            a.threat_score = $threat_score,
            a.kill_chain_stage = $stage
        MERGE (src:IP {address: $source_ip})
        MERGE (a)-[:ORIGINATED_FROM]->(src)
        WITH a
        WHERE $dest_ip IS NOT NULL
        MERGE (dst:IP {address: $dest_ip})
        MERGE (a)-[:TARGETED]->(dst)
    """

    LINK_CAMPAIGN_QUERY = """
        MATCH (a:Alert {alert_id: $alert_id})
        MERGE (c:Campaign {campaign_id: $campaign_id})
        SET c.risk_score = $risk_score, c.status = $status
        MERGE (a)-[:PART_OF]->(c)
    """

    FIND_RELATED_ALERTS_QUERY = """
        MATCH (a:Alert)-[:ORIGINATED_FROM]->(ip:IP)<-[:ORIGINATED_FROM]-(related:Alert)
        WHERE ip.address = $source_ip
          AND related.timestamp > $since
          AND a.alert_id <> related.alert_id
        RETURN DISTINCT related.alert_id AS alert_id,
               related.attack_type AS attack_type,
               related.kill_chain_stage AS stage,
               related.threat_score AS threat_score,
               related.timestamp AS timestamp
        ORDER BY related.timestamp
    """

    FIND_CAMPAIGN_QUERY = """
        MATCH (a:Alert)-[:ORIGINATED_FROM]->(ip:IP {address: $source_ip}),
              (a)-[:PART_OF]->(c:Campaign)
        WHERE c.status = 'ACTIVE'
        RETURN c.campaign_id AS campaign_id
        LIMIT 1
    """

    def __init__(self, driver: Any) -> None:
        self._driver = driver

    async def store_alert(self, alert: AttackChainAlert) -> None:
        """Store an alert node + IP relationships in Neo4j."""
        async with self._driver.session() as session:
            await session.run(
                self.CREATE_ALERT_QUERY,
                alert_id=alert.alert_id,
                timestamp=alert.timestamp,
                attack_type=alert.attack_type,
                threat_score=alert.threat_score,
                stage=alert.kill_chain_stage,
                source_ip=alert.source_ip,
                dest_ip=alert.destination_ip,
            )

    async def find_active_campaign(self, source_ip: str) -> Optional[str]:
        """Find an active campaign associated with a source IP."""
        async with self._driver.session() as session:
            result = await session.run(
                self.FIND_CAMPAIGN_QUERY, source_ip=source_ip
            )
            record = await result.single()
            return record["campaign_id"] if record else None

    async def link_to_campaign(
        self, alert_id: str, campaign: AttackCampaign
    ) -> None:
        """Link an alert to a campaign in Neo4j."""
        async with self._driver.session() as session:
            await session.run(
                self.LINK_CAMPAIGN_QUERY,
                alert_id=alert_id,
                campaign_id=campaign.campaign_id,
                risk_score=campaign.risk_score,
                status=campaign.status,
            )


# ──────────────────────────────────────────────
# Attack Chain Builder
# ──────────────────────────────────────────────

class AttackChainBuilder:
    """Correlates alerts into attack campaigns.

    Parameters
    ----------
    neo4j_store : Neo4jCampaignStore, optional
        If provided, campaigns are persisted to Neo4j.
    correlation_window_h : int
        Hours to look back for correlated alerts (default 24).
    """

    def __init__(
        self,
        neo4j_store: Optional[Neo4jCampaignStore] = None,
        correlation_window_h: int = 24,
    ) -> None:
        self._neo4j = neo4j_store
        self._window = timedelta(hours=correlation_window_h)
        # In-memory campaign index: campaign_id → AttackCampaign
        self._campaigns: Dict[str, AttackCampaign] = {}
        # source_ip → campaign_id (for quick lookup)
        self._ip_campaign: Dict[str, str] = {}

    def classify_stage(
        self,
        attack_type: str,
        mitre_tactic: Optional[str] = None,
    ) -> str:
        """Determine kill-chain stage for an alert.

        Tries MITRE tactic mapping first, then attack-type mapping,
        then defaults to 'Exploitation'.
        """
        if mitre_tactic:
            stage = TACTIC_TO_STAGE.get(mitre_tactic)
            if stage:
                return stage
        return ATTACK_TYPE_TO_STAGE.get(attack_type, "Exploitation")

    async def process_alert(self, alert_data: Dict[str, Any]) -> AttackCampaign:
        """Add an alert to an existing or new campaign.

        Parameters
        ----------
        alert_data : dict
            Must contain: alert_id, source_ip, attack_type, threat_score.

        Returns
        -------
        AttackCampaign
        """
        stage = self.classify_stage(
            alert_data.get("attack_type", ""),
            alert_data.get("mitre_tactic"),
        )

        chain_alert = AttackChainAlert(
            alert_id=alert_data["alert_id"],
            timestamp=alert_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            source_ip=alert_data["source_ip"],
            destination_ip=alert_data.get("destination_ip"),
            attack_type=alert_data["attack_type"],
            threat_score=alert_data.get("threat_score", 0.0),
            kill_chain_stage=stage,
            mitre_tactic=alert_data.get("mitre_tactic"),
            mitre_technique=alert_data.get("mitre_technique"),
        )

        # Try to find existing campaign
        source_ip = chain_alert.source_ip
        campaign_id = self._ip_campaign.get(source_ip)

        if campaign_id and campaign_id in self._campaigns:
            campaign = self._campaigns[campaign_id]
        else:
            # Check Neo4j
            if self._neo4j:
                campaign_id = await self._neo4j.find_active_campaign(source_ip)
            if campaign_id and campaign_id in self._campaigns:
                campaign = self._campaigns[campaign_id]
            else:
                campaign = AttackCampaign()
                self._campaigns[campaign.campaign_id] = campaign

        campaign.add_alert(chain_alert)
        self._ip_campaign[source_ip] = campaign.campaign_id

        # Persist to Neo4j
        if self._neo4j:
            await self._neo4j.store_alert(chain_alert)
            await self._neo4j.link_to_campaign(chain_alert.alert_id, campaign)

        logger.info(
            "Campaign %s | stage=%s | risks_score=%.4f | alerts=%d | stages=%s",
            campaign.campaign_id[:8],
            stage,
            campaign.risk_score,
            len(campaign.alerts),
            campaign.stages_reached,
        )

        return campaign

    def get_campaign(self, campaign_id: str) -> Optional[AttackCampaign]:
        return self._campaigns.get(campaign_id)

    def get_campaigns_for_ip(self, ip: str) -> Optional[AttackCampaign]:
        cid = self._ip_campaign.get(ip)
        return self._campaigns.get(cid) if cid else None

    @property
    def active_campaigns(self) -> List[AttackCampaign]:
        return [c for c in self._campaigns.values() if c.status == "ACTIVE"]
