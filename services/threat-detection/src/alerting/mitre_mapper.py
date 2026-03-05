"""
CyberShield-X — MITRE ATT&CK Auto-Mapper
Maps detected techniques to ATT&CK Tactic + Technique + Sub-technique
using an embedded mapping matrix (not raw JSON).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

logger = logging.getLogger("cybershield.alerting.mitre_mapper")


# ──────────────────────────────────────────────
# ATT&CK data model
# ──────────────────────────────────────────────

@dataclass
class ATTCKMapping:
    """Structured ATT&CK technique mapping."""

    tactic: str
    technique_id: str
    technique_name: str
    sub_technique: Optional[str] = None
    sub_technique_id: Optional[str] = None
    description: str = ""
    detection_tips: List[str] = None
    mitigation_ids: List[str] = None

    def __post_init__(self):
        if self.detection_tips is None:
            self.detection_tips = []
        if self.mitigation_ids is None:
            self.mitigation_ids = []

    def to_dict(self) -> Dict:
        return asdict(self)


# ──────────────────────────────────────────────
# Embedded ATT&CK mapping matrix
# ──────────────────────────────────────────────

# Covers all 14 tactics × key techniques for CyberShield-X detection categories.

TECHNIQUE_DB: Dict[str, ATTCKMapping] = {
    # ─── Initial Access ──────────────
    "T1190": ATTCKMapping(
        tactic="Initial Access", technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        description="Adversary exploits a vulnerability in an internet-facing system.",
        detection_tips=["Monitor WAF logs for exploit payloads", "Track anomalous POST sizes"],
        mitigation_ids=["M1048", "M1050", "M1030"],
    ),
    "T1566": ATTCKMapping(
        tactic="Initial Access", technique_id="T1566",
        technique_name="Phishing",
        sub_technique="Spearphishing Attachment",
        sub_technique_id="T1566.001",
        description="Adversary sends targeted phishing emails.",
        detection_tips=["Scan inbound emails for known IOCs", "Sandbox suspicious attachments"],
        mitigation_ids=["M1054", "M1017", "M1049"],
    ),
    "T1078": ATTCKMapping(
        tactic="Initial Access", technique_id="T1078",
        technique_name="Valid Accounts",
        description="Adversary uses stolen or compromised credentials.",
        detection_tips=["Monitor for impossible travel", "Check for credential stuffing patterns"],
        mitigation_ids=["M1027", "M1026", "M1032"],
    ),
    # ─── Execution ───────────────────
    "T1059": ATTCKMapping(
        tactic="Execution", technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        sub_technique="PowerShell",
        sub_technique_id="T1059.001",
        description="Adversary executes commands via script interpreters.",
        detection_tips=["Monitor process creation for script engines", "Log command-line arguments"],
        mitigation_ids=["M1049", "M1038", "M1042"],
    ),
    "T1204": ATTCKMapping(
        tactic="Execution", technique_id="T1204",
        technique_name="User Execution",
        sub_technique="Malicious Link",
        sub_technique_id="T1204.001",
        description="User opens a malicious link or file.",
        detection_tips=["Track URL click-through from emails", "Monitor child processes of browsers"],
        mitigation_ids=["M1017", "M1038"],
    ),
    # ─── Persistence ─────────────────
    "T1547": ATTCKMapping(
        tactic="Persistence", technique_id="T1547",
        technique_name="Boot or Logon Autostart Execution",
        sub_technique="Registry Run Keys",
        sub_technique_id="T1547.001",
        description="Adversary adds registry keys for persistence.",
        detection_tips=["Monitor HKLM/HKCU Run keys", "Audit startup folder changes"],
        mitigation_ids=["M1038", "M1024"],
    ),
    "T1136": ATTCKMapping(
        tactic="Persistence", technique_id="T1136",
        technique_name="Create Account",
        description="Adversary creates a new account for persistence.",
        detection_tips=["Alert on new account creation", "Monitor AD changes"],
        mitigation_ids=["M1032", "M1026"],
    ),
    # ─── Privilege Escalation ────────
    "T1068": ATTCKMapping(
        tactic="Privilege Escalation", technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        description="Adversary exploits software vulnerability to gain elevated privileges.",
        detection_tips=["Monitor for unexpected privilege changes", "Track exploit indicators"],
        mitigation_ids=["M1048", "M1019", "M1038"],
    ),
    # ─── Defense Evasion ─────────────
    "T1070": ATTCKMapping(
        tactic="Defense Evasion", technique_id="T1070",
        technique_name="Indicator Removal",
        sub_technique="Clear Windows Event Logs",
        sub_technique_id="T1070.001",
        description="Adversary clears logs to remove evidence.",
        detection_tips=["Monitor EventLog service stops", "Alert on log clearing events"],
        mitigation_ids=["M1029", "M1022"],
    ),
    "T1027": ATTCKMapping(
        tactic="Defense Evasion", technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        description="Adversary obfuscates payloads to evade detection.",
        detection_tips=["Scan for encoded/packed binaries", "Detect high-entropy files"],
        mitigation_ids=["M1049", "M1040"],
    ),
    # ─── Credential Access ───────────
    "T1110": ATTCKMapping(
        tactic="Credential Access", technique_id="T1110",
        technique_name="Brute Force",
        sub_technique="Password Spraying",
        sub_technique_id="T1110.003",
        description="Adversary attempts many passwords against accounts.",
        detection_tips=["Monitor failed login counts per source", "Detect spray patterns"],
        mitigation_ids=["M1032", "M1027", "M1036"],
    ),
    "T1003": ATTCKMapping(
        tactic="Credential Access", technique_id="T1003",
        technique_name="OS Credential Dumping",
        sub_technique="LSASS Memory",
        sub_technique_id="T1003.001",
        description="Adversary dumps credentials from OS memory.",
        detection_tips=["Monitor access to lsass.exe", "Enable Credential Guard"],
        mitigation_ids=["M1043", "M1025", "M1027"],
    ),
    # ─── Discovery ───────────────────
    "T1046": ATTCKMapping(
        tactic="Discovery", technique_id="T1046",
        technique_name="Network Service Discovery",
        description="Adversary scans for open ports and services.",
        detection_tips=["Detect sequential port probes", "Monitor for SYN scans"],
        mitigation_ids=["M1030", "M1031"],
    ),
    "T1087": ATTCKMapping(
        tactic="Discovery", technique_id="T1087",
        technique_name="Account Discovery",
        description="Adversary enumerates accounts on a system or domain.",
        detection_tips=["Monitor for net user / LDAP queries", "Detect bulk AD enumeration"],
        mitigation_ids=["M1028", "M1018"],
    ),
    # ─── Lateral Movement ────────────
    "T1021": ATTCKMapping(
        tactic="Lateral Movement", technique_id="T1021",
        technique_name="Remote Services",
        sub_technique="SMB/Windows Admin Shares",
        sub_technique_id="T1021.002",
        description="Adversary moves laterally via SMB shares.",
        detection_tips=["Monitor SMB lateral auth", "Detect PsExec or admin share access"],
        mitigation_ids=["M1026", "M1035", "M1032"],
    ),
    "T1076": ATTCKMapping(
        tactic="Lateral Movement", technique_id="T1076",
        technique_name="Remote Desktop Protocol",
        description="Adversary uses RDP for lateral movement.",
        detection_tips=["Monitor RDP sessions", "Detect unusual RDP source IPs"],
        mitigation_ids=["M1042", "M1035", "M1032"],
    ),
    # ─── Collection ──────────────────
    "T1005": ATTCKMapping(
        tactic="Collection", technique_id="T1005",
        technique_name="Data from Local System",
        description="Adversary collects data from the local file system.",
        detection_tips=["Monitor file access patterns", "Detect bulk reads of sensitive dirs"],
        mitigation_ids=["M1057", "M1017"],
    ),
    # ─── Command and Control ─────────
    "T1071": ATTCKMapping(
        tactic="Command and Control", technique_id="T1071",
        technique_name="Application Layer Protocol",
        sub_technique="Web Protocols",
        sub_technique_id="T1071.001",
        description="Adversary uses HTTP/HTTPS for C2 communication.",
        detection_tips=["Detect beaconing patterns", "Monitor for DGA domains"],
        mitigation_ids=["M1031", "M1037"],
    ),
    "T1573": ATTCKMapping(
        tactic="Command and Control", technique_id="T1573",
        technique_name="Encrypted Channel",
        description="Adversary uses encryption for C2.",
        detection_tips=["Inspect TLS certificate anomalies", "Detect non-standard TLS ports"],
        mitigation_ids=["M1031", "M1020"],
    ),
    # ─── Exfiltration ────────────────
    "T1041": ATTCKMapping(
        tactic="Exfiltration", technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        description="Adversary exfiltrates data over the C2 channel.",
        detection_tips=["Monitor outbound data volume anomalies", "Detect large uploads"],
        mitigation_ids=["M1031", "M1057"],
    ),
    "T1048": ATTCKMapping(
        tactic="Exfiltration", technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        description="Adversary exfiltrates using DNS, ICMP, etc.",
        detection_tips=["Monitor DNS TXT record sizes", "Detect ICMP data exfil"],
        mitigation_ids=["M1031", "M1037"],
    ),
    # ─── Impact ──────────────────────
    "T1486": ATTCKMapping(
        tactic="Impact", technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        description="Adversary encrypts data to demand ransom.",
        detection_tips=["Detect rapid file encryption patterns", "Monitor for ransom notes"],
        mitigation_ids=["M1053", "M1040"],
    ),
    "T1498": ATTCKMapping(
        tactic="Impact", technique_id="T1498",
        technique_name="Network Denial of Service",
        description="Adversary floods network causing DoS.",
        detection_tips=["Monitor traffic volume spikes", "Detect SYN floods"],
        mitigation_ids=["M1037"],
    ),
    "T1583.005": ATTCKMapping(
        tactic="Resource Development", technique_id="T1583",
        technique_name="Acquire Infrastructure",
        sub_technique="Botnet",
        sub_technique_id="T1583.005",
        description="Adversary acquires/builds a botnet.",
        detection_tips=["Detect C2 beaconing from multiple hosts", "Monitor for IRC/HTTP-based bot traffic"],
        mitigation_ids=["M1056"],
    ),
}

# ─── Attack-type → Technique-ID Quick Map ──────
ATTACK_TYPE_TO_TECHNIQUE: Dict[str, str] = {
    "DDoS": "T1498",
    "PortScan": "T1046",
    "BruteForce": "T1110",
    "Botnet": "T1583.005",
    "Infiltration": "T1078",
    "WebAttack": "T1190",
    "Ransomware": "T1486",
    "C2": "T1071",
    "Exfiltration": "T1041",
    "Phishing": "T1566",
    "SPEAR_PHISHING": "T1566",
    "BEC": "T1566",
    "CredentialDumping": "T1003",
    "LateralMovement": "T1021",
    "PrivilegeEscalation": "T1068",
    "DefenseEvasion": "T1027",
    "DataTheft": "T1005",
}


# ──────────────────────────────────────────────
# Mapper
# ──────────────────────────────────────────────

class MITREMapper:
    """Map detected attacks to MITRE ATT&CK framework.

    Usage:
        mapper = MITREMapper()
        mapping = mapper.map_attack("DDoS")
        mapping = mapper.map_technique_id("T1190")
    """

    def __init__(self) -> None:
        self._db = TECHNIQUE_DB
        self._attack_map = ATTACK_TYPE_TO_TECHNIQUE

    def map_attack(self, attack_type: str) -> Optional[ATTCKMapping]:
        """Map an attack type label to its ATT&CK technique.

        Parameters
        ----------
        attack_type : str
            CyberShield-X attack label.

        Returns
        -------
        ATTCKMapping or None if no mapping exists.
        """
        tid = self._attack_map.get(attack_type)
        if tid:
            return self._db.get(tid)
        logger.debug("No ATT&CK mapping for attack type: %s", attack_type)
        return None

    def map_technique_id(self, technique_id: str) -> Optional[ATTCKMapping]:
        """Look up directly by ATT&CK technique ID."""
        return self._db.get(technique_id)

    def get_tactic_techniques(self, tactic: str) -> List[ATTCKMapping]:
        """Return all techniques for a given tactic."""
        return [m for m in self._db.values() if m.tactic == tactic]

    def get_all_tactics(self) -> List[str]:
        """Return unique list of mapped tactics."""
        return sorted(set(m.tactic for m in self._db.values()))

    def map_event(self, event: Dict[str, Any]) -> Optional[ATTCKMapping]:
        """Map a full event dict (with attack_type or mitre_technique key).

        Tries attack_type first, then mitre_technique.
        """
        at = event.get("attack_type")
        if at:
            mapping = self.map_attack(at)
            if mapping:
                return mapping

        tid = event.get("mitre_technique")
        if tid:
            return self.map_technique_id(tid)

        return None

    @property
    def technique_count(self) -> int:
        return len(self._db)
