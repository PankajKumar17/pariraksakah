"""
P11 — Canary Deployer
Deploys canary pods with instrumented honeypot services to detect
lateral movement and attacker reconnaissance within the cluster.
"""

import hashlib
import json
import logging
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("cybershield.ephemeral.canary")


@dataclass
class CanaryPod:
    name: str
    namespace: str
    service_type: str       # ssh, http, smb, rdp, database
    honeypot_port: int
    deployed_at: str = ""
    interactions: int = 0
    alerts_raised: int = 0
    token: str = ""         # Canary token embedded in service

    def __post_init__(self):
        if not self.deployed_at:
            self.deployed_at = datetime.now(timezone.utc).isoformat()
        if not self.token:
            self.token = "canary-" + "".join(random.choices(string.hexdigits[:16], k=24))


@dataclass
class CanaryInteraction:
    canary_name: str
    source_ip: str
    source_port: int
    timestamp: str
    interaction_type: str   # connection, login_attempt, data_access, command
    payload: Optional[str] = None
    alert_severity: str = "high"


# ── Canary templates ────────────────────────────

CANARY_TEMPLATES = {
    "ssh": {
        "image": "cybershield/canary-ssh:latest",
        "port": 22,
        "description": "Fake SSH server recording all login attempts",
    },
    "http": {
        "image": "cybershield/canary-http:latest",
        "port": 80,
        "description": "Fake admin panel capturing credential submissions",
    },
    "smb": {
        "image": "cybershield/canary-smb:latest",
        "port": 445,
        "description": "Fake file share detecting lateral movement",
    },
    "rdp": {
        "image": "cybershield/canary-rdp:latest",
        "port": 3389,
        "description": "Fake RDP server detecting brute-force attempts",
    },
    "database": {
        "image": "cybershield/canary-db:latest",
        "port": 5432,
        "description": "Fake database server with seeded fake data",
    },
}


class CanaryDeployer:
    """Manages deployment and monitoring of canary/honeypot pods."""

    def __init__(self, namespace: str = "cybershield"):
        self.namespace = namespace
        self.canaries: Dict[str, CanaryPod] = {}
        self.interactions: List[CanaryInteraction] = []

    def deploy_canary(self, service_type: str, custom_name: Optional[str] = None) -> CanaryPod:
        """Deploy a new canary pod of the specified type."""
        if service_type not in CANARY_TEMPLATES:
            raise ValueError(f"Unknown canary type: {service_type}")

        template = CANARY_TEMPLATES[service_type]
        name = custom_name or f"canary-{service_type}-{_random_suffix()}"

        pod = CanaryPod(
            name=name,
            namespace=self.namespace,
            service_type=service_type,
            honeypot_port=template["port"],
        )

        # Generate K8s manifest (would be applied via K8s API in production)
        manifest = self._generate_manifest(pod, template)
        logger.info("Deploying canary %s (%s) on port %d", name, service_type, template["port"])
        logger.debug("Manifest: %s", json.dumps(manifest, indent=2))

        self.canaries[name] = pod
        return pod

    def deploy_all_types(self) -> List[CanaryPod]:
        """Deploy one canary of each type."""
        return [self.deploy_canary(stype) for stype in CANARY_TEMPLATES]

    def record_interaction(self, interaction: CanaryInteraction):
        """Record an interaction with a canary pod."""
        self.interactions.append(interaction)
        if interaction.canary_name in self.canaries:
            self.canaries[interaction.canary_name].interactions += 1
            self.canaries[interaction.canary_name].alerts_raised += 1
        logger.warning(
            "CANARY TRIGGERED: %s from %s:%d (%s)",
            interaction.canary_name,
            interaction.source_ip,
            interaction.source_port,
            interaction.interaction_type,
        )

    def get_alerts(self, since: Optional[str] = None) -> List[CanaryInteraction]:
        """Retrieve canary interactions, optionally filtered by time."""
        if since is None:
            return self.interactions
        return [i for i in self.interactions if i.timestamp >= since]

    def rotate_canaries(self):
        """Rotate all canary pods (new tokens, new IPs)."""
        rotated = []
        for name, canary in list(self.canaries.items()):
            new_pod = self.deploy_canary(canary.service_type, custom_name=name + "-r")
            del self.canaries[name]
            rotated.append(new_pod)
            logger.info("Rotated canary %s → %s", name, new_pod.name)
        return rotated

    def _generate_manifest(self, pod: CanaryPod, template: Dict) -> Dict:
        """Generate a Kubernetes pod manifest for the canary."""
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod.name,
                "namespace": pod.namespace,
                "labels": {
                    "app": "cybershield-canary",
                    "canary-type": pod.service_type,
                    "canary-token": hashlib.sha256(pod.token.encode()).hexdigest()[:16],
                },
                "annotations": {
                    "cybershield.io/canary": "true",
                    "cybershield.io/deployed-at": pod.deployed_at,
                },
            },
            "spec": {
                "containers": [{
                    "name": "canary",
                    "image": template["image"],
                    "ports": [{"containerPort": template["port"]}],
                    "env": [
                        {"name": "CANARY_TOKEN", "value": pod.token},
                        {"name": "CANARY_TYPE", "value": pod.service_type},
                    ],
                    "resources": {
                        "limits": {"cpu": "100m", "memory": "128Mi"},
                        "requests": {"cpu": "50m", "memory": "64Mi"},
                    },
                }],
                "restartPolicy": "Always",
            },
        }


def _random_suffix(length: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
