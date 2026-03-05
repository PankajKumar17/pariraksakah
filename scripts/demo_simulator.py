"""
CyberShield-X — Demo Simulator
Generates realistic demo traffic and alerts for showcasing the platform.
Run: python scripts/demo_simulator.py
"""

import json
import time
import random
import hashlib
from datetime import datetime, timedelta

# ── Configuration ───────────────────────────────

ATTACK_SCENARIOS = [
    {
        "name": "APT29 Campaign — Supply Chain Attack",
        "kill_chain": [
            {"stage": "reconnaissance", "delay": 2, "event": "DNS enumeration from 185.220.101.34 targeting internal-api.corp.local"},
            {"stage": "weaponization", "delay": 3, "event": "Trojanized update package detected in staging repo"},
            {"stage": "delivery", "delay": 2, "event": "Spear-phishing email with malicious PDF to finance@company.com"},
            {"stage": "exploitation", "delay": 1, "event": "CVE-2024-0001 exploit triggered on fin-srv-03 (10.0.5.42)"},
            {"stage": "installation", "delay": 2, "event": "Cobalt Strike beacon installed as svchost.exe on 10.0.5.42"},
            {"stage": "command_control", "delay": 3, "event": "C2 beacon to 45.33.32.156:443 every 60s (HTTPS)"},
            {"stage": "actions_on_objectives", "delay": 2, "event": "Ransomware payload deployed across finance subnet"},
        ],
    },
    {
        "name": "Insider Threat — Data Exfiltration",
        "kill_chain": [
            {"stage": "reconnaissance", "delay": 1, "event": "Unusual database queries from svc-analytics (off-hours)"},
            {"stage": "exploitation", "delay": 2, "event": "Privilege escalation via misconfigured IAM role"},
            {"stage": "actions_on_objectives", "delay": 3, "event": "5.2 GB data exported to personal cloud storage"},
        ],
    },
    {
        "name": "Distributed Phishing Campaign",
        "kill_chain": [
            {"stage": "delivery", "delay": 1, "event": "142 phishing emails detected — homoglyph domain: micros0ft-login.com"},
            {"stage": "delivery", "delay": 2, "event": "Voice deepfake call to CFO from spoofed CEO number"},
            {"stage": "exploitation", "delay": 1, "event": "3 credential harvesting form submissions detected"},
        ],
    },
]

NORMAL_EVENTS = [
    "User login from trusted IP 10.0.1.{}",
    "Firewall rule updated by admin@company.com",
    "Scheduled backup completed for db-cluster-01",
    "SSL certificate renewed for api.company.com",
    "Patch KB5034441 applied to {} workstations",
    "VPN session established from 203.0.113.{}",
    "Email gateway processed {} messages (0 threats)",
    "DNS query resolved: internal-app.corp.local",
]


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ⛨  CyberShield-X  Demo Simulator  v1.0                ║
║                                                          ║
║   Simulates realistic attack scenarios and normal        ║
║   traffic for platform demonstration.                    ║
║                                                          ║
║   8 Breakthrough Innovations:                            ║
║   • Autonomous Swarm Defense (P12)                       ║
║   • Dream-State Hunting (P13)                            ║
║   • Bio-Cyber Fusion Auth (P10)                          ║
║   • Ephemeral Infrastructure (P11)                       ║
║   • Cognitive Firewall (P12)                             ║
║   • Self-Healing Code DNA (P14)                          ║
║   • Satellite Integrity Chain (P15)                      ║
║   • Post-Quantum Crypto (P06)                            ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    """)


def simulate_normal_traffic():
    """Generate a normal event."""
    template = random.choice(NORMAL_EVENTS)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": "normal",
        "source": f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
        "event": template.format(random.randint(1, 254)),
        "severity": "info",
    }
    print(f"  [INFO]  {event['timestamp'][:19]}  {event['event']}")
    return event


def simulate_attack_scenario(scenario):
    """Walk through a full kill chain scenario."""
    print(f"\n{'='*60}")
    print(f"  🚨 SCENARIO: {scenario['name']}")
    print(f"{'='*60}")

    alerts_generated = []
    for step in scenario["kill_chain"]:
        time.sleep(step["delay"])
        
        severity = "critical" if step["stage"] in ("actions_on_objectives", "command_control") else \
                   "high" if step["stage"] in ("exploitation", "installation") else "medium"
        
        alert = {
            "alert_id": f"ALT-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8].upper()}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "stage": step["stage"],
            "severity": severity,
            "event": step["event"],
            "mitre_technique": get_mitre_technique(step["stage"]),
        }
        alerts_generated.append(alert)
        
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(severity, "🔵")
        print(f"  {icon} [{severity.upper():8}] Stage: {step['stage']}")
        print(f"    └─ {step['event']}")
        print(f"       MITRE: {alert['mitre_technique']}  |  Alert: {alert['alert_id']}")
    
    # Swarm response
    print(f"\n  🐝 SWARM RESPONSE:")
    print(f"    └─ 24 hunter agents deployed to affected subnet")
    print(f"    └─ BFT consensus reached in 45ms — threat confirmed")
    print(f"    └─ Cognitive Firewall: blocking source IPs")
    
    return alerts_generated


def simulate_innovation_status():
    """Show status of all 8 innovations."""
    print(f"\n{'='*60}")
    print(f"  📊 INNOVATION STATUS CHECK")
    print(f"{'='*60}")
    
    innovations = [
        ("🐝 Swarm Defense", "ACTIVE", "128 agents, 342 det/min"),
        ("🌙 Dream Hunting", "ACTIVE", "23 findings, 8 retro-hits"),
        ("🧬 Bio-Auth Fusion", "ACTIVE", "47 enrolled, 99.2% conf"),
        ("♻️  Ephemeral Infra", "ACTIVE", "6 rotations/h, 34 canaries"),
        ("🧠 Cognitive FW", "ACTIVE", "1,247 tracked, 91.3% accuracy"),
        ("🔧 Self-Healing", "DEGRADED", "2 mutations, 1 auto-healed"),
        ("🛰️  Satellite Chain", "ACTIVE", "48,291 entries, ±50ns"),
        ("🔐 Post-Quantum", "ACTIVE", "Kyber-1024, 1,200 kex/s"),
    ]
    
    for name, status, metrics in innovations:
        color = "✅" if status == "ACTIVE" else "⚠️"
        print(f"  {color} {name:25} [{status:8}]  {metrics}")


def get_mitre_technique(stage: str) -> str:
    mapping = {
        "reconnaissance": "T1595 - Active Scanning",
        "weaponization": "T1587 - Develop Capabilities",
        "delivery": "T1566 - Phishing",
        "exploitation": "T1203 - Exploitation for Client Execution",
        "installation": "T1543 - Create or Modify System Process",
        "command_control": "T1071 - Application Layer Protocol",
        "actions_on_objectives": "T1486 - Data Encrypted for Impact",
    }
    return mapping.get(stage, "Unknown")


def main():
    print_banner()
    
    print("\n📡 Starting normal traffic generation...\n")
    for _ in range(5):
        simulate_normal_traffic()
        time.sleep(0.5)
    
    # Run attack scenarios
    for scenario in ATTACK_SCENARIOS:
        alerts = simulate_attack_scenario(scenario)
    
    # Innovation status
    simulate_innovation_status()
    
    # Summary
    print(f"\n{'='*60}")
    print(f"  📋 DEMO SUMMARY")
    print(f"{'='*60}")
    print(f"  Total events generated:     {5 + sum(len(s['kill_chain']) for s in ATTACK_SCENARIOS)}")
    print(f"  Attack scenarios:           {len(ATTACK_SCENARIOS)}")
    print(f"  Critical alerts:            {sum(1 for s in ATTACK_SCENARIOS for step in s['kill_chain'] if step['stage'] in ('actions_on_objectives', 'command_control'))}")
    print(f"  Innovations active:         7/8")
    print(f"  Mean detection time:        12ms")
    print(f"  Swarm consensus time:       45ms")
    print(f"\n  ✅ Demo simulation complete.\n")


if __name__ == "__main__":
    main()
