"""CyberShield-X Cognitive Firewall — Attacker ToM + Dynamic Rule Engine."""

import time
import hashlib
import logging
from collections import defaultdict
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app, Counter
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cognitive-firewall")

RULE_GEN_COUNT = Counter("cf_rules_generated_total", "Firewall rules generated", ["action"])
BLOCK_COUNT    = Counter("cf_blocks_total", "Connections blocked", ["reason"])

app = FastAPI(
    title="CyberShield-X Cognitive Firewall",
    version="1.0.0",
    description="Attacker Theory-of-Mind prediction and dynamic firewall controller",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/metrics", make_asgi_app())

# ── In-memory firewall ruleset + behavioral state ─

_rules: List[dict] = []                           # active dynamic rules
_blocked_ips: Dict[str, dict] = {}                # IP → block reason + time
_attacker_profiles: Dict[str, dict] = {}          # src_ip → behavioral profile
_stats = {"rules_active": 0, "ips_blocked": 0, "behaviors_analyzed": 0, "predictions_made": 0}

# ── MITRE ATT&CK kill-chain stages ────────────────

KILL_CHAIN = ["reconnaissance", "weaponization", "delivery", "exploitation",
              "installation", "command_and_control", "actions_on_objectives"]

# Attacker behavior → predicted next stage
NEXT_STAGE_MAP = {
    "port_scan":          ("delivery",            ["T1046", "T1595"]),
    "brute_force":        ("exploitation",        ["T1110", "T1078"]),
    "lateral_movement":   ("command_and_control", ["T1021", "T1071"]),
    "c2_beacon":          ("actions_on_objectives",["T1071", "T1041"]),
    "data_exfiltration":  ("actions_on_objectives",["T1041", "T1048"]),
    "credential_access":  ("lateral_movement",    ["T1003", "T1078"]),
    "privilege_escalation":("installation",       ["T1068", "T1055"]),
}

# ── Schemas ───────────────────────────────────────

class BehaviorEvent(BaseModel):
    src_ip: str
    technique: str              # port_scan, brute_force, lateral_movement, etc.
    confidence: float = 0.8
    dst_ports: List[int] = []
    bytes_sent: int = 0
    timestamp: Optional[str] = None

class FirewallRuleRequest(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: str = "TCP"
    action: str = "DENY"            # DENY, ALLOW, RATE_LIMIT, REDIRECT
    reason: str = ""
    ttl_seconds: int = 3600

class ConnectionRequest(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    user_agent: Optional[str] = None

# ── Core cognitive engine ──────────────────────────

def _update_attacker_profile(src_ip: str, technique: str, confidence: float) -> dict:
    """Build a behavioral profile for an attacker IP using kill-chain progression."""
    profile = _attacker_profiles.get(src_ip, {
        "src_ip": src_ip,
        "techniques_observed": [],
        "kill_chain_stage": "reconnaissance",
        "threat_score": 0.0,
        "first_seen": time.time(),
        "last_seen": time.time(),
    })

    if technique not in profile["techniques_observed"]:
        profile["techniques_observed"].append(technique)

    # Advance kill-chain stage based on observed technique
    next_stage, mitre = NEXT_STAGE_MAP.get(technique, (profile["kill_chain_stage"], []))
    current_idx = KILL_CHAIN.index(profile["kill_chain_stage"]) if profile["kill_chain_stage"] in KILL_CHAIN else 0
    next_idx    = KILL_CHAIN.index(next_stage) if next_stage in KILL_CHAIN else 0
    if next_idx > current_idx:
        profile["kill_chain_stage"] = next_stage

    # Increase threat score
    profile["threat_score"] = min(profile["threat_score"] + confidence * 0.25, 1.0)
    profile["last_seen"] = time.time()
    profile["predicted_next_techniques"] = mitre

    _attacker_profiles[src_ip] = profile
    return profile

def _generate_rules_for_threat(profile: dict) -> List[dict]:
    """Generate dynamic firewall rules based on attacker's kill-chain stage."""
    rules = []
    src_ip = profile["src_ip"]
    stage = profile["kill_chain_stage"]
    score = profile["threat_score"]

    if score >= 0.8 or stage in ("command_and_control", "actions_on_objectives"):
        # Full block
        rules.append({
            "id": hashlib.md5(f"block-{src_ip}".encode()).hexdigest()[:10],
            "action": "DENY",
            "src_ip": src_ip,
            "dst_ip": "ANY",
            "dst_port": "ANY",
            "protocol": "ANY",
            "reason": f"High-confidence threat actor (score={score:.2f}, stage={stage})",
            "auto_generated": True,
            "expires_at": time.time() + 86400,
        })
        _blocked_ips[src_ip] = {"reason": f"auto-block: {stage}", "time": time.time(), "score": score}
        _stats["ips_blocked"] = len(_blocked_ips)

    elif score >= 0.5 or stage in ("exploitation", "installation"):
        # Rate limit + alert
        rules.append({
            "id": hashlib.md5(f"ratelimit-{src_ip}".encode()).hexdigest()[:10],
            "action": "RATE_LIMIT",
            "src_ip": src_ip,
            "dst_ip": "ANY",
            "dst_port": "ANY",
            "protocol": "ANY",
            "reason": f"Suspicious behavior (score={score:.2f}, stage={stage})",
            "rate_limit": "10/min",
            "auto_generated": True,
            "expires_at": time.time() + 3600,
        })
    elif score >= 0.3:
        # Log + monitor
        rules.append({
            "id": hashlib.md5(f"monitor-{src_ip}".encode()).hexdigest()[:10],
            "action": "LOG_AND_MONITOR",
            "src_ip": src_ip,
            "dst_ip": "ANY",
            "dst_port": "ANY",
            "protocol": "ANY",
            "reason": f"Early-stage suspicious activity (stage={stage})",
            "auto_generated": True,
            "expires_at": time.time() + 1800,
        })

    return rules

# ── Endpoints ──────────────────────────────────────

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "cognitive-firewall",
        "version": "1.0.0",
        "stats": _stats,
    }

@app.post("/analyze/behavior")
async def analyze_behavior(ev: BehaviorEvent):
    """Analyze attacker behavior, predict kill-chain progression, generate rules."""
    t0 = time.time()
    _stats["behaviors_analyzed"] += 1

    profile = _update_attacker_profile(ev.src_ip, ev.technique, ev.confidence)
    new_rules = _generate_rules_for_threat(profile)

    for rule in new_rules:
        # Avoid duplicates
        if not any(r["id"] == rule["id"] for r in _rules):
            _rules.append(rule)
            _stats["rules_active"] = len(_rules)
            RULE_GEN_COUNT.labels(action=rule["action"]).inc()

    _stats["predictions_made"] += 1

    return {
        "src_ip": ev.src_ip,
        "kill_chain_stage": profile["kill_chain_stage"],
        "threat_score": round(profile["threat_score"], 4),
        "techniques_observed": profile["techniques_observed"],
        "predicted_next_techniques": profile.get("predicted_next_techniques", []),
        "rules_generated": len(new_rules),
        "new_rules": new_rules,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }

@app.post("/rules")
async def add_rule(req: FirewallRuleRequest):
    """Manually add a firewall rule."""
    rule = {
        "id": hashlib.md5(f"{req.src_ip}{req.dst_port}{time.time()}".encode()).hexdigest()[:10],
        "action": req.action,
        "src_ip": req.src_ip or "ANY",
        "dst_ip": req.dst_ip or "ANY",
        "dst_port": str(req.dst_port) if req.dst_port else "ANY",
        "protocol": req.protocol,
        "reason": req.reason,
        "auto_generated": False,
        "expires_at": time.time() + req.ttl_seconds,
    }
    _rules.append(rule)
    _stats["rules_active"] = len(_rules)
    RULE_GEN_COUNT.labels(action=req.action).inc()
    if req.src_ip and req.action == "DENY":
        _blocked_ips[req.src_ip] = {"reason": req.reason, "time": time.time()}
        _stats["ips_blocked"] = len(_blocked_ips)
    return rule

@app.get("/rules")
async def get_rules():
    """Get all active firewall rules, expiring old ones."""
    now = time.time()
    active = [r for r in _rules if r.get("expires_at", now + 1) > now]
    _rules.clear()
    _rules.extend(active)
    _stats["rules_active"] = len(_rules)
    return {"rules": _rules, "total": len(_rules), "stats": _stats}

@app.post("/check")
async def check_connection(req: ConnectionRequest):
    """Check if a connection should be allowed or blocked by current rules."""
    now = time.time()
    for rule in _rules:
        if rule.get("expires_at", now + 1) <= now:
            continue
        src_match = rule["src_ip"] == "ANY" or rule["src_ip"] == req.src_ip
        dst_port_match = rule["dst_port"] == "ANY" or str(rule["dst_port"]) == str(req.dst_port)
        if src_match and dst_port_match:
            BLOCK_COUNT.labels(reason=rule["action"]).inc()
            return {
                "allowed": rule["action"] in ("ALLOW", "LOG_AND_MONITOR"),
                "action": rule["action"],
                "rule_id": rule["id"],
                "reason": rule["reason"],
            }
    return {"allowed": True, "action": "ALLOW", "rule_id": None, "reason": "No matching rule"}

@app.get("/profiles")
async def get_attacker_profiles():
    """Get behavioral profiles of tracked attacker IPs."""
    return {
        "profiles": list(_attacker_profiles.values()),
        "total": len(_attacker_profiles),
    }

@app.get("/stats")
async def get_stats():
    return {"service": "cognitive-firewall", **_stats}

@app.on_event("startup")
async def startup_event():
    logger.info("Cognitive Firewall starting up — ToM engine active")
    logger.info("Dynamic rule generation with kill-chain awareness enabled")
