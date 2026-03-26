# type: ignore
"""DSRN Network Health Monitor - P2P network health scoring and alerting."""
import os
import json
import time
import logging
from datetime import datetime
from threading import Thread

import requests  # type: ignore
import redis  # type: ignore
from fastapi import FastAPI  # type: ignore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [NET-MON] %(message)s")

PEER_URL = os.getenv("PEER_NODE_URL", "http://dsrn-peer-node:8060")
CONSENSUS_URL = os.getenv("CONSENSUS_ENGINE_URL", "http://dsrn-consensus-engine:8061")
TRUST_URL = os.getenv("TRUST_MANAGER_URL", "http://dsrn-peer-trust-manager:8064")
LEDGER_URL = os.getenv("LEDGER_URL", "http://dsrn-blockchain-ledger:8065")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PASS = os.getenv("REDIS_PASSWORD", "changeme_redis")

app = FastAPI(title="DSRN Network Health Monitor")
rds = redis.Redis(host=REDIS_HOST, port=6379, password=REDIS_PASS, decode_responses=True)

health_history = []
alerts = []


def fetch_json(url, default=None):
    try:
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return default or {}


def calculate_resilience():
    peers_data = fetch_json(PEER_URL + "/peer/list", {"peers": []})
    peer_list = peers_data.get("peers", [])
    active = [p for p in peer_list if isinstance(p, dict) and p.get("status") == "ACTIVE"]
    peer_count = len(active)

    consensus_data = fetch_json(CONSENSUS_URL + "/consensus/history", {"rounds": []})
    round_list = consensus_data.get("rounds", [])
    committed = sum(1 for r in round_list if isinstance(r, dict) and r.get("result") == "COMMITTED")
    total_rounds = max(len(round_list), 1)
    success_rate = committed / total_rounds

    trust_data = fetch_json(TRUST_URL + "/trust/network/health", {})
    trust_avg = trust_data.get("average_reputation", 75.0)
    above_thresh = trust_data.get("peers_above_threshold", 0)

    peer_adequacy = min(peer_count / 4.0, 1.0) * 25.0
    consensus_health = success_rate * 25.0
    intel_quality = 0.85 * 25.0
    denom = max(peer_count, 1)
    trust_dist = (above_thresh / denom) * 25.0

    raw_score = peer_adequacy + consensus_health + intel_quality + trust_dist
    score = int(raw_score * 10) / 10.0

    return {
        "resilience_score": min(score, 100.0),
        "peer_count": peer_count,
        "byzantine_tolerance": max((peer_count - 1) // 3, 0),
        "consensus_success_rate": int(success_rate * 1000) / 10.0,
        "trust_average": int(float(trust_avg) * 10) / 10.0,
        "timestamp": datetime.utcnow().isoformat(),
    }


def monitor_loop():
    while True:
        try:
            metrics = calculate_resilience()
            health_history.append(metrics)
            if len(health_history) > 1000:
                health_history.pop(0)
            rds.setex("dsrn:network:resilience", 60, json.dumps(metrics))

            pc = metrics.get("peer_count", 0)
            rs = metrics.get("resilience_score", 0)
            ts = str(metrics.get("timestamp", ""))
            if isinstance(pc, int) and pc < 4:
                alerts.append({"type": "LOW_PEER_COUNT", "severity": "HIGH",
                               "message": "Only " + str(pc) + " peers", "at": ts})
            if isinstance(rs, (int, float)) and rs < 50:
                alerts.append({"type": "LOW_RESILIENCE", "severity": "CRITICAL",
                               "message": "Score=" + str(rs), "at": ts})
        except Exception as e:
            logging.error("Monitor error: %s", e)
        time.sleep(30)


@app.on_event("startup")
def startup():
    Thread(target=monitor_loop, daemon=True).start()


@app.get("/network/health")
async def health():
    cached = rds.get("dsrn:network:resilience")
    if cached:
        return json.loads(str(cached))
    return calculate_resilience()


@app.get("/network/topology")
async def topology():
    return fetch_json(PEER_URL + "/peer/network/topology", {})


@app.get("/network/metrics")
async def metrics_endpoint():
    return {"history_length": len(health_history),
            "latest": health_history[-1] if health_history else {}}


@app.get("/network/alerts")
async def get_alerts():
    return {"alerts": alerts[-50:] if len(alerts) > 50 else alerts}


@app.get("/network/resilience")
async def resilience():
    return calculate_resilience()


@app.get("/metrics")
async def prom_metrics():
    latest = health_history[-1] if health_history else {}
    r_score = latest.get("resilience_score", 0)
    p_count = latest.get("peer_count", 0)
    return "dsrn_network_resilience_score " + str(r_score) + "\ndsrn_network_peer_count " + str(p_count) + "\n"


if __name__ == "__main__":
    import uvicorn  # type: ignore
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("MONITOR_PORT", "8066")))
