import os, time, json, logging
from datetime import datetime
import psycopg2
from neo4j import GraphDatabase
from confluent_kafka import Producer
import requests
from fastapi import FastAPI
from threading import Thread

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MONITOR] %(message)s")

KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
DB_URL = os.getenv("DATABASE_URL", "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "changeme_neo4j")
IDENTITY_ENGINE = os.getenv("DNA_IDENTITY_ENGINE_URL", "http://dna-identity-engine:8050")
TRUST_REGISTRY = os.getenv("DNA_TRUST_REGISTRY_URL", "http://dna-trust-registry:8053")

COMPONENTS = ["api-gateway", "kafka", "timescaledb", "neo4j", "redis", "flink", "mlflow", "falco", "trivy", "prometheus", "grafana", "react-frontend", "self-healing", "dna-identity-engine", "dna-certificate-authority", "dna-trust-registry"]

# Connect to DBs
try:
    pg_conn = psycopg2.connect(DB_URL)
    pg_conn.autocommit = True
    pg_cur = pg_conn.cursor()
except Exception as e:
    logging.warning(f"PG Connection failed: {e}")

try:
    neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
except Exception as e:
    logging.warning(f"Neo4j Connection failed: {e}")

producer = Producer({'bootstrap.servers': KAFKA_BROKER})

app = FastAPI()

def publish_event(topic, payload):
    try:
        producer.produce(topic, key="monitor", value=json.dumps(payload))
        producer.flush()
    except Exception as e:
        logging.error(f"Kafka error: {e}")

def hash_fake():
    return os.urandom(16).hex()

def calculate_delta(baseline, current):
    # Simulated delta calculation
    hw_delta = 0.0 # mostly static
    sw_delta = 0.0 # occasionally changes
    bw_delta = 0.1 # fluctuates
    nw_delta = 0.0
    return hw_delta * 0.4 + sw_delta * 0.3 + bw_delta * 0.2 + nw_delta * 0.1

def fetch_trust_score(c_id):
    try:
        r = requests.get(f"{TRUST_REGISTRY}/trust/score/{c_id}", timeout=2)
        if r.status_code == 200:
            return r.json().get("trust_score", 100.0)
    except:
        pass
    return 100.0

def monitor_loop():
    while True:
        logging.info("Starting fingerprint monitor cycle (every 60s)...")
        now_ts = datetime.utcnow().isoformat()
        for cid in COMPONENTS:
            baseline = {}
            current = {"hardware": hash_fake(), "software": hash_fake(), "behavioral": hash_fake(), "network": hash_fake()}
            delta = calculate_delta(baseline, current)
            
            # Simulate anomaly injection for demo if self-healing triggered, else default to small delta
            if cid == "api-gateway" and int(time.time()) % 300 < 5:
                delta = 0.60 # Create major anomaly periodically
                
            fp_update = {
                "component_id": cid, "recorded_at": now_ts,
                "fingerprint_hash": hash_fake(), "hardware_hash": current["hardware"],
                "software_hash": current["software"], "behavioral_hash": current["behavioral"],
                "network_hash": current["network"], "temporal_hash": hash_fake(),
                "delta_score": delta * 100.0
            }
            publish_event("dna.fingerprint.updates", fp_update)
            
            try:
                pg_cur.execute(
                    "INSERT INTO fingerprint_history (id, component_id, fingerprint_hash, hardware_hash, software_hash, behavioral_hash, network_hash, temporal_hash, recorded_at, delta_score) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (hash_fake(), cid, fp_update["fingerprint_hash"], fp_update["hardware_hash"], fp_update["software_hash"], fp_update["behavioral_hash"], fp_update["network_hash"], fp_update["temporal_hash"], now_ts, fp_update["delta_score"])
                )
            except:
                pass

            t_score = fetch_trust_score(cid)
            try:
                with neo4j_driver.session() as session:
                    session.run("MATCH (n:ComponentNode {id: $id}) SET n.trust_score = $ts", id=cid, ts=t_score)
            except:
                pass

            if fp_update["delta_score"] > 50.0:
                logging.warning(f"CRITICAL BREACH: {cid} delta > 50%. Invoking self-healing.")
                publish_event("dna.anomaly.detected", {
                    "anomaly_id": f"anm-{hash_fake()}", "component_id": cid, "attack_type": "Identity High Delta",
                    "severity": "CRITICAL", "detected_at": now_ts, "details": "Delta score exceeded 50%", "confidence": 0.95
                })
                # notify self-healing via REST or direct message (Kafka alert picked up by Falco/Self-Healing)
            elif fp_update["delta_score"] > 30.0:
                logging.warning(f"RED ALERT: {cid} delta > 30%. Auto-revoking.")
                try:
                    requests.post(f"{IDENTITY_ENGINE}/dna/revoke/{cid}", timeout=3)
                except:
                    pass
            elif fp_update["delta_score"] > 15.0:
                logging.info(f"YELLOW ALERT: {cid} delta > 15%")
                publish_event("dna.anomaly.detected", {
                    "anomaly_id": f"anm-{hash_fake()}", "component_id": cid, "attack_type": "Behavioral Drift",
                    "severity": "MEDIUM", "detected_at": now_ts, "details": "Delta score exceeded 15%", "confidence": 0.7
                })

        time.sleep(60)

@app.on_event("startup")
def startup_event():
    Thread(target=monitor_loop, daemon=True).start()

@app.get("/metrics")
def get_metrics():
    return "dna_fingerprint_monitor_cycles_total 1\n"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("MONITOR_PORT", "8052")))
