import os, json, time, logging
import numpy as np
from datetime import datetime
import psycopg2
from neo4j import GraphDatabase
from confluent_kafka import Producer
import requests
from fastapi import FastAPI
from threading import Thread
import mlflow
import mlflow.sklearn
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ANOMALY] %(message)s")

KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
DB_URL = os.getenv("DATABASE_URL", "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "changeme_neo4j")
MLFLOW_URI = os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000")
TRUST_REGISTRY = os.getenv("DNA_TRUST_REGISTRY_URL", "http://dna-trust-registry:8053")

mlflow.set_tracking_uri(MLFLOW_URI)

app = FastAPI()
producer = Producer({'bootstrap.servers': KAFKA_BROKER})

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

models = {}

def publish_event(topic, payload):
    try:
        producer.produce(topic, key="anomaly", value=json.dumps(payload))
        producer.flush()
    except Exception as e:
        logging.error(f"Kafka error: {e}")

def train_models():
    logging.info("Training Isolation Forest models for DNA anomalies via MLFlow...")
    components = ["api-gateway", "redis", "kafka", "neo4j", "timescaledb"]
    
    for comp in components:
        # Simulate fetching normal baseline behavioral features from TimescaleDB
        normal_data = np.random.normal(loc=0.0, scale=1.0, size=(1000, 4))
        
        mlflow.set_experiment(f"dna_anomaly_{comp}")
        with mlflow.start_run(run_name=f"auto-retrain-{datetime.utcnow().date()}"):
            clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
            clf.fit(normal_data)
            mlflow.sklearn.log_model(clf, "model")
            models[comp] = clf
            
def background_training_loop():
    while True:
        try:
            train_models()
        except Exception as e:
            logging.error(f"Training failed: {e}")
        time.sleep(86400) # Re-train every 24 hours

def trigger_response(comp_id, attack_type, confidence):
    now_str = datetime.utcnow().isoformat()
    # 1. Publish to Kafka
    anomaly = {
        "anomaly_id": f"anm-{os.urandom(4).hex()}",
        "component_id": comp_id,
        "attack_type": attack_type,
        "severity": "CRITICAL",
        "detected_at": now_str,
        "details": f"Detected high-confidence ({confidence:.2f}) {attack_type}",
        "confidence": confidence
    }
    publish_event("dna.anomaly.detected", anomaly)
    
    # 2. Add ImpersonationAttempt to Neo4j
    if neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    MERGE (c:ComponentNode {id: $cid})
                    MERGE (a:ImpersonationAttempt {id: $aid, attack_type: $type, timestamp: $ts})
                    MERGE (c)-[:RECEIVED_ATTACK]->(a)
                """, cid=comp_id, aid=anomaly["anomaly_id"], type=attack_type, ts=now_str)
        except Exception as e:
            logging.error(f"Neo4j update failed: {e}")
            
    # 3. Write immutable audit record
    if pg_conn:
        try:
            pg_cur.execute(
                "INSERT INTO dna_audit_trail (id, action, component_id, actor, timestamp, outcome, signature) VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s)",
                ("Anomaly Response Triggered", comp_id, "anomaly-detector", now_str, f"Attempted Mitigation: {attack_type}", "auto-signed-mlflow")
            )
        except Exception as e:
            logging.error(f"PG Update failed: {e}")
            
    # 4. Notify Trust Registry to revoke and Self-Healing Engine to quarantine
    # (Kafka messages hit self-healing, trust override hitting directly)
    try:
        requests.post(f"{TRUST_REGISTRY}/trust/override/{comp_id}", json={"score": 0.0}, timeout=2)
    except:
        pass

@app.on_event("startup")
def startup():
    Thread(target=background_training_loop, daemon=True).start()

@app.post("/anomaly/analyze/{component_id}")
def analyze_component(component_id: str):
    # Simulate receiving live fp vectors, scoring.
    if component_id in models:
        vector = np.random.normal(loc=0.0, scale=1.0, size=(1, 4))
        # inject anomaly 5% chance
        if np.random.random() < 0.05:
            vector = np.random.normal(loc=5.0, scale=2.0, size=(1, 4))
            pred = models[component_id].predict(vector)[0]
            if pred == -1: # Anomaly
                trigger_response(component_id, "Behavioral Mimicry", 0.95)
                return {"status": "anomaly_detected"}
    return {"status": "clean"}

@app.get("/metrics")
def metrics():
    return "dna_anomaly_analyzed_total 1\n"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("ANOMALY_PORT", "8054")))
