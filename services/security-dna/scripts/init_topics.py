import os
import json
import requests
from time import sleep

KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
SCHEMA_REGISTRY_URL = os.getenv("SCHEMA_REGISTRY_URL", "http://localhost:8081")

# The schemas and their corresponding subjects (topics)
SCHEMAS = {
    "dna.identity.issued": "dna_identity_issued.avsc",
    "dna.identity.verified": "dna_identity_verified.avsc",
    "dna.identity.revoked": "dna_identity_revoked.avsc",
    "dna.fingerprint.updates": "dna_fingerprint_updates.avsc",
    "dna.anomaly.detected": "dna_anomaly_detected.avsc",
    "dna.trust.scores": "dna_trust_scores.avsc",
    "dna.audit.trail": "dna_audit_trail.avsc"
}

def register_schema(topic, filename):
    subject = f"{topic}-value"
    filepath = os.path.join(os.path.dirname(__file__), "..", "kafka-schemas", filename)
    with open(filepath, "r") as f:
        schema_str = f.read()

    payload = {
        "schema": schema_str
    }
    headers = {"Content-Type": "application/vnd.schemaregistry.v1+json"}
    url = f"{SCHEMA_REGISTRY_URL}/subjects/{subject}/versions"
    
    print(f"Registering schema for {topic}...")
    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code in (200, 201):
            print(f"Successfully registered schema for: {topic} - ID: {response.json()['id']}")
        else:
            print(f"Failed to register schema for {topic}: {response.text}")
    except Exception as e:
        print(f"Exception for {topic}: {e}")

if __name__ == "__main__":
    # Wait for Schema Registry
    for _ in range(10):
        try:
            r = requests.get(SCHEMA_REGISTRY_URL)
            if r.status_code == 200:
                print("Schema Registry is up!")
                break
        except requests.ConnectionError:
            print("Waiting for schema registry...")
            sleep(5)
            
    for topic, filename in SCHEMAS.items():
        register_schema(topic, filename)
