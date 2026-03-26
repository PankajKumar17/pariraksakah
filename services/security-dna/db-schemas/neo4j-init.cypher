// Neo4j Schema Initializations for Security DNA Platform

// Create indexes and constraints
CREATE CONSTRAINT IF NOT EXISTS FOR (n:ComponentNode) REQUIRE n.id IS UNIQUE;
CREATE INDEX IF NOT EXISTS FOR (n:ComponentNode) ON (n.name);
CREATE INDEX IF NOT EXISTS FOR (n:ComponentNode) ON (n.type);

// Base initialization for docker-compose services
// API Gateway
MERGE (api:ComponentNode {id: 'api-gateway', name: 'API Gateway', type: 'go-service', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (kafka:ComponentNode {id: 'kafka', name: 'Apache Kafka', type: 'message-broker', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (tsdb:ComponentNode {id: 'timescaledb', name: 'TimescaleDB', type: 'database', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (redis:ComponentNode {id: 'redis', name: 'Redis', type: 'cache', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (neo4j:ComponentNode {id: 'neo4j', name: 'Neo4j', type: 'database', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (flink:ComponentNode {id: 'flink', name: 'Flink', type: 'stream-processor', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (mlflow:ComponentNode {id: 'mlflow', name: 'MLFlow', type: 'ml-registry', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (falco:ComponentNode {id: 'falco', name: 'Falco', type: 'security-monitor', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (trivy:ComponentNode {id: 'trivy', name: 'Trivy', type: 'vulnerability-scanner', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (prom:ComponentNode {id: 'prometheus', name: 'Prometheus', type: 'metrics', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (grafana:ComponentNode {id: 'grafana', name: 'Grafana', type: 'dashboard', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (react:ComponentNode {id: 'react-frontend', name: 'React SPA', type: 'frontend', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (healing:ComponentNode {id: 'self-healing', name: 'Self-Healing Engine', type: 'rust-service', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (dna_engine:ComponentNode {id: 'dna-identity-engine', name: 'DNA Identity Engine', type: 'rust-service', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (dna_ca:ComponentNode {id: 'dna-certificate-authority', name: 'DNA CA', type: 'go-service', dna_fingerprint: 'PENDING', trust_score: 100})
MERGE (dna_trust:ComponentNode {id: 'dna-trust-registry', name: 'DNA Trust Registry', type: 'go-service', dna_fingerprint: 'PENDING', trust_score: 100})

// Initial Trust Relationships
MERGE (api)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(kafka)
MERGE (api)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(redis)
MERGE (api)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(tsdb)

MERGE (react)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(api)
MERGE (healing)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(api)
MERGE (dna_ca)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(tsdb)
MERGE (dna_engine)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(tsdb)
MERGE (dna_engine)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(kafka)
MERGE (dna_trust)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(tsdb)
MERGE (dna_trust)-[:TrustRelationship {verified: false, trust_level: 'pending', last_verified: timestamp()}]->(neo4j)
