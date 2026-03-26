#!/bin/bash
# Quantum Security Suite: Kafka Topic Creation + Avro Schema Registration
set -euo pipefail

KAFKA_BROKER="${KAFKA_BOOTSTRAP_SERVERS:-kafka:9092}"
SCHEMA_REGISTRY="${SCHEMA_REGISTRY_URL:-http://schema-registry:8081}"

echo "═══ Creating Quantum Kafka Topics ═══"

for TOPIC in \
  quantum.crypto.keyexchange \
  quantum.crypto.violation \
  quantum.qkd.session \
  quantum.qkd.eavesdrop \
  quantum.rng.generated \
  quantum.rng.quality \
  quantum.threat.quantum.detected \
  quantum.ml.anomaly \
  quantum.supplychain.verified \
  quantum.supplychain.violation \
  quantum.attack.simulation \
  quantum.zerotrust.verification \
  quantum.zerotrust.violation \
  quantum.audit.trail
do
  kafka-topics.sh --create --if-not-exists --topic "$TOPIC" \
    --bootstrap-server "$KAFKA_BROKER" --replication-factor 1 --partitions 6 \
    --config retention.ms=604800000 --config cleanup.policy=delete
done

# Make audit trail compacted and infinite retention
kafka-topics.sh --alter --topic quantum.audit.trail \
  --bootstrap-server "$KAFKA_BROKER" \
  --config retention.ms=-1 --config cleanup.policy=compact

echo "═══ Registering Avro Schemas ═══"

# quantum.crypto.keyexchange-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.crypto.keyexchange-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"QuantumKeyExchange\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"key_id\",\"type\":\"string\"},{\"name\":\"algorithm\",\"type\":\"string\"},{\"name\":\"key_size_bits\",\"type\":\"int\"},{\"name\":\"generation_method\",\"type\":\"string\"},{\"name\":\"entropy_source\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.crypto.violation-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.crypto.violation-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"CryptoViolation\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"violation_id\",\"type\":\"string\"},{\"name\":\"service\",\"type\":\"string\"},{\"name\":\"classical_algorithm\",\"type\":\"string\"},{\"name\":\"recommended_replacement\",\"type\":\"string\"},{\"name\":\"severity\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.qkd.session-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.qkd.session-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"QKDSession\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"session_id\",\"type\":\"string\"},{\"name\":\"protocol\",\"type\":\"string\"},{\"name\":\"alice_endpoint\",\"type\":\"string\"},{\"name\":\"bob_endpoint\",\"type\":\"string\"},{\"name\":\"qber_rate\",\"type\":\"double\"},{\"name\":\"key_bits_generated\",\"type\":\"int\"},{\"name\":\"eavesdrop_detected\",\"type\":\"boolean\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.qkd.eavesdrop-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.qkd.eavesdrop-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"QKDEavesdrop\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"session_id\",\"type\":\"string\"},{\"name\":\"qber_rate\",\"type\":\"double\"},{\"name\":\"threshold\",\"type\":\"double\"},{\"name\":\"eve_intercept_pct\",\"type\":\"double\"},{\"name\":\"action_taken\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.rng.generated-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.rng.generated-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"RNGGenerated\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"batch_id\",\"type\":\"string\"},{\"name\":\"entropy_source\",\"type\":\"string\"},{\"name\":\"bits_generated\",\"type\":\"int\"},{\"name\":\"randomness_score\",\"type\":\"double\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.rng.quality-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.rng.quality-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"RNGQuality\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"batch_id\",\"type\":\"string\"},{\"name\":\"test_name\",\"type\":\"string\"},{\"name\":\"p_value\",\"type\":\"double\"},{\"name\":\"passed\",\"type\":\"boolean\"},{\"name\":\"overall_score\",\"type\":\"double\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.threat.quantum.detected-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.threat.quantum.detected-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"QuantumThreatDetected\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"detection_id\",\"type\":\"string\"},{\"name\":\"threat_type\",\"type\":\"string\"},{\"name\":\"quantum_algorithm_used\",\"type\":\"string\"},{\"name\":\"classical_comparison_score\",\"type\":\"double\"},{\"name\":\"quantum_confidence_score\",\"type\":\"double\"},{\"name\":\"speed_improvement_factor\",\"type\":\"double\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.ml.anomaly-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.ml.anomaly-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"QuantumMLAnomaly\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"model_id\",\"type\":\"string\"},{\"name\":\"circuit_depth\",\"type\":\"int\"},{\"name\":\"qubit_count\",\"type\":\"int\"},{\"name\":\"anomaly_score\",\"type\":\"double\"},{\"name\":\"classical_baseline_score\",\"type\":\"double\"},{\"name\":\"quantum_advantage_ratio\",\"type\":\"double\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.supplychain.verified-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.supplychain.verified-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"SupplyChainVerified\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"artifact_id\",\"type\":\"string\"},{\"name\":\"artifact_type\",\"type\":\"string\"},{\"name\":\"artifact_hash\",\"type\":\"string\"},{\"name\":\"quantum_signature\",\"type\":\"string\"},{\"name\":\"verification_result\",\"type\":\"string\"},{\"name\":\"tamper_detected\",\"type\":\"boolean\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.supplychain.violation-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.supplychain.violation-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"SupplyChainViolation\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"artifact_id\",\"type\":\"string\"},{\"name\":\"violation_type\",\"type\":\"string\"},{\"name\":\"expected_hash\",\"type\":\"string\"},{\"name\":\"actual_hash\",\"type\":\"string\"},{\"name\":\"severity\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.attack.simulation-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.attack.simulation-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"AttackSimulation\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"simulation_id\",\"type\":\"string\"},{\"name\":\"attack_type\",\"type\":\"string\"},{\"name\":\"quantum_algorithm\",\"type\":\"string\"},{\"name\":\"target_crypto\",\"type\":\"string\"},{\"name\":\"success_probability\",\"type\":\"double\"},{\"name\":\"time_to_break_estimate\",\"type\":\"string\"},{\"name\":\"mitigation_recommended\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.zerotrust.verification-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.zerotrust.verification-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"ZeroTrustVerification\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"verification_id\",\"type\":\"string\"},{\"name\":\"subject_id\",\"type\":\"string\"},{\"name\":\"resource_id\",\"type\":\"string\"},{\"name\":\"quantum_entropy_used\",\"type\":\"boolean\"},{\"name\":\"trust_score\",\"type\":\"double\"},{\"name\":\"decision\",\"type\":\"string\"},{\"name\":\"quantum_signature\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.zerotrust.violation-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.zerotrust.violation-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"ZeroTrustViolation\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"verification_id\",\"type\":\"string\"},{\"name\":\"subject_id\",\"type\":\"string\"},{\"name\":\"violation_type\",\"type\":\"string\"},{\"name\":\"trust_score\",\"type\":\"double\"},{\"name\":\"threshold\",\"type\":\"double\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# quantum.audit.trail-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/quantum.audit.trail-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"QuantumAuditTrail\",\"namespace\":\"com.cybershield.quantum\",\"fields\":[{\"name\":\"action\",\"type\":\"string\"},{\"name\":\"quantum_service\",\"type\":\"string\"},{\"name\":\"component\",\"type\":\"string\"},{\"name\":\"outcome\",\"type\":\"string\"},{\"name\":\"quantum_signature\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

echo "═══ All Quantum Kafka topics and schemas registered ═══"
