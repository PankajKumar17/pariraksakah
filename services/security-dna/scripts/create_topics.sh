#!/bin/bash

# Configuration
KAFKA_BROKER=${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}

# Topics to create
TOPICS=(
  "dna.identity.issued"
  "dna.identity.verified"
  "dna.identity.revoked"
  "dna.fingerprint.updates"
  "dna.anomaly.detected"
  "dna.trust.scores"
  "dna.audit.trail"
)

# Wait for Kafka
echo "Waiting for Kafka at $KAFKA_BROKER..."
while ! nc -z ${KAFKA_BROKER%:*} ${KAFKA_BROKER#*:} 2>/dev/null; do
  sleep 2
done
echo "Kafka is reachable."

for topic in "${TOPICS[@]}"; do
  echo "Creating topic: $topic"
  kafka-topics.sh --create --if-not-exists --bootstrap-server "$KAFKA_BROKER" --topic "$topic" --partitions 3 --replication-factor 1
done

echo "Topic creation completed."
