"""
CyberShield-X — Kafka Event Producer
Production Kafka producer with Avro serialization, retry logic,
and schema registry integration.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from confluent_kafka import Producer, KafkaError, KafkaException
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer
from confluent_kafka.serialization import (
    SerializationContext,
    MessageField,
    StringSerializer,
)
from pydantic import BaseModel, Field

logger = logging.getLogger("cybershield.ingestion.kafka_producer")

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

TOPICS = (
    "network-events",
    "endpoint-events",
    "auth-events",
    "dns-events",
)

DEFAULT_KAFKA_CONFIG = {
    "bootstrap.servers": "kafka-0:9092,kafka-1:9092,kafka-2:9092",
    "client.id": "cybershield-threat-detection",
    "acks": "all",
    "enable.idempotence": True,
    "max.in.flight.requests.per.connection": 5,
    "retries": 10,
    "retry.backoff.ms": 200,
    "linger.ms": 5,
    "batch.size": 65536,
    "compression.type": "lz4",
    "request.timeout.ms": 30000,
    "delivery.timeout.ms": 120000,
}

SCHEMA_REGISTRY_URL = "http://schema-registry:8081"

# ──────────────────────────────────────────────
# Avro Schema (inline, must match event_schema.avsc)
# ──────────────────────────────────────────────

SECURITY_EVENT_SCHEMA = """{
    "type": "record",
    "name": "SecurityEvent",
    "namespace": "com.cybershield.events",
    "fields": [
        {"name": "event_id", "type": "string"},
        {"name": "timestamp", "type": "string"},
        {"name": "event_type", "type": {"type": "enum", "name": "EventType",
         "symbols": ["NETWORK", "ENDPOINT", "AUTH", "DNS", "FILE", "PROCESS"]}},
        {"name": "source_ip", "type": ["null", "string"], "default": null},
        {"name": "destination_ip", "type": ["null", "string"], "default": null},
        {"name": "source_port", "type": ["null", "int"], "default": null},
        {"name": "destination_port", "type": ["null", "int"], "default": null},
        {"name": "protocol", "type": ["null", "string"], "default": null},
        {"name": "user_id", "type": ["null", "string"], "default": null},
        {"name": "hostname", "type": ["null", "string"], "default": null},
        {"name": "process_name", "type": ["null", "string"], "default": null},
        {"name": "pid", "type": ["null", "int"], "default": null},
        {"name": "bytes_sent", "type": ["null", "long"], "default": null},
        {"name": "bytes_received", "type": ["null", "long"], "default": null},
        {"name": "duration_ms", "type": ["null", "long"], "default": null},
        {"name": "severity_score", "type": ["null", "float"], "default": null},
        {"name": "raw_payload", "type": ["null", "string"], "default": null}
    ]
}"""


# ──────────────────────────────────────────────
# Event Model
# ──────────────────────────────────────────────

class SecurityEvent(BaseModel):
    """Pydantic model for a CyberShield-X security event."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str  # NETWORK | ENDPOINT | AUTH | DNS | FILE | PROCESS
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user_id: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    duration_ms: Optional[int] = None
    severity_score: Optional[float] = None
    raw_payload: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return dict suitable for Avro serialization."""
        return self.model_dump()


# ──────────────────────────────────────────────
# Producer
# ──────────────────────────────────────────────

class CyberShieldKafkaProducer:
    """Production Kafka producer with Avro serialization and retry logic.

    Parameters
    ----------
    kafka_config : dict, optional
        Confluent Kafka producer configuration overrides.
    schema_registry_url : str, optional
        URL of the Confluent Schema Registry.
    max_retries : int
        Maximum number of produce retries (default 5).
    base_backoff_s : float
        Base backoff in seconds for exponential retry (default 0.5).
    """

    def __init__(
        self,
        kafka_config: Optional[Dict[str, Any]] = None,
        schema_registry_url: str = SCHEMA_REGISTRY_URL,
        max_retries: int = 5,
        base_backoff_s: float = 0.5,
    ) -> None:
        self._max_retries = max_retries
        self._base_backoff = base_backoff_s

        # Merge user config with defaults
        cfg = {**DEFAULT_KAFKA_CONFIG, **(kafka_config or {})}
        self._producer: Producer = Producer(cfg)

        # Schema Registry + Avro serializer
        sr_client = SchemaRegistryClient({"url": schema_registry_url})
        self._avro_serializer = AvroSerializer(
            sr_client,
            SECURITY_EVENT_SCHEMA,
            to_dict=lambda obj, ctx: obj,
        )
        self._string_serializer = StringSerializer("utf_8")

        # Delivery stats
        self._delivered = 0
        self._failed = 0

        logger.info(
            "CyberShieldKafkaProducer initialised — brokers=%s, schema_registry=%s",
            cfg["bootstrap.servers"],
            schema_registry_url,
        )

    # ── delivery callback ──
    def _on_delivery(self, err: Optional[KafkaError], msg: Any) -> None:
        """Called once per produced message."""
        if err is not None:
            self._failed += 1
            logger.error("Delivery failed: topic=%s err=%s", msg.topic(), err)
        else:
            self._delivered += 1
            logger.debug(
                "Delivered: topic=%s partition=%d offset=%d",
                msg.topic(),
                msg.partition(),
                msg.offset(),
            )

    # ── produce with retry ──
    def produce(
        self,
        topic: str,
        event: SecurityEvent | Dict[str, Any],
        key: Optional[str] = None,
    ) -> None:
        """Produce a single event to Kafka with exponential backoff retry.

        Parameters
        ----------
        topic : str
            Kafka topic name (must be one of TOPICS).
        event : SecurityEvent | dict
            The security event payload.
        key : str, optional
            Kafka message key (defaults to event source_ip).
        """
        if topic not in TOPICS:
            raise ValueError(f"Unknown topic '{topic}'. Valid: {TOPICS}")

        if isinstance(event, SecurityEvent):
            data = event.to_dict()
        else:
            data = event

        # Ensure mandatory envelope fields
        data.setdefault("event_id", str(uuid.uuid4()))
        data.setdefault(
            "timestamp", datetime.now(timezone.utc).isoformat()
        )
        if "source_ip" in data and key is None:
            key = data["source_ip"]

        attempt = 0
        while attempt <= self._max_retries:
            try:
                self._producer.produce(
                    topic=topic,
                    key=self._string_serializer(key) if key else None,
                    value=self._avro_serializer(
                        data,
                        SerializationContext(topic, MessageField.VALUE),
                    ),
                    on_delivery=self._on_delivery,
                )
                self._producer.poll(0)
                return
            except BufferError:
                logger.warning(
                    "Local queue full (attempt %d/%d). Flushing…",
                    attempt + 1,
                    self._max_retries,
                )
                self._producer.flush(timeout=10)
            except KafkaException as exc:
                backoff = self._base_backoff * (2**attempt)
                logger.warning(
                    "Produce error (attempt %d/%d): %s — retrying in %.1fs",
                    attempt + 1,
                    self._max_retries,
                    exc,
                    backoff,
                )
                time.sleep(backoff)
            attempt += 1

        logger.error(
            "Failed to produce event after %d retries: topic=%s event_id=%s",
            self._max_retries,
            topic,
            data.get("event_id"),
        )
        self._failed += 1

    # ── batch produce ──
    def produce_batch(
        self,
        topic: str,
        events: list[SecurityEvent | Dict[str, Any]],
    ) -> None:
        """Produce a batch of events.

        Parameters
        ----------
        topic : str
            Target Kafka topic.
        events : list
            List of SecurityEvent or dict payloads.
        """
        for event in events:
            self.produce(topic, event)
        self._producer.flush(timeout=30)

    # ── housekeeping ──
    def flush(self, timeout: float = 30.0) -> int:
        """Flush pending messages and return number remaining."""
        remaining = self._producer.flush(timeout=timeout)
        logger.info(
            "Flush complete — delivered=%d failed=%d remaining=%d",
            self._delivered,
            self._failed,
            remaining,
        )
        return remaining

    @property
    def stats(self) -> Dict[str, int]:
        """Return delivery statistics."""
        return {"delivered": self._delivered, "failed": self._failed}

    def close(self) -> None:
        """Graceful shutdown: flush remaining messages."""
        self.flush(timeout=60)
        logger.info("Producer closed.")
