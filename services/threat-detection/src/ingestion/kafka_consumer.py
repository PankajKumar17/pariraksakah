"""Kafka consumer for threat-detection streaming ingestion."""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from confluent_kafka import Consumer, KafkaError

logger = logging.getLogger("threat-detection.kafka-consumer")


class ThreatKafkaConsumer:
    """Background Kafka consumer for network/auth event topics."""

    def __init__(
        self,
        bootstrap_servers: str,
        group_id: str = "threat-detection-stream",
        topics: Optional[List[str]] = None,
        poll_timeout: float = 1.0,
    ) -> None:
        self._topics = topics or ["network-events", "endpoint-events", "auth-events"]
        self._poll_timeout = poll_timeout
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[str, Dict[str, Any]], None]] = None

        config = {
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
            "session.timeout.ms": 10000,
        }
        self._consumer = Consumer(config)

    def start(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Start background consume loop."""
        if self._running:
            return

        self._callback = callback
        self._running = True
        self._consumer.subscribe(self._topics)
        self._thread = threading.Thread(target=self._run, name="threat-kafka-consumer", daemon=True)
        self._thread.start()
        logger.info("Kafka consumer started. topics=%s", self._topics)

    def stop(self) -> None:
        """Stop background consume loop and close consumer."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        try:
            self._consumer.close()
        except Exception as e:
            logger.warning("Kafka consumer close error: %s", e)
        logger.info("Kafka consumer stopped")

    def _run(self) -> None:
        """Poll loop for Kafka messages."""
        while self._running:
            try:
                msg = self._consumer.poll(self._poll_timeout)
                if msg is None:
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.warning("Kafka consume error: %s", msg.error())
                    continue

                topic = msg.topic()
                payload = self._decode_message(msg.value())
                if payload is None:
                    continue

                if self._callback:
                    self._callback(topic, payload)

            except Exception as e:
                logger.exception("Kafka consume loop failure: %s", e)
                time.sleep(1)

    @staticmethod
    def _decode_message(raw: Any) -> Optional[Dict[str, Any]]:
        """Decode Kafka message payload into dict when possible."""
        if raw is None:
            return None

        if isinstance(raw, dict):
            return raw

        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except Exception:
                return None

        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None

        return None
