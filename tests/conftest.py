"""Pytest bootstrap for repo-wide import stability on local/CI runs."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVICES_DIR = ROOT / "services"
THREAT_DASH_DIR = SERVICES_DIR / "threat-detection"


def _ensure_repo_on_syspath() -> None:
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


def _register_threat_detection_alias() -> None:
    """Map services.threat_detection -> services/threat-detection for tests."""
    services_mod = sys.modules.get("services")
    if services_mod is None:
        services_mod = types.ModuleType("services")
        services_mod.__path__ = [str(SERVICES_DIR)]
        sys.modules["services"] = services_mod

    alias_name = "services.threat_detection"
    alias_mod = sys.modules.get(alias_name)
    if alias_mod is None:
        alias_mod = types.ModuleType(alias_name)
        alias_mod.__path__ = [str(THREAT_DASH_DIR)]
        sys.modules[alias_name] = alias_mod

    setattr(services_mod, "threat_detection", alias_mod)


def _install_confluent_kafka_stub() -> None:
    """Install lightweight stub modules so patch() targets can resolve imports."""
    if "confluent_kafka" in sys.modules:
        return

    ck = types.ModuleType("confluent_kafka")

    class KafkaError(Exception):
        pass

    class KafkaException(Exception):
        pass

    class Producer:
        def __init__(self, *_args, **_kwargs):
            pass

        def produce(self, *_args, **_kwargs):
            return None

        def poll(self, *_args, **_kwargs):
            return 0

        def flush(self, *_args, **_kwargs):
            return 0

    ck.KafkaError = KafkaError
    ck.KafkaException = KafkaException
    ck.Producer = Producer

    schema_registry = types.ModuleType("confluent_kafka.schema_registry")

    class SchemaRegistryClient:
        def __init__(self, *_args, **_kwargs):
            pass

    schema_registry.SchemaRegistryClient = SchemaRegistryClient

    avro = types.ModuleType("confluent_kafka.schema_registry.avro")

    class AvroSerializer:
        def __init__(self, *_args, **_kwargs):
            pass

        def __call__(self, value, _ctx):
            return json.dumps(value).encode("utf-8") if value is not None else None

    avro.AvroSerializer = AvroSerializer

    serialization = types.ModuleType("confluent_kafka.serialization")

    class MessageField:
        VALUE = "value"

    class SerializationContext:
        def __init__(self, topic, field):
            self.topic = topic
            self.field = field

    class StringSerializer:
        def __init__(self, _encoding="utf_8"):
            pass

        def __call__(self, value):
            return value.encode("utf-8") if value is not None else None

    serialization.MessageField = MessageField
    serialization.SerializationContext = SerializationContext
    serialization.StringSerializer = StringSerializer

    sys.modules["confluent_kafka"] = ck
    sys.modules["confluent_kafka.schema_registry"] = schema_registry
    sys.modules["confluent_kafka.schema_registry.avro"] = avro
    sys.modules["confluent_kafka.serialization"] = serialization


_ensure_repo_on_syspath()
_register_threat_detection_alias()
_install_confluent_kafka_stub()


@pytest.fixture(autouse=True)
def _clear_cached_ingestion_modules():
    """Avoid stale symbol bindings when tests patch external Kafka symbols."""
    sys.modules.pop("services.threat_detection.src.ingestion.kafka_producer", None)
    yield
