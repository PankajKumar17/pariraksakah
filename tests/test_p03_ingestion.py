"""
Unit tests for the CyberShield-X Kafka ingestion pipeline (P03).

Kafka is mocked throughout — no running broker required.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# ──────────────────────────────────────────────
# Kafka Producer tests
# ──────────────────────────────────────────────

class TestCyberShieldKafkaProducer:
    """Tests for kafka_producer.CyberShieldKafkaProducer."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        """Patch confluent_kafka before importing the module."""
        self.mock_producer_cls = MagicMock()
        self.mock_producer_inst = MagicMock()
        self.mock_producer_cls.return_value = self.mock_producer_inst
        self.mock_producer_inst.flush.return_value = 0

        self.mock_sr_client = MagicMock()
        self.mock_avro_ser = MagicMock(side_effect=lambda data, ctx: b"avro-bytes")
        self.mock_str_ser = MagicMock(side_effect=lambda s: s.encode() if s else None)

        patches = {
            "confluent_kafka.Producer": self.mock_producer_cls,
            "confluent_kafka.schema_registry.SchemaRegistryClient": MagicMock(
                return_value=self.mock_sr_client
            ),
            "confluent_kafka.schema_registry.avro.AvroSerializer": MagicMock(
                return_value=self.mock_avro_ser
            ),
            "confluent_kafka.serialization.StringSerializer": MagicMock(
                return_value=self.mock_str_ser
            ),
        }

        self._patchers = []
        for target, mock_obj in patches.items():
            p = patch(target, mock_obj)
            p.start()
            self._patchers.append(p)

        from services.threat_detection.src.ingestion.kafka_producer import (
            CyberShieldKafkaProducer,
            SecurityEvent,
            TOPICS,
        )

        self.CyberShieldKafkaProducer = CyberShieldKafkaProducer
        self.SecurityEvent = SecurityEvent
        self.TOPICS = TOPICS

        yield

        for p in self._patchers:
            p.stop()

    def test_init_creates_producer(self):
        """Producer instance should be created on init."""
        producer = self.CyberShieldKafkaProducer()
        self.mock_producer_cls.assert_called_once()

    def test_produce_valid_topic(self):
        """produce() with a valid topic should call confluent produce()."""
        producer = self.CyberShieldKafkaProducer()
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "NETWORK",
            "source_ip": "10.0.0.1",
        }
        producer.produce("network-events", event)
        self.mock_producer_inst.produce.assert_called_once()

    def test_produce_invalid_topic_raises(self):
        """produce() with an unknown topic should raise ValueError."""
        producer = self.CyberShieldKafkaProducer()
        with pytest.raises(ValueError, match="Unknown topic"):
            producer.produce("invalid-topic", {"event_type": "NETWORK"})

    def test_produce_with_security_event_model(self):
        """produce() should accept a SecurityEvent pydantic model."""
        producer = self.CyberShieldKafkaProducer()
        event = self.SecurityEvent(
            event_type="AUTH",
            source_ip="192.168.1.1",
            user_id="u-123",
        )
        producer.produce("auth-events", event)
        self.mock_producer_inst.produce.assert_called_once()

    def test_produce_sets_default_envelope_fields(self):
        """produce() should set event_id and timestamp if missing."""
        producer = self.CyberShieldKafkaProducer()
        event: dict = {"event_type": "DNS"}
        producer.produce("dns-events", event)
        assert "event_id" in event
        assert "timestamp" in event

    def test_produce_batch(self):
        """produce_batch() should call produce() for each event."""
        producer = self.CyberShieldKafkaProducer()
        events = [
            {"event_type": "NETWORK", "source_ip": f"10.0.0.{i}"}
            for i in range(5)
        ]
        producer.produce_batch("network-events", events)
        assert self.mock_producer_inst.produce.call_count == 5
        self.mock_producer_inst.flush.assert_called()

    def test_retry_on_buffer_error(self):
        """produce() should retry on BufferError."""
        self.mock_producer_inst.produce.side_effect = [BufferError, None]
        producer = self.CyberShieldKafkaProducer()
        event = {"event_type": "NETWORK", "source_ip": "10.0.0.1"}
        producer.produce("network-events", event)
        assert self.mock_producer_inst.produce.call_count == 2

    def test_flush_returns_remaining(self):
        """flush() should return 0 when all messages are delivered."""
        producer = self.CyberShieldKafkaProducer()
        assert producer.flush() == 0

    def test_stats_property(self):
        """stats property should return dict with delivered and failed."""
        producer = self.CyberShieldKafkaProducer()
        s = producer.stats
        assert "delivered" in s
        assert "failed" in s

    def test_close(self):
        """close() should flush remaining messages."""
        producer = self.CyberShieldKafkaProducer()
        producer.close()
        self.mock_producer_inst.flush.assert_called()


# ──────────────────────────────────────────────
# eBPF Sensor tests
# ──────────────────────────────────────────────

class TestEBPFSensor:
    """Tests for ebpf_sensor.EBPFSensor (mocked eBPF / bcc)."""

    @pytest.fixture
    def mock_producer(self):
        producer = MagicMock()
        producer.produce = MagicMock()
        producer.flush = MagicMock()
        return producer

    def test_sensor_init(self, mock_producer):
        from services.threat_detection.src.ingestion.ebpf_sensor import EBPFSensor

        sensor = EBPFSensor(kafka_producer=mock_producer, hostname="test-host")
        assert sensor._hostname == "test-host"
        assert sensor._running is False

    def test_build_execve_event(self, mock_producer):
        from services.threat_detection.src.ingestion.ebpf_sensor import (
            EBPFSensor,
            ExecveEvent,
        )
        import ctypes as ct

        sensor = EBPFSensor(kafka_producer=mock_producer, hostname="node-01")
        evt = ExecveEvent()
        evt.pid = 1234
        evt.uid = 1000
        evt.comm = b"python3"
        evt.filename = b"/usr/bin/python3"
        evt.ts = 0

        result = sensor._build_execve_event(evt)
        assert result["event_type"] == "PROCESS"
        assert result["pid"] == 1234
        assert result["hostname"] == "node-01"
        assert "execve" in result["raw_payload"]

    def test_build_connect_event(self, mock_producer):
        from services.threat_detection.src.ingestion.ebpf_sensor import (
            EBPFSensor,
            ConnectEvent,
            _ip_from_int,
            _ntohs,
        )

        sensor = EBPFSensor(kafka_producer=mock_producer, hostname="node-01")
        evt = ConnectEvent()
        evt.pid = 5678
        evt.uid = 0
        evt.comm = b"curl"
        # 8.8.8.8 in network order: struct.unpack("!I", inet_aton("8.8.8.8"))
        evt.daddr = struct.unpack("<I", bytes([8, 8, 8, 8]))[0]
        evt.dport = struct.unpack("<H", struct.pack("!H", 443))[0]
        evt.ts = 0

        result = sensor._build_connect_event(evt)
        assert result["event_type"] == "NETWORK"
        assert result["destination_ip"] == "8.8.8.8"
        assert result["destination_port"] == 443

    def test_build_openat_event(self, mock_producer):
        from services.threat_detection.src.ingestion.ebpf_sensor import (
            EBPFSensor,
            OpenatEvent,
        )

        sensor = EBPFSensor(kafka_producer=mock_producer, hostname="node-01")
        evt = OpenatEvent()
        evt.pid = 999
        evt.uid = 0
        evt.comm = b"cat"
        evt.filename = b"/etc/shadow"
        evt.ts = 0

        result = sensor._build_openat_event(evt)
        assert result["event_type"] == "FILE"
        assert "/etc/shadow" in result["raw_payload"]

    def test_start_without_bcc_falls_back(self, mock_producer):
        """start() should log error and return if bcc is not importable."""
        from services.threat_detection.src.ingestion.ebpf_sensor import EBPFSensor

        sensor = EBPFSensor(kafka_producer=mock_producer)

        with patch.dict("sys.modules", {"bcc": None}):
            with patch(
                "services.threat_detection.src.ingestion.ebpf_sensor.EBPFSensor.start"
            ) as mock_start:
                mock_start.return_value = None
                sensor.start()

    def test_stop_sets_running_false(self, mock_producer):
        from services.threat_detection.src.ingestion.ebpf_sensor import EBPFSensor

        sensor = EBPFSensor(kafka_producer=mock_producer)
        sensor._running = True
        sensor.stop()
        assert sensor._running is False

    def test_ip_from_int(self):
        from services.threat_detection.src.ingestion.ebpf_sensor import _ip_from_int

        # 127.0.0.1 stored in little-endian as 0x0100007f
        assert _ip_from_int(0x0100007F) == "127.0.0.1"

    def test_ntohs(self):
        from services.threat_detection.src.ingestion.ebpf_sensor import _ntohs

        assert _ntohs(0xBB01) == 0x01BB  # port 443 swapped


# ──────────────────────────────────────────────
# NetFlow Collector tests
# ──────────────────────────────────────────────

class TestNetFlowParser:
    """Tests for netflow_collector.NetFlowV9Parser."""

    def test_parse_empty_packet(self):
        from services.threat_detection.src.ingestion.netflow_collector import (
            NetFlowV9Parser,
        )

        parser = NetFlowV9Parser()
        assert parser.parse_packet(b"", ("127.0.0.1", 2055)) == []

    def test_parse_short_packet(self):
        from services.threat_detection.src.ingestion.netflow_collector import (
            NetFlowV9Parser,
        )

        parser = NetFlowV9Parser()
        assert parser.parse_packet(b"\x00\x09" + b"\x00" * 10, ("127.0.0.1", 2055)) == []

    def test_parse_unknown_version(self):
        from services.threat_detection.src.ingestion.netflow_collector import (
            NetFlowV9Parser,
        )

        parser = NetFlowV9Parser()
        pkt = struct.pack("!H", 99) + b"\x00" * 18
        assert parser.parse_packet(pkt, ("127.0.0.1", 2055)) == []

    def test_template_caching(self):
        """A template flowset should be cached for later data parsing."""
        from services.threat_detection.src.ingestion.netflow_collector import (
            NetFlowV9Parser,
            FIELD_IPV4_SRC_ADDR,
            FIELD_IPV4_DST_ADDR,
            FIELD_L4_SRC_PORT,
            FIELD_L4_DST_PORT,
            FIELD_PROTOCOL,
            FIELD_IN_BYTES,
            FIELD_IN_PKTS,
        )

        parser = NetFlowV9Parser()

        # Build a v9 packet with a template flowset
        template_id = 256
        fields = [
            (FIELD_IPV4_SRC_ADDR, 4),
            (FIELD_IPV4_DST_ADDR, 4),
            (FIELD_L4_SRC_PORT, 2),
            (FIELD_L4_DST_PORT, 2),
            (FIELD_PROTOCOL, 1),
            (FIELD_IN_BYTES, 4),
            (FIELD_IN_PKTS, 4),
        ]
        field_count = len(fields)

        # Template FlowSet (id=0)
        tmpl_body = struct.pack("!HH", template_id, field_count)
        for ftype, flen in fields:
            tmpl_body += struct.pack("!HH", ftype, flen)
        tmpl_flowset = struct.pack("!HH", 0, 4 + len(tmpl_body)) + tmpl_body

        # V9 header: version, count, uptime, unixsecs, seq, source_id
        header = struct.pack("!HHIIII", 9, 1, 1000, int(time.time()), 1, 1)
        pkt = header + tmpl_flowset

        records = parser.parse_packet(pkt, ("10.0.0.1", 2055))
        assert records == []  # template only, no data records yet
        assert 256 in parser._templates.get(1, {})


class TestNetFlowCollector:
    """Tests for netflow_collector.NetFlowCollector."""

    @pytest.fixture
    def mock_producer(self):
        p = MagicMock()
        p.produce = MagicMock()
        p.flush = MagicMock()
        return p

    def test_collector_init(self, mock_producer):
        from services.threat_detection.src.ingestion.netflow_collector import (
            NetFlowCollector,
        )

        collector = NetFlowCollector(kafka_producer=mock_producer)
        assert collector._port == 2055
        assert collector.total_flows == 0

    def test_process_record_produces_to_kafka(self, mock_producer):
        from services.threat_detection.src.ingestion.netflow_collector import (
            NetFlowCollector,
            FlowRecord,
        )

        collector = NetFlowCollector(kafka_producer=mock_producer)
        rec = FlowRecord(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            bytes_sent=1024,
            bytes_received=2048,
            packets_sent=10,
            packets_received=15,
            duration_ms=500,
        )
        collector._process_record(rec)
        mock_producer.produce.assert_called_once()
        call_args = mock_producer.produce.call_args
        assert call_args[0][0] == "network-events"

    def test_process_record_with_geoip(self, mock_producer):
        from services.threat_detection.src.ingestion.netflow_collector import (
            NetFlowCollector,
            FlowRecord,
            GeoIPEnricher,
        )

        geo = MagicMock(spec=GeoIPEnricher)
        geo.lookup.return_value = {"country": "US", "city": "Ashburn", "asn": 14618}

        collector = NetFlowCollector(
            kafka_producer=mock_producer, geoip_enricher=geo
        )
        rec = FlowRecord(
            src_ip="8.8.8.8",
            dst_ip="1.1.1.1",
            src_port=80,
            dst_port=12345,
            protocol=6,
            bytes_sent=100,
            bytes_received=200,
            packets_sent=1,
            packets_received=2,
            duration_ms=10,
        )
        collector._process_record(rec)
        assert geo.lookup.call_count == 2  # src + dst

    @pytest.mark.asyncio
    async def test_start_stop(self, mock_producer):
        from services.threat_detection.src.ingestion.netflow_collector import (
            NetFlowCollector,
        )

        collector = NetFlowCollector(
            kafka_producer=mock_producer,
            listen_host="127.0.0.1",
            listen_port=0,  # OS-assigned port
        )
        await collector.start()
        assert collector._transport is not None
        await collector.stop()
        mock_producer.flush.assert_called()


class TestGeoIPEnricher:
    """Tests for GeoIPEnricher."""

    def test_private_ip_returns_private(self):
        from services.threat_detection.src.ingestion.netflow_collector import (
            GeoIPEnricher,
        )

        geo = GeoIPEnricher(city_db_path="", asn_db_path="")
        result = geo.lookup("192.168.1.1")
        assert result.get("country") == "PRIVATE"

    def test_loopback_returns_private(self):
        from services.threat_detection.src.ingestion.netflow_collector import (
            GeoIPEnricher,
        )

        geo = GeoIPEnricher(city_db_path="", asn_db_path="")
        result = geo.lookup("127.0.0.1")
        assert result.get("country") == "PRIVATE"

    def test_invalid_ip_returns_empty(self):
        from services.threat_detection.src.ingestion.netflow_collector import (
            GeoIPEnricher,
        )

        geo = GeoIPEnricher(city_db_path="", asn_db_path="")
        result = geo.lookup("not-an-ip")
        assert result == {}


class TestProtoMap:
    """Test protocol map."""

    def test_common_protocols(self):
        from services.threat_detection.src.ingestion.netflow_collector import PROTO_MAP

        assert PROTO_MAP[6] == "TCP"
        assert PROTO_MAP[17] == "UDP"
        assert PROTO_MAP[1] == "ICMP"
