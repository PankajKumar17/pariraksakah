"""
CyberShield-X — NetFlow v9 / IPFIX Collector
Listens on UDP port 2055, parses NetFlow records, enriches with GeoIP,
and forwards events to the Kafka ``network-events`` topic.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cybershield.ingestion.netflow_collector")

# ──────────────────────────────────────────────
# NetFlow v9 constants & templates
# ──────────────────────────────────────────────

NETFLOW_V9_VERSION = 9
IPFIX_VERSION = 10

# Common field type IDs (RFC 3954 / RFC 7012)
FIELD_IN_BYTES = 1
FIELD_IN_PKTS = 2
FIELD_PROTOCOL = 4
FIELD_SRC_TOS = 5
FIELD_TCP_FLAGS = 6
FIELD_L4_SRC_PORT = 7
FIELD_IPV4_SRC_ADDR = 8
FIELD_SRC_MASK = 9
FIELD_INPUT_SNMP = 10
FIELD_L4_DST_PORT = 11
FIELD_IPV4_DST_ADDR = 12
FIELD_DST_MASK = 13
FIELD_OUTPUT_SNMP = 14
FIELD_LAST_SWITCHED = 21
FIELD_FIRST_SWITCHED = 22
FIELD_OUT_BYTES = 23
FIELD_OUT_PKTS = 24
FIELD_IPV4_NEXT_HOP = 15

# ──────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────


@dataclass
class FlowRecord:
    """Parsed NetFlow record."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration_ms: int
    tcp_flags: int = 0
    tos: int = 0


@dataclass
class EnrichedFlow:
    """NetFlow record enriched with GeoIP and metadata."""

    event_id: str
    timestamp: str
    event_type: str  # always "NETWORK"
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    duration_ms: int
    packets_sent: int
    packets_received: int
    tcp_flags: int
    src_country: Optional[str] = None
    src_city: Optional[str] = None
    src_asn: Optional[int] = None
    dst_country: Optional[str] = None
    dst_city: Optional[str] = None
    dst_asn: Optional[int] = None


PROTO_MAP = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
    51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}


# ──────────────────────────────────────────────
# GeoIP enricher
# ──────────────────────────────────────────────

class GeoIPEnricher:
    """Enrich IP addresses with geolocation and ASN data.

    Uses MaxMind geoip2 databases (GeoLite2-City.mmdb, GeoLite2-ASN.mmdb).
    Falls back gracefully if databases are unavailable.
    """

    def __init__(
        self,
        city_db_path: str = "/usr/share/GeoIP/GeoLite2-City.mmdb",
        asn_db_path: str = "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    ) -> None:
        self._city_reader = None
        self._asn_reader = None
        try:
            import geoip2.database  # type: ignore[import-untyped]

            if city_db_path:
                self._city_reader = geoip2.database.Reader(city_db_path)
                logger.info("GeoIP city DB loaded: %s", city_db_path)
            if asn_db_path:
                self._asn_reader = geoip2.database.Reader(asn_db_path)
                logger.info("GeoIP ASN DB loaded: %s", asn_db_path)
        except Exception as exc:
            logger.warning("GeoIP databases not available (%s). Enrichment disabled.", exc)

    def lookup(self, ip: str) -> Dict[str, Any]:
        """Return geo metadata for an IP address."""
        result: Dict[str, Any] = {}
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                return {"country": "PRIVATE", "city": None, "asn": None}
        except ValueError:
            return result

        if self._city_reader:
            try:
                city_resp = self._city_reader.city(ip)
                result["country"] = city_resp.country.iso_code
                result["city"] = city_resp.city.name
            except Exception:
                pass

        if self._asn_reader:
            try:
                asn_resp = self._asn_reader.asn(ip)
                result["asn"] = asn_resp.autonomous_system_number
            except Exception:
                pass

        return result

    def close(self) -> None:
        """Close database readers."""
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()


# ──────────────────────────────────────────────
# NetFlow v9 parser
# ──────────────────────────────────────────────

class NetFlowV9Parser:
    """Stateful parser for NetFlow v9 (and basic IPFIX) packets.

    Maintains template cache across packets from the same exporter.
    """

    def __init__(self) -> None:
        # templates[source_id][template_id] = [(field_type, field_length), ...]
        self._templates: Dict[int, Dict[int, List[Tuple[int, int]]]] = {}

    def parse_packet(self, data: bytes, addr: Tuple[str, int]) -> List[FlowRecord]:
        """Parse a raw NetFlow v9 / IPFIX UDP packet.

        Parameters
        ----------
        data : bytes
            Raw UDP payload.
        addr : tuple
            Source (ip, port) of the exporter.

        Returns
        -------
        list[FlowRecord]
            Zero or more parsed flow records.
        """
        if len(data) < 20:
            return []

        version = struct.unpack("!H", data[:2])[0]
        if version == NETFLOW_V9_VERSION:
            return self._parse_v9(data, addr)
        elif version == IPFIX_VERSION:
            return self._parse_ipfix(data, addr)
        else:
            logger.debug("Unknown NetFlow version %d from %s", version, addr)
            return []

    def _parse_v9(self, data: bytes, addr: Tuple[str, int]) -> List[FlowRecord]:
        """Parse NetFlow v9 packet."""
        # Header: version(2), count(2), sys_uptime(4), unix_secs(4),
        #         sequence(4), source_id(4) = 20 bytes
        if len(data) < 20:
            return []

        count = struct.unpack("!H", data[2:4])[0]
        sys_uptime = struct.unpack("!I", data[4:8])[0]
        source_id = struct.unpack("!I", data[16:20])[0]
        offset = 20
        records: List[FlowRecord] = []

        self._templates.setdefault(source_id, {})

        flowset_parsed = 0
        while offset < len(data) and flowset_parsed < count:
            if offset + 4 > len(data):
                break
            flowset_id = struct.unpack("!H", data[offset:offset + 2])[0]
            flowset_length = struct.unpack("!H", data[offset + 2:offset + 4])[0]

            if flowset_length < 4:
                break

            flowset_data = data[offset + 4:offset + flowset_length]

            if flowset_id == 0:
                # Template FlowSet
                self._parse_templates(flowset_data, source_id)
            elif flowset_id == 1:
                # Options Template FlowSet (skip)
                pass
            elif flowset_id >= 256:
                # Data FlowSet
                tmpl = self._templates.get(source_id, {}).get(flowset_id)
                if tmpl:
                    records.extend(self._parse_data_flowset(flowset_data, tmpl, sys_uptime))

            offset += flowset_length
            flowset_parsed += 1

        return records

    def _parse_ipfix(self, data: bytes, addr: Tuple[str, int]) -> List[FlowRecord]:
        """Minimal IPFIX parser — reuses v9 logic since field types overlap."""
        # IPFIX header is 16 bytes vs v9's 20
        if len(data) < 16:
            return []
        # Treat similarly with dummy source_id
        return self._parse_v9(data[:2] + data[2:4] + b"\x00" * 4 + data[4:8] + data[8:12] + b"\x00\x00\x00\x01" + data[16:], addr)

    def _parse_templates(self, data: bytes, source_id: int) -> None:
        """Parse and cache templates from a Template FlowSet."""
        offset = 0
        while offset + 4 <= len(data):
            template_id = struct.unpack("!H", data[offset:offset + 2])[0]
            field_count = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4

            fields: List[Tuple[int, int]] = []
            for _ in range(field_count):
                if offset + 4 > len(data):
                    break
                ftype = struct.unpack("!H", data[offset:offset + 2])[0]
                flen = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                fields.append((ftype, flen))
                offset += 4

            if fields:
                self._templates[source_id][template_id] = fields
                logger.debug(
                    "Cached template %d (source=%d) with %d fields",
                    template_id, source_id, len(fields),
                )

    def _parse_data_flowset(
        self,
        data: bytes,
        template: List[Tuple[int, int]],
        sys_uptime: int,
    ) -> List[FlowRecord]:
        """Parse data records using a cached template."""
        record_len = sum(flen for _, flen in template)
        if record_len == 0:
            return []

        records: List[FlowRecord] = []
        offset = 0

        while offset + record_len <= len(data):
            fields: Dict[int, Any] = {}
            pos = offset
            for ftype, flen in template:
                raw = data[pos:pos + flen]
                if ftype in (FIELD_IPV4_SRC_ADDR, FIELD_IPV4_DST_ADDR, FIELD_IPV4_NEXT_HOP):
                    fields[ftype] = str(ipaddress.IPv4Address(raw))
                elif flen <= 4:
                    val = int.from_bytes(raw, "big")
                    fields[ftype] = val
                else:
                    fields[ftype] = raw
                pos += flen

            # Build FlowRecord
            first = fields.get(FIELD_FIRST_SWITCHED, 0)
            last = fields.get(FIELD_LAST_SWITCHED, 0)
            duration = max(0, last - first) if last and first else 0

            rec = FlowRecord(
                src_ip=fields.get(FIELD_IPV4_SRC_ADDR, "0.0.0.0"),
                dst_ip=fields.get(FIELD_IPV4_DST_ADDR, "0.0.0.0"),
                src_port=fields.get(FIELD_L4_SRC_PORT, 0),
                dst_port=fields.get(FIELD_L4_DST_PORT, 0),
                protocol=fields.get(FIELD_PROTOCOL, 0),
                bytes_sent=fields.get(FIELD_IN_BYTES, 0),
                bytes_received=fields.get(FIELD_OUT_BYTES, 0),
                packets_sent=fields.get(FIELD_IN_PKTS, 0),
                packets_received=fields.get(FIELD_OUT_PKTS, 0),
                duration_ms=duration,
                tcp_flags=fields.get(FIELD_TCP_FLAGS, 0),
                tos=fields.get(FIELD_SRC_TOS, 0),
            )
            records.append(rec)
            offset += record_len

        return records


# ──────────────────────────────────────────────
# Async UDP server
# ──────────────────────────────────────────────

class NetFlowCollector:
    """Async NetFlow v9/IPFIX collector.

    Parameters
    ----------
    kafka_producer : object
        ``CyberShieldKafkaProducer`` instance.
    listen_host : str
        Bind address (default ``0.0.0.0``).
    listen_port : int
        UDP port (default 2055).
    geoip_enricher : GeoIPEnricher, optional
        If provided, flows are enriched with geo data.
    """

    def __init__(
        self,
        kafka_producer: Any,
        listen_host: str = "0.0.0.0",
        listen_port: int = 2055,
        geoip_enricher: Optional[GeoIPEnricher] = None,
    ) -> None:
        self._producer = kafka_producer
        self._host = listen_host
        self._port = listen_port
        self._geo = geoip_enricher
        self._parser = NetFlowV9Parser()
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._total_flows = 0

    class _Protocol(asyncio.DatagramProtocol):
        """Internal UDP protocol handler."""

        def __init__(self, collector: "NetFlowCollector") -> None:
            self._collector = collector

        def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
            records = self._collector._parser.parse_packet(data, addr)
            for rec in records:
                self._collector._process_record(rec)
            self._collector._total_flows += len(records)

        def error_received(self, exc: Exception) -> None:
            logger.error("UDP error: %s", exc)

    def _process_record(self, record: FlowRecord) -> None:
        """Enrich and forward a single flow record to Kafka."""
        enriched = EnrichedFlow(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="NETWORK",
            source_ip=record.src_ip,
            destination_ip=record.dst_ip,
            source_port=record.src_port,
            destination_port=record.dst_port,
            protocol=PROTO_MAP.get(record.protocol, str(record.protocol)),
            bytes_sent=record.bytes_sent,
            bytes_received=record.bytes_received,
            duration_ms=record.duration_ms,
            packets_sent=record.packets_sent,
            packets_received=record.packets_received,
            tcp_flags=record.tcp_flags,
        )

        # GeoIP enrichment
        if self._geo:
            src_geo = self._geo.lookup(record.src_ip)
            dst_geo = self._geo.lookup(record.dst_ip)
            enriched.src_country = src_geo.get("country")
            enriched.src_city = src_geo.get("city")
            enriched.src_asn = src_geo.get("asn")
            enriched.dst_country = dst_geo.get("country")
            enriched.dst_city = dst_geo.get("city")
            enriched.dst_asn = dst_geo.get("asn")

        self._producer.produce("network-events", asdict(enriched))

    async def start(self) -> None:
        """Start the UDP listener."""
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self._Protocol(self),
            local_addr=(self._host, self._port),
        )
        logger.info("NetFlow collector listening on %s:%d", self._host, self._port)

    async def stop(self) -> None:
        """Stop the collector and flush Kafka."""
        if self._transport:
            self._transport.close()
        self._producer.flush(timeout=10)
        if self._geo:
            self._geo.close()
        logger.info(
            "NetFlow collector stopped. Total flows processed: %d",
            self._total_flows,
        )

    @property
    def total_flows(self) -> int:
        """Number of flow records processed."""
        return self._total_flows


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────

async def run_collector() -> None:
    """CLI entrypoint for the NetFlow collector."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    from .kafka_producer import CyberShieldKafkaProducer

    producer = CyberShieldKafkaProducer()
    geo = GeoIPEnricher()
    collector = NetFlowCollector(
        kafka_producer=producer,
        geoip_enricher=geo,
    )
    await collector.start()

    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        await collector.stop()
        producer.close()


def main() -> None:
    asyncio.run(run_collector())


if __name__ == "__main__":
    main()
