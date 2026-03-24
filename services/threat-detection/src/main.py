"""CyberShield-X Threat Detection Service — Main Entry Point."""

import os
import time
import math
import asyncio
import logging
import hashlib
import uuid
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app, Counter, Histogram
from pydantic import BaseModel

from .ingestion.kafka_consumer import ThreatKafkaConsumer
from .persistence import db as persistence_db
from .persistence.repository import ThreatRepository, NetworkEventRepository, UEBAEventRepository, SuppressionRepository

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("threat-detection")

REQUEST_COUNT   = Counter("atde_requests_total", "Total inference requests", ["endpoint", "status"])
INFERENCE_LAT   = Histogram("atde_inference_latency_seconds", "ML inference latency")
THREAT_DETECTED = Counter("atde_threats_detected_total", "Threats detected", ["severity", "technique"])
STREAM_INGESTION_LAG_SECONDS = Histogram(
    "atde_stream_ingestion_lag_seconds",
    "Lag between event timestamp and stream ingestion",
)
ALERT_END_TO_END_LATENCY_SECONDS = Histogram(
    "atde_alert_end_to_end_latency_seconds",
    "Latency from event timestamp to alert emission",
)
DEDUP_CHECK_TOTAL = Counter("atde_dedup_check_total", "Total dedup checks")
DEDUP_HIT_TOTAL = Counter("atde_dedup_hit_total", "Total dedup hits")
SUPPRESSION_CHECK_TOTAL = Counter("atde_suppression_check_total", "Total suppression checks")
SUPPRESSION_HIT_TOTAL = Counter("atde_suppression_hit_total", "Total suppression hits")
PERSISTENCE_FAILURE_TOTAL = Counter("atde_persistence_failure_total", "Total persistence write failures", ["operation"])

app = FastAPI(
    title="CyberShield-X Threat Detection Engine",
    version="1.0.0",
    description="AI-Powered Advanced Threat Detection Engine (ATDE)",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/metrics", make_asgi_app())

# ── In-memory state for UEBA / anomaly detection ─

_event_window: deque = deque(maxlen=10000)          # sliding window of recent events
_ip_counters: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
_ip_last_seen: Dict[str, float] = {}
_user_baselines: Dict[str, dict] = {}
_user_last_seen: Dict[str, float] = {}
_detected_threats: deque = deque(maxlen=1000)       # Fast in-memory cache (also persisted to DB)
_stats = {
    "events_processed": 0,
    "threats_detected": 0,
    "false_positives_suppressed": 0,
    "deduplicated_alerts": 0,
    "persistence_failures": 0,
}

# ── Database repositories (initialized on startup) ─
_db_ready: bool = False
_stream_consumer: Optional[ThreatKafkaConsumer] = None
_app_loop: Optional[asyncio.AbstractEventLoop] = None

STREAM_ENABLED = os.getenv("THREAT_STREAM_ENABLED", "true").lower() == "true"
STREAM_TOPICS = [x.strip() for x in os.getenv("THREAT_STREAM_TOPICS", "network-events").split(",") if x.strip()]
STREAM_GROUP_ID = os.getenv("THREAT_STREAM_GROUP_ID", "threat-detection-stream")

_stream_stats = {
    "enabled": STREAM_ENABLED,
    "running": False,
    "messages_consumed": 0,
    "network_events": 0,
    "ueba_events": 0,
    "last_message_at": None,
    "last_error": None,
    "ws_clients": 0,
}

MAX_IP_TRACKERS = int(os.getenv("THREAT_IP_TRACKERS_MAX", "5000"))
MAX_USER_BASELINES = int(os.getenv("THREAT_USER_BASELINES_MAX", "5000"))
RETENTION_DAYS = int(os.getenv("THREAT_RETENTION_DAYS", "30"))
RETENTION_CLEANUP_EVERY_EVENTS = int(os.getenv("THREAT_RETENTION_CLEANUP_EVERY", "500"))
DEDUP_WINDOW_SECONDS = int(os.getenv("THREAT_DEDUP_WINDOW_SECONDS", "300"))
CORRELATION_WINDOW_SECONDS = int(os.getenv("THREAT_CORRELATION_WINDOW_SECONDS", "3600"))
SUPPRESSION_TTL_MINUTES = int(os.getenv("THREAT_SUPPRESSION_TTL_MINUTES", "120"))

_dedup_cache: Dict[str, Dict[str, Any]] = {}
_campaigns: Dict[str, Dict[str, Any]] = {}
_source_campaign_index: Dict[str, str] = {}


class WebSocketManager:
    """Tracks WebSocket clients and broadcasts JSON events."""

    def __init__(self):
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
            _stream_stats["ws_clients"] = len(self._clients)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._clients:
                self._clients.remove(ws)
            _stream_stats["ws_clients"] = len(self._clients)

    async def broadcast(self, payload: Dict[str, Any]):
        async with self._lock:
            clients = list(self._clients)

        dead: List[WebSocket] = []
        for ws in clients:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)
                _stream_stats["ws_clients"] = len(self._clients)


_ws_manager = WebSocketManager()

# ── Known IOC / suspicious ports / MITRE mapping ─

SUSPICIOUS_PORTS = {22, 23, 445, 3389, 4444, 5900, 6667, 8080, 31337}
LATERAL_MOVEMENT_PORTS = {135, 139, 445, 5985, 5986}
EXFIL_PORTS = {21, 22, 53, 80, 443, 4444}

MITRE_MAP = {
    "port_scan":          ("T1046", "Network Service Scanning",  "discovery"),
    "lateral_movement":   ("T1021", "Remote Services",           "lateral_movement"),
    "c2_beacon":          ("T1071", "Application Layer Protocol","command_and_control"),
    "credential_access":  ("T1003", "OS Credential Dumping",     "credential_access"),
    "data_exfiltration":  ("T1041", "Exfiltration Over C2",      "exfiltration"),
    "brute_force":        ("T1110", "Brute Force",               "credential_access"),
    "privilege_escalation":("T1068","Exploitation for Privilege Escalation","privilege_escalation"),
}

# ── Schemas ──────────────────────────────────────

class NetworkEvent(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_recv: int = 0
    duration_ms: int = 0
    user_agent: Optional[str] = None
    payload_entropy: Optional[float] = None
    timestamp: Optional[str] = None

class UserBehaviorEvent(BaseModel):
    user_id: str
    action: str                    # login, file_access, privilege_use, lateral_move
    resource: str
    source_ip: str
    hour_of_day: int = 9
    day_of_week: int = 1
    failed_attempts: int = 0

class BatchEventRequest(BaseModel):
    events: List[NetworkEvent]


class AlertFeedbackRequest(BaseModel):
    threat_id: str
    verdict: str                    # true_positive | false_positive | benign
    note: Optional[str] = None
    suppression_minutes: Optional[int] = None

# ── Core detection engine ─────────────────────────

def _entropy(data: str) -> float:
    """Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _threat_pattern_hash(src_ip: str, dst_ip: str, threat_type: str, dst_port: int) -> str:
    """Stable hash used for dedup/suppression decisions."""
    raw = f"{src_ip}|{dst_ip}|{threat_type}|{dst_port}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _mitre_tactic_to_stage(mitre_tactic: str) -> str:
    stage_map = {
        "discovery": "Reconnaissance",
        "initial_access": "Delivery",
        "credential_access": "Exploitation",
        "privilege_escalation": "Exploitation",
        "lateral_movement": "Command & Control",
        "command_and_control": "Command & Control",
        "exfiltration": "Actions on Objectives",
        "impact": "Actions on Objectives",
    }
    return stage_map.get((mitre_tactic or "").lower(), "Exploitation")


def _stage_risk(stage: str) -> float:
    weights = {
        "Reconnaissance": 0.15,
        "Delivery": 0.35,
        "Exploitation": 0.55,
        "Command & Control": 0.80,
        "Actions on Objectives": 1.00,
    }
    return weights.get(stage, 0.4)


def _is_suppressed(pattern_hash: str) -> bool:
    """Check if this pattern is currently suppressed by analyst feedback."""
    if not _db_ready:
        return False
    try:
        with persistence_db.session_scope() as session:
            return SuppressionRepository(session).is_suppressed(pattern_hash)
    except Exception as e:
        logger.warning("Suppression lookup failed: %s", e)
        return False


def _check_dedup(pattern_hash: str) -> Optional[Dict[str, Any]]:
    """Return dedup cache item when within configured dedup window."""
    item = _dedup_cache.get(pattern_hash)
    if not item:
        return None
    if time.time() - item["first_seen"] > DEDUP_WINDOW_SECONDS:
        _dedup_cache.pop(pattern_hash, None)
        return None
    return item


def _register_dedup(pattern_hash: str, threat_id: str):
    """Register a newly emitted alert in dedup cache."""
    _dedup_cache[pattern_hash] = {
        "threat_id": threat_id,
        "first_seen": time.time(),
        "hits": 1,
    }


def _correlate_campaign(src_ip: str, threat_type: str, mitre_tactic: str) -> Dict[str, Any]:
    """Correlate an alert into an active campaign and return campaign metadata."""
    now = time.time()
    campaign_id = _source_campaign_index.get(src_ip)
    campaign = _campaigns.get(campaign_id) if campaign_id else None

    if not campaign or (now - campaign["last_seen"] > CORRELATION_WINDOW_SECONDS):
        campaign_id = str(uuid.uuid4())
        campaign = {
            "campaign_id": campaign_id,
            "source_ip": src_ip,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "last_seen": now,
            "threat_types": set(),
            "stages": set(),
            "alert_count": 0,
            "risk_score": 0.0,
        }
        _campaigns[campaign_id] = campaign
        _source_campaign_index[src_ip] = campaign_id

    stage = _mitre_tactic_to_stage(mitre_tactic)
    campaign["last_seen"] = now
    campaign["alert_count"] += 1
    campaign["threat_types"].add(threat_type)
    campaign["stages"].add(stage)
    campaign["risk_score"] = round(max(_stage_risk(x) for x in campaign["stages"]), 4)

    return {
        "campaign_id": campaign_id,
        "kill_chain_stage": stage,
        "campaign_risk_score": campaign["risk_score"],
        "campaign_alert_count": campaign["alert_count"],
        "campaign_stages": sorted(list(campaign["stages"])),
    }


def _prune_in_memory_state(now_ts: Optional[float] = None):
    """Bound in-memory growth by evicting stale/old keys."""
    now_ts = now_ts or time.time()

    if len(_ip_last_seen) > MAX_IP_TRACKERS:
        overflow = len(_ip_last_seen) - MAX_IP_TRACKERS
        oldest_ips = sorted(_ip_last_seen.items(), key=lambda kv: kv[1])[:overflow]
        for ip, _ in oldest_ips:
            _ip_last_seen.pop(ip, None)
            _ip_counters.pop(ip, None)

    if len(_user_last_seen) > MAX_USER_BASELINES:
        overflow = len(_user_last_seen) - MAX_USER_BASELINES
        oldest_users = sorted(_user_last_seen.items(), key=lambda kv: kv[1])[:overflow]
        for uid, _ in oldest_users:
            _user_last_seen.pop(uid, None)
            _user_baselines.pop(uid, None)


def _maybe_run_retention_cleanup():
    """Apply retention periodically to keep historical tables bounded."""
    if not _db_ready or RETENTION_DAYS <= 0:
        return

    if _stats["events_processed"] > 0 and _stats["events_processed"] % RETENTION_CLEANUP_EVERY_EVENTS == 0:
        try:
            summary = persistence_db.apply_retention_policies(retention_days=RETENTION_DAYS)
            logger.info("Retention cleanup applied: %s", summary)
        except Exception as e:
            logger.warning("Retention cleanup failed: %s", e)


def _emit_ws_event(payload: Dict[str, Any]) -> None:
    """Schedule a WebSocket broadcast on the app event loop."""
    if not _app_loop:
        return
    try:
        asyncio.run_coroutine_threadsafe(_ws_manager.broadcast(payload), _app_loop)
    except Exception as e:
        logger.warning("Failed to schedule websocket broadcast: %s", e)


def _parse_iso_timestamp(timestamp: Optional[str]) -> Optional[datetime]:
    """Best-effort parse for ISO timestamps, including trailing Z."""
    if not timestamp:
        return None
    try:
        normalized = timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception:
        return None


def _normalize_network_event(payload: Dict[str, Any]) -> NetworkEvent:
    """Normalize stream payload variants into NetworkEvent schema."""
    src_ip = str(payload.get("src_ip") or payload.get("source_ip") or "0.0.0.0")
    dst_ip = str(payload.get("dst_ip") or payload.get("destination_ip") or "0.0.0.0")
    dst_port = int(payload.get("dst_port") or payload.get("destination_port") or 0)

    return NetworkEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=str(payload.get("protocol") or "TCP"),
        bytes_sent=int(payload.get("bytes_sent") or 0),
        bytes_recv=int(payload.get("bytes_recv") or payload.get("bytes_received") or 0),
        duration_ms=int(payload.get("duration_ms") or 0),
        user_agent=payload.get("user_agent") or payload.get("raw_payload"),
        payload_entropy=payload.get("payload_entropy"),
        timestamp=payload.get("timestamp"),
    )


def _normalize_ueba_event(payload: Dict[str, Any]) -> UserBehaviorEvent:
    """Normalize stream payload variants into UserBehaviorEvent schema."""
    now = datetime.utcnow()
    return UserBehaviorEvent(
        user_id=str(payload.get("user_id") or payload.get("username") or "unknown-user"),
        action=str(payload.get("action") or payload.get("event_type") or "login"),
        resource=str(payload.get("resource") or payload.get("hostname") or "unknown-resource"),
        source_ip=str(payload.get("source_ip") or payload.get("src_ip") or "0.0.0.0"),
        hour_of_day=int(payload.get("hour_of_day") or now.hour),
        day_of_week=int(payload.get("day_of_week") or now.weekday()),
        failed_attempts=int(payload.get("failed_attempts") or 0),
    )


def _process_network_event(ev: NetworkEvent, request_metric_label: str = "analyze_network") -> Dict[str, Any]:
    """Canonical network-event processing path used by API and Kafka ingestion."""
    REQUEST_COUNT.labels(endpoint=request_metric_label, status="ok").inc()

    result = _classify_network_event(ev)
    _event_window.append({**ev.dict(), **result})
    _stats["events_processed"] += 1
    _prune_in_memory_state()
    _maybe_run_retention_cleanup()

    if result["is_threat"]:
        pattern_hash = _threat_pattern_hash(
            ev.src_ip,
            ev.dst_ip,
            str(result.get("primary_technique") or "unknown"),
            int(ev.dst_port),
        )

        # Suppression comes first: if analysts marked this pattern as FP/benign, skip alert emission.
        SUPPRESSION_CHECK_TOTAL.inc()
        if _is_suppressed(pattern_hash):
            SUPPRESSION_HIT_TOTAL.inc()
            _stats["false_positives_suppressed"] += 1
            return {**result, "suppressed": True}

        # Dedup within a short window to reduce alert storms.
        DEDUP_CHECK_TOTAL.inc()
        dedup_item = _check_dedup(pattern_hash)
        if dedup_item is not None:
            DEDUP_HIT_TOTAL.inc()
            dedup_item["hits"] += 1
            _stats["deduplicated_alerts"] += 1
            return {**result, "deduplicated": True, "dedup_parent_threat_id": dedup_item["threat_id"]}

        _stats["threats_detected"] += 1
        if result["primary_technique"]:
            THREAT_DETECTED.labels(severity=result["severity"], technique=result["primary_technique"]).inc()

        threat_id = hashlib.md5(f"{ev.src_ip}{ev.dst_ip}{time.time()}".encode()).hexdigest()[:12]
        detected_at = datetime.utcnow()
        event_ts = _parse_iso_timestamp(ev.timestamp)
        if event_ts:
            try:
                ALERT_END_TO_END_LATENCY_SECONDS.observe(max(0.0, (detected_at - event_ts.replace(tzinfo=None)).total_seconds()))
            except Exception:
                pass

        threat_dict = {
            "id": threat_id,
            "src_ip": ev.src_ip,
            "dst_ip": ev.dst_ip,
            "dst_port": ev.dst_port,
            "detected_at": detected_at,
            "severity": result["severity"],
            "threat_type": result["primary_technique"],
            "confidence_score": result["score"],
            "mitre_technique": result["mitre_technique_id"],
            "mitre_tactic": result["mitre_tactic"],
            "description": f"{result.get('primary_technique', 'Unknown')} detected on {ev.dst_ip}:{ev.dst_port}",
            "payload_entropy": result["indicators"].get("payload_entropy", 0),
            "bytes_transferred": ev.bytes_sent + ev.bytes_recv,
            "status": "open",
        }

        campaign_meta = _correlate_campaign(
            src_ip=ev.src_ip,
            threat_type=str(result.get("primary_technique") or "unknown"),
            mitre_tactic=str(result.get("mitre_tactic") or ""),
        )

        _detected_threats.append({
            **threat_dict,
            "primary_technique": result["primary_technique"],
            "score": result["score"],
            "mitre_technique_id": result["mitre_technique_id"],
            "detected_at": detected_at.isoformat() + "Z",
            "suppression_hash": pattern_hash,
            **campaign_meta,
        })
        _register_dedup(pattern_hash, threat_id)

        # Broadcast live alert event to websocket subscribers.
        _emit_ws_event({
            "type": "alert",
            "alert": {
                "id": threat_id,
                "severity": result["severity"],
                "type": result.get("mitre_technique_name") or "Suspicious Activity",
                "source_ip": ev.src_ip,
                "destination_ip": ev.dst_ip,
                "description": threat_dict["description"],
                "timestamp": detected_at.isoformat() + "Z",
                "mitre_technique": result["mitre_technique_id"],
                "status": "open",
                "confidence": result["score"],
                "source": "threat-detection",
                "campaign_id": campaign_meta["campaign_id"],
                "kill_chain_stage": campaign_meta["kill_chain_stage"],
                "campaign_risk_score": campaign_meta["campaign_risk_score"],
            },
        })

        if _db_ready:
            try:
                with persistence_db.session_scope() as session:
                    ThreatRepository(session).create_threat(threat_dict)
            except Exception as e:
                PERSISTENCE_FAILURE_TOTAL.labels(operation="create_threat").inc()
                _stats["persistence_failures"] += 1
                logger.warning(f"Failed to persist threat {threat_id}: {e}")

    return result


def _process_ueba_event(ev: UserBehaviorEvent, request_metric_label: str = "analyze_ueba") -> Dict[str, Any]:
    """Canonical UEBA processing path used by API and Kafka ingestion."""
    REQUEST_COUNT.labels(endpoint=request_metric_label, status="ok").inc()
    result = _classify_user_behavior(ev)
    _stats["events_processed"] += 1
    _prune_in_memory_state()
    _maybe_run_retention_cleanup()

    if result["is_anomalous"]:
        _stats["threats_detected"] += 1

    return result


def _on_stream_message(topic: str, payload: Dict[str, Any]) -> None:
    """Kafka callback: route incoming events through canonical processors."""
    _stream_stats["messages_consumed"] += 1
    _stream_stats["last_message_at"] = datetime.utcnow().isoformat() + "Z"

    payload_ts = _parse_iso_timestamp(str(payload.get("timestamp") or ""))
    if payload_ts:
        try:
            STREAM_INGESTION_LAG_SECONDS.observe(max(0.0, (datetime.utcnow() - payload_ts.replace(tzinfo=None)).total_seconds()))
        except Exception:
            pass

    try:
        if topic in {"network-events", "endpoint-events"}:
            ev = _normalize_network_event(payload)
            _process_network_event(ev, request_metric_label="stream_network")
            _stream_stats["network_events"] += 1
        elif topic == "auth-events":
            ev = _normalize_ueba_event(payload)
            _process_ueba_event(ev, request_metric_label="stream_ueba")
            _stream_stats["ueba_events"] += 1
        else:
            logger.debug("Ignoring unsupported stream topic=%s", topic)
    except Exception as e:
        _stream_stats["last_error"] = str(e)
        logger.warning("Stream message processing failed topic=%s err=%s", topic, e)

def _classify_network_event(ev: NetworkEvent) -> dict:
    """Real statistical + rule-based threat classification."""
    threats = []
    score = 0.0

    # 1. Port scan heuristic: many distinct destination ports from same src
    recent_ports = _ip_counters[ev.src_ip]
    _ip_last_seen[ev.src_ip] = time.time()
    recent_ports.append(ev.dst_port)
    unique_ports_last_100 = len(set(list(recent_ports)[-100:]))
    if unique_ports_last_100 > 20:
        threats.append("port_scan")
        score += 0.6

    # 2. Lateral movement: internal→internal on known ports
    src_internal = ev.src_ip.startswith(("10.", "172.", "192.168."))
    dst_internal = ev.dst_ip.startswith(("10.", "172.", "192.168."))
    if src_internal and dst_internal and ev.dst_port in LATERAL_MOVEMENT_PORTS:
        threats.append("lateral_movement")
        score += 0.5

    # 3. C2 beacon: regular small packets to external with high entropy payload
    entropy = ev.payload_entropy or _entropy(ev.user_agent or "")
    if not dst_internal and ev.bytes_sent < 512 and ev.bytes_recv < 512 and entropy > 4.5:
        threats.append("c2_beacon")
        score += 0.55

    # 4. Suspicious port usage
    if ev.dst_port in SUSPICIOUS_PORTS:
        score += 0.3
        if ev.dst_port == 4444:  # Metasploit default
            threats.append("c2_beacon")
            score += 0.4

    # 5. Data exfiltration: large outbound bytes to external
    if not dst_internal and ev.bytes_sent > 10_000_000:  # 10MB+
        threats.append("data_exfiltration")
        score += 0.65

    # 6. Brute force: many failed connections on auth ports
    # (requires session-level data — approximated by high duration + small bytes)
    if ev.dst_port in {22, 3389, 5900} and ev.duration_ms < 500 and ev.bytes_recv < 200:
        score += 0.25
        threats.append("brute_force")

    score = min(score, 1.0)

    if score >= 0.7:
        severity = "critical"
    elif score >= 0.5:
        severity = "high"
    elif score >= 0.3:
        severity = "medium"
    else:
        severity = "low"
        threats = []

    primary = threats[0] if threats else None
    mitre_id, mitre_name, tactic = MITRE_MAP.get(primary, ("", "", "")) if primary else ("", "", "")

    return {
        "is_threat": score >= 0.3,
        "severity": severity,
        "score": round(score, 4),
        "techniques_detected": threats,
        "primary_technique": primary,
        "mitre_technique_id": mitre_id,
        "mitre_technique_name": mitre_name,
        "mitre_tactic": tactic,
        "indicators": {
            "unique_ports_scanned": unique_ports_last_100,
            "payload_entropy": round(entropy, 3),
            "bytes_sent": ev.bytes_sent,
            "lateral_movement_port": ev.dst_port in LATERAL_MOVEMENT_PORTS,
        },
    }

def _classify_user_behavior(ev: UserBehaviorEvent) -> dict:
    """UEBA — User and Entity Behavior Analytics."""
    uid = ev.user_id
    _user_last_seen[uid] = time.time()
    baseline = _user_baselines.get(uid, {"normal_hours": list(range(8, 18)), "normal_days": list(range(0, 5)), "failed_threshold": 3})

    anomalies = []
    score = 0.0

    # Off-hours access
    if ev.hour_of_day not in baseline["normal_hours"]:
        anomalies.append(f"off_hours_access (hour={ev.hour_of_day})")
        score += 0.35

    # Weekend access
    if ev.day_of_week in (5, 6) and ev.day_of_week not in baseline["normal_days"]:
        anomalies.append("weekend_access")
        score += 0.20

    # Too many failed attempts
    if ev.failed_attempts >= baseline["failed_threshold"]:
        anomalies.append(f"excessive_failures ({ev.failed_attempts} attempts)")
        score += 0.45

    # Privilege use from unusual IP
    if ev.action == "privilege_use":
        score += 0.30
        anomalies.append("privilege_escalation_attempt")

    # Lateral movement
    if ev.action == "lateral_move":
        score += 0.55
        anomalies.append("lateral_movement_detected")

    score = min(score, 1.0)
    # Update baseline (simple exponential moving average)
    _user_baselines[uid] = baseline

    return {
        "user_id": uid,
        "is_anomalous": score >= 0.35,
        "risk_score": round(score, 4),
        "anomalies": anomalies,
        "action": ev.action,
        "resource": ev.resource,
    }

# ── Endpoints ─────────────────────────────────────

@app.get("/health")
async def health_check():
    db_health = persistence_db.get_db_health() if _db_ready else {"status": "not_initialized"}
    return {
        "status": "healthy",
        "service": "threat-detection",
        "version": "1.0.0",
        "stats": _stats,
        "db": db_health,
        "memory": {
            "event_window": len(_event_window),
            "detected_threats_cache": len(_detected_threats),
            "ip_trackers": len(_ip_counters),
            "user_baselines": len(_user_baselines),
        },
        "stream": _stream_stats,
    }

@app.post("/analyze/network")
async def analyze_network_event(ev: NetworkEvent):
    """Analyze a single network event for threats using statistical + rule-based detection."""
    t0 = time.time()
    result = _process_network_event(ev, request_metric_label="analyze_network")

    INFERENCE_LAT.observe(time.time() - t0)
    return {**result, "latency_ms": round((time.time() - t0) * 1000, 2)}

@app.post("/analyze/ueba")
async def analyze_user_behavior(ev: UserBehaviorEvent):
    """UEBA — analyze user behavior for insider threats and account compromise."""
    t0 = time.time()
    result = _process_ueba_event(ev, request_metric_label="analyze_ueba")
    return {**result, "latency_ms": round((time.time() - t0) * 1000, 2)}

@app.post("/analyze/batch")
async def analyze_batch(req: BatchEventRequest):
    """Batch analyze multiple network events."""
    t0 = time.time()
    results = [_process_network_event(ev, request_metric_label="analyze_batch_network") for ev in req.events]
    threats = [r for r in results if r["is_threat"]]
    return {
        "total": len(results),
        "threats_found": len(threats),
        "results": results,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }

@app.get("/threats/recent")
async def get_recent_threats(limit: int = 50):
    """Return the most recently detected threats."""
    items = list(_detected_threats)
    return {
        "threats": items[-limit:][::-1],
        "total": len(_detected_threats),
    }

@app.get("/stats")
async def get_stats():
    db_health = {"status": "unknown"}
    if _db_ready:
        try:
            with persistence_db.session_scope() as session:
                ThreatRepository(session).get_recent_threats(limit=1)
            db_health = {"status": "healthy"}
        except Exception as e:
            db_health = {"status": "error", "error": str(e)}
    
    return {
        "service": "threat-detection",
        **_stats,
        "db_health": db_health,
        "stream": _stream_stats,
    }


@app.get("/stream/status")
async def get_stream_status():
    """Return Kafka streaming ingestion status."""
    return {
        "service": "threat-detection",
        "stream": _stream_stats,
        "topics": STREAM_TOPICS,
        "group_id": STREAM_GROUP_ID,
    }


@app.get("/campaigns/active")
async def get_active_campaigns(limit: int = 50):
    """Return active correlated campaigns from in-memory correlation index."""
    campaigns = []
    now = time.time()
    for item in _campaigns.values():
        # keep only recently active campaigns
        if now-item["last_seen"] > CORRELATION_WINDOW_SECONDS:
            continue
        campaigns.append({
            "campaign_id": item["campaign_id"],
            "source_ip": item["source_ip"],
            "created_at": item["created_at"],
            "last_seen": datetime.utcfromtimestamp(item["last_seen"]).isoformat() + "Z",
            "alert_count": item["alert_count"],
            "risk_score": item["risk_score"],
            "stages": sorted(list(item["stages"])),
            "threat_types": sorted(list(item["threat_types"])),
        })

    campaigns.sort(key=lambda x: (x["risk_score"], x["alert_count"]), reverse=True)
    return {
        "campaigns": campaigns[:limit],
        "total": len(campaigns),
    }


@app.post("/alerts/feedback")
async def submit_alert_feedback(req: AlertFeedbackRequest):
    """Analyst feedback endpoint for false-positive suppression tuning."""
    if not _db_ready:
        raise HTTPException(status_code=503, detail="Database not initialized")

    verdict = req.verdict.strip().lower()
    if verdict not in {"true_positive", "false_positive", "benign"}:
        raise HTTPException(status_code=400, detail="verdict must be true_positive|false_positive|benign")

    try:
        with persistence_db.session_scope() as session:
            threat_repo = ThreatRepository(session)
            threat = threat_repo.get_threat_by_id(req.threat_id)
            if not threat:
                raise HTTPException(status_code=404, detail="threat not found")

            # Update threat lifecycle state.
            new_status = "resolved" if verdict == "true_positive" else "false_positive"
            threat_repo.update_threat_status(req.threat_id, new_status, note=req.note)

            suppression_created = False
            suppression_until = None
            if verdict in {"false_positive", "benign"}:
                ttl_minutes = req.suppression_minutes or SUPPRESSION_TTL_MINUTES
                suppression_until_dt = datetime.utcnow().timestamp() + (ttl_minutes * 60)
                suppression_until = datetime.utcfromtimestamp(suppression_until_dt).isoformat() + "Z"
                pattern_hash = _threat_pattern_hash(
                    threat.src_ip or "",
                    threat.dst_ip or "",
                    threat.threat_type or "unknown",
                    int(threat.dst_port or 0),
                )
                SuppressionRepository(session).create_suppression({
                    "id": hashlib.md5(f"{pattern_hash}{time.time()}".encode()).hexdigest()[:16],
                    "threat_id": req.threat_id,
                    "threat_pattern_hash": pattern_hash,
                    "reason": verdict,
                    "suppression_until": datetime.utcfromtimestamp(suppression_until_dt),
                    "count_suppressed": 1,
                })
                suppression_created = True

        return {
            "status": "ok",
            "threat_id": req.threat_id,
            "verdict": verdict,
            "updated_status": new_status,
            "suppression_created": suppression_created,
            "suppression_until": suppression_until,
        }
    except HTTPException:
        raise
    except Exception as e:
        PERSISTENCE_FAILURE_TOTAL.labels(operation="alert_feedback").inc()
        _stats["persistence_failures"] += 1
        logger.error("Feedback submission failed: %s", e)
        raise HTTPException(status_code=500, detail=f"feedback failed: {str(e)}")


@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    """WebSocket endpoint for live alert push notifications."""
    await _ws_manager.connect(ws)
    try:
        # keep connection alive; clients may send ping/heartbeat payloads
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await _ws_manager.disconnect(ws)
    except Exception:
        await _ws_manager.disconnect(ws)

@app.get("/threats/historical")
async def get_historical_threats(
    severity: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 100,
    technique: Optional[str] = None,
):
    """Query historical threats from persistent storage."""
    if not _db_ready:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    try:
        with persistence_db.session_scope() as session:
            repo = ThreatRepository(session)
            if technique:
                threats = repo.get_threats_by_technique(technique, hours_back=hours_back, limit=limit)
            else:
                threats = repo.get_recent_threats(limit=limit, severity=severity, hours_back=hours_back)
        
        return {
            "threats": [
                {
                    "id": t.id,
                    "severity": t.severity,
                    "threat_type": t.threat_type,
                    "src_ip": t.src_ip,
                    "dst_ip": t.dst_ip,
                    "detected_at": t.detected_at.isoformat() + "Z",
                    "mitre_technique": t.mitre_technique,
                    "mitre_tactic": t.mitre_tactic,
                    "confidence_score": t.confidence_score,
                    "status": t.status,
                }
                for t in threats
            ],
            "total": len(threats),
            "query": {"severity": severity, "technique": technique, "hours_back": hours_back},
        }
    except Exception as e:
        logger.error(f"Failed to query historical threats: {e}")
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")

@app.get("/threats/by-ip")
async def get_threats_by_ip(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 100,
):
    """Query threats by source or destination IP."""
    if not _db_ready:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    try:
        with persistence_db.session_scope() as session:
            threats = ThreatRepository(session).get_threats_by_ip(
                src_ip=src_ip,
                dst_ip=dst_ip,
                hours_back=hours_back,
                limit=limit
            )
        
        return {
            "threats": [
                {
                    "id": t.id,
                    "severity": t.severity,
                    "threat_type": t.threat_type,
                    "src_ip": t.src_ip,
                    "dst_ip": t.dst_ip,
                    "detected_at": t.detected_at.isoformat() + "Z",
                    "confidence_score": t.confidence_score,
                }
                for t in threats
            ],
            "total": len(threats),
            "query": {"src_ip": src_ip, "dst_ip": dst_ip, "hours_back": hours_back},
        }
    except Exception as e:
        logger.error(f"Failed to query threats by IP: {e}")
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")

@app.on_event("startup")
async def startup_event():
    global _db_ready, _stream_consumer, _app_loop

    _app_loop = asyncio.get_running_loop()
    
    logger.info("Threat Detection Engine starting up...")
    logger.info("KAFKA_BOOTSTRAP_SERVERS=%s", os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    
    # Initialize database and repositories
    if persistence_db.init_database():
        try:
            with persistence_db.session_scope() as session:
                ThreatRepository(session)
                NetworkEventRepository(session)
                UEBAEventRepository(session)
            _db_ready = True

            retention_summary = persistence_db.apply_retention_policies(retention_days=RETENTION_DAYS)
            logger.info("✅ Persistence layer initialized")
            logger.info("Retention policy initialized: %s", retention_summary)
        except Exception as e:
            _db_ready = False
            logger.error(f"Failed to initialize repositories: {e}")
    else:
        _db_ready = False
        logger.warning("⚠️ Database initialization failed — running in memory-only mode")

    if STREAM_ENABLED:
        try:
            _stream_consumer = ThreatKafkaConsumer(
                bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"),
                group_id=STREAM_GROUP_ID,
                topics=STREAM_TOPICS,
            )
            _stream_consumer.start(_on_stream_message)
            _stream_stats["running"] = True
            logger.info("✅ Stream ingestion enabled topics=%s", STREAM_TOPICS)
        except Exception as e:
            _stream_stats["running"] = False
            _stream_stats["last_error"] = str(e)
            logger.error("Failed to initialize stream consumer: %s", e)
    else:
        logger.info("Stream ingestion disabled by THREAT_STREAM_ENABLED=false")
    
    logger.info("Threat Detection Engine ready — statistical + rule-based detection active + persistence enabled")

@app.on_event("shutdown")
async def shutdown_event():
    global _stream_consumer, _app_loop
    logger.info("Threat Detection Engine shutting down...")
    if _stream_consumer:
        _stream_consumer.stop()
        _stream_stats["running"] = False
    _app_loop = None
    persistence_db.close_database()
    logger.info("Database connections closed")
