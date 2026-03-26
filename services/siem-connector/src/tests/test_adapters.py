"""
Tests for SIEM connector adapters and dispatcher.
Run with: pytest src/tests/ -v
"""

from __future__ import annotations

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters import splunk_hec, elastic_adapter, cef_syslog
from dispatcher import SIEMDispatcher


# ── Fixtures ─────────────────────────────────

SAMPLE_ALERT = {
    "alert_id":        "test-alert-001",
    "timestamp":       "2026-03-26T16:00:00Z",
    "severity":        "HIGH",
    "attack_type":     "PortScan",
    "threat_score":    0.87,
    "confidence":      0.92,
    "source_ip":       "203.0.113.42",
    "destination_ip":  "10.1.1.50",
    "mitre_technique": "T1046",
    "mitre_tactic":    "discovery",
    "event_ids":       ["evt-001"],
    "threat_intel":    {"reputation": -3},
}


# ── Splunk Tests ──────────────────────────────

def test_splunk_hec_payload_structure():
    """Test that the HEC payload has the correct top-level structure."""
    from adapters.splunk_hec import _build_hec_payload
    payload = _build_hec_payload(SAMPLE_ALERT)
    assert "time" in payload
    assert payload["sourcetype"] == splunk_hec.SPLUNK_SOURCETYPE
    assert payload["event"]["alert_id"] == "test-alert-001"
    assert payload["event"]["severity"] == "HIGH"
    assert payload["event"]["mitre_technique"] == "T1046"


@pytest.mark.asyncio
async def test_splunk_simulated_mode():
    """Splunk adapter returns simulated status when no token is set."""
    # Force simulate mode
    with patch.object(splunk_hec, "SIMULATE", True):
        result = await splunk_hec.forward(SAMPLE_ALERT)
    assert result["destination"] == "splunk"
    assert result["status"] == "simulated"
    assert result["latency_ms"] >= 0


@pytest.mark.asyncio
async def test_splunk_health_simulated():
    with patch.object(splunk_hec, "SIMULATE", True):
        health = await splunk_hec.health()
    assert health["adapter"] == "splunk"
    assert health["healthy"] is True


# ── Elastic Tests ─────────────────────────────

def test_elastic_ecs_document():
    """Test ECS document structure."""
    from adapters.elastic_adapter import _ecs_document
    doc = _ecs_document(SAMPLE_ALERT)
    assert doc["event"]["kind"] == "alert"
    assert doc["source"]["ip"] == "203.0.113.42"
    assert doc["destination"]["ip"] == "10.1.1.50"
    assert "T1046" in doc["threat"]["technique"]["id"]
    assert doc["labels"]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_elastic_simulated_mode():
    with patch.object(elastic_adapter, "SIMULATE", True):
        result = await elastic_adapter.forward(SAMPLE_ALERT)
    assert result["destination"] == "elasticsearch"
    assert result["status"] == "simulated"
    assert "index" in result


@pytest.mark.asyncio
async def test_elastic_health_simulated():
    with patch.object(elastic_adapter, "SIMULATE", True):
        health = await elastic_adapter.health()
    assert health["adapter"] == "elasticsearch"
    assert health["healthy"] is True


# ── CEF/Syslog Tests ─────────────────────────

def test_cef_format():
    """Test that the CEF string has the correct format."""
    from adapters.cef_syslog import _build_cef
    cef = _build_cef(SAMPLE_ALERT)
    assert cef.startswith("CEF:0|CyberShield-X|Pariraksakah")
    assert "src=203.0.113.42" in cef
    assert "dst=10.1.1.50" in cef
    assert "T1046" in cef
    assert "PortScan" in cef


@pytest.mark.asyncio
async def test_syslog_simulated_mode():
    with patch.object(cef_syslog, "SIMULATE", True):
        result = await cef_syslog.forward(SAMPLE_ALERT)
    assert result["destination"] == "syslog"
    assert result["status"] == "simulated"
    assert "cef_message" in result


@pytest.mark.asyncio
async def test_syslog_health_simulated():
    with patch.object(cef_syslog, "SIMULATE", True):
        health = await cef_syslog.health()
    assert health["adapter"] == "syslog"
    assert health["healthy"] is True


# ── Dispatcher Tests ──────────────────────────

@pytest.mark.asyncio
async def test_dispatcher_fans_out_to_all_adapters():
    """Dispatcher calls all three adapters concurrently."""
    dispatcher = SIEMDispatcher()
    with (
        patch.object(splunk_hec,       "SIMULATE", True),
        patch.object(elastic_adapter,  "SIMULATE", True),
        patch.object(cef_syslog,       "SIMULATE", True),
    ):
        results = await dispatcher.dispatch(SAMPLE_ALERT)

    assert len(results) == 3
    destinations = {r["destination"] for r in results}
    assert "splunk"          in destinations
    assert "elasticsearch"   in destinations
    assert "syslog"          in destinations


@pytest.mark.asyncio
async def test_dispatcher_tracks_stats():
    """Dispatcher increments success stats correctly."""
    dispatcher = SIEMDispatcher()
    with (
        patch.object(splunk_hec,       "SIMULATE", True),
        patch.object(elastic_adapter,  "SIMULATE", True),
        patch.object(cef_syslog,       "SIMULATE", True),
    ):
        await dispatcher.dispatch(SAMPLE_ALERT)

    stats = dispatcher.get_stats()
    assert len(stats["destinations"]) == 3
    for dest_stat in stats["destinations"]:
        assert dest_stat["total_forwarded"] >= 1
    assert len(stats["recent_events"]) == 1
    assert stats["recent_events"][0]["alert_id"] == "test-alert-001"
