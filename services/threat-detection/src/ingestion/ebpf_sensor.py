"""
CyberShield-X — eBPF Kernel Sensor Agent
Monitors syscalls, network connections, and file access via eBPF (using bcc),
then forwards captured events to Kafka.

Requires Linux 5.4+ with eBPF support and the ``bcc`` library.
Falls back gracefully on systems without eBPF support.
"""

from __future__ import annotations

import ctypes as ct
import json
import logging
import os
import signal
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("cybershield.ingestion.ebpf_sensor")

# ──────────────────────────────────────────────
# eBPF C programs for kernel tracing
# ──────────────────────────────────────────────

BPF_EXECVE_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct execve_event_t {
    u32 pid;
    u32 uid;
    char comm[64];
    char filename[256];
    u64 ts;
};

BPF_PERF_OUTPUT(execve_events);

int trace_execve(struct tracepoint__syscalls__sys_enter_execve *args) {
    struct execve_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.ts  = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename),
                            (void *)args->filename);
    execve_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

BPF_CONNECT_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct connect_event_t {
    u32 pid;
    u32 uid;
    char comm[64];
    u32 daddr;
    u16 dport;
    u64 ts;
};

BPF_PERF_OUTPUT(connect_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct connect_event_t evt = {};
    evt.pid   = bpf_get_current_pid_tgid() >> 32;
    evt.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.ts    = bpf_ktime_get_ns();
    evt.daddr = sk->__sk_common.skc_daddr;
    evt.dport = sk->__sk_common.skc_dport;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    connect_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

BPF_OPENAT_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct openat_event_t {
    u32 pid;
    u32 uid;
    char comm[64];
    char filename[256];
    u64 ts;
};

BPF_PERF_OUTPUT(openat_events);

int trace_openat(struct tracepoint__syscalls__sys_enter_openat *args) {
    struct openat_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.ts  = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename),
                            (void *)args->filename);
    openat_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

# ──────────────────────────────────────────────
# C-type structs for perf-event data
# ──────────────────────────────────────────────


class ExecveEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 64),
        ("filename", ct.c_char * 256),
        ("ts", ct.c_uint64),
    ]


class ConnectEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 64),
        ("daddr", ct.c_uint32),
        ("dport", ct.c_uint16),
        ("ts", ct.c_uint64),
    ]


class OpenatEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 64),
        ("filename", ct.c_char * 256),
        ("ts", ct.c_uint64),
    ]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _ip_from_int(addr: int) -> str:
    """Convert a 32-bit network-order integer to dotted-quad string."""
    return ".".join(str((addr >> (8 * i)) & 0xFF) for i in range(4))


def _ntohs(port: int) -> int:
    """Convert a 16-bit port from network byte order to host byte order."""
    return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)


# ──────────────────────────────────────────────
# Sensor daemon
# ──────────────────────────────────────────────

class EBPFSensor:
    """eBPF kernel sensor that monitors syscalls and forwards events to Kafka.

    Parameters
    ----------
    kafka_producer : object
        An instance of ``CyberShieldKafkaProducer`` (or duck-type compatible).
    hostname : str, optional
        Hostname to tag events with (auto-detected if omitted).
    """

    def __init__(
        self,
        kafka_producer: Any,
        hostname: Optional[str] = None,
    ) -> None:
        self._producer = kafka_producer
        self._hostname = hostname or os.uname().nodename
        self._running = False
        self._bpf_objects: list[Any] = []

        # Wire shutdown signals
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    # ── graceful shutdown ──
    def _handle_signal(self, signum: int, frame: Any) -> None:
        logger.info("Received signal %d — shutting down sensor…", signum)
        self._running = False

    # ── event builders ──
    def _build_execve_event(self, event: ExecveEvent) -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "PROCESS",
            "hostname": self._hostname,
            "pid": event.pid,
            "process_name": event.comm.decode("utf-8", errors="replace"),
            "user_id": str(event.uid),
            "raw_payload": json.dumps({
                "syscall": "execve",
                "filename": event.filename.decode("utf-8", errors="replace"),
            }),
        }

    def _build_connect_event(self, event: ConnectEvent) -> Dict[str, Any]:
        dst_ip = _ip_from_int(event.daddr)
        dst_port = _ntohs(event.dport)
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "NETWORK",
            "hostname": self._hostname,
            "pid": event.pid,
            "process_name": event.comm.decode("utf-8", errors="replace"),
            "user_id": str(event.uid),
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "raw_payload": json.dumps({
                "syscall": "connect",
                "dst": f"{dst_ip}:{dst_port}",
            }),
        }

    def _build_openat_event(self, event: OpenatEvent) -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "FILE",
            "hostname": self._hostname,
            "pid": event.pid,
            "process_name": event.comm.decode("utf-8", errors="replace"),
            "user_id": str(event.uid),
            "raw_payload": json.dumps({
                "syscall": "openat",
                "filename": event.filename.decode("utf-8", errors="replace"),
            }),
        }

    # ── callback factories ──
    def _make_callback(self, builder, topic):
        def _cb(cpu, data, size):
            try:
                evt = builder(ct.cast(data, ct.POINTER(type(builder.__func__.__annotations__.get("event")))).contents
                              if False else
                              ct.cast(data, ct.POINTER(ExecveEvent if "execve" in builder.__name__
                                                        else ConnectEvent if "connect" in builder.__name__
                                                        else OpenatEvent)).contents)
                self._producer.produce(topic, evt)
            except Exception:
                logger.exception("Error in eBPF callback")
        return _cb

    # ── main loop ──
    def start(self) -> None:
        """Attach eBPF probes and enter the polling loop.

        Falls back gracefully if eBPF / bcc is unavailable.
        """
        try:
            from bcc import BPF  # type: ignore[import-untyped]
        except ImportError:
            logger.error(
                "bcc library not available — eBPF sensor disabled. "
                "Install with: apt-get install bpfcc-tools python3-bcc"
            )
            return

        logger.info("Starting eBPF sensor on %s…", self._hostname)

        # Attach execve tracepoint
        try:
            b_exec = BPF(text=BPF_EXECVE_PROGRAM)
            b_exec["execve_events"].open_perf_buffer(
                lambda cpu, data, size: self._on_execve(b_exec, cpu, data, size)
            )
            self._bpf_objects.append(b_exec)
            logger.info("Attached execve tracepoint")
        except Exception:
            logger.warning("Failed to attach execve tracepoint", exc_info=True)

        # Attach connect kprobe
        try:
            b_conn = BPF(text=BPF_CONNECT_PROGRAM)
            b_conn.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
            b_conn["connect_events"].open_perf_buffer(
                lambda cpu, data, size: self._on_connect(b_conn, cpu, data, size)
            )
            self._bpf_objects.append(b_conn)
            logger.info("Attached connect kprobe")
        except Exception:
            logger.warning("Failed to attach connect kprobe", exc_info=True)

        # Attach openat tracepoint
        try:
            b_open = BPF(text=BPF_OPENAT_PROGRAM)
            b_open["openat_events"].open_perf_buffer(
                lambda cpu, data, size: self._on_openat(b_open, cpu, data, size)
            )
            self._bpf_objects.append(b_open)
            logger.info("Attached openat tracepoint")
        except Exception:
            logger.warning("Failed to attach openat tracepoint", exc_info=True)

        if not self._bpf_objects:
            logger.error("No eBPF probes attached — sensor cannot run.")
            return

        self._running = True
        logger.info("eBPF sensor running. Polling events…")

        while self._running:
            for bpf in self._bpf_objects:
                try:
                    bpf.perf_buffer_poll(timeout=100)
                except Exception:
                    logger.exception("Error polling eBPF perf buffer")

        # Clean shutdown
        self._producer.flush(timeout=10)
        logger.info("eBPF sensor stopped.")

    # ── perf callbacks ──
    def _on_execve(self, bpf, cpu, data, size) -> None:
        event = ct.cast(data, ct.POINTER(ExecveEvent)).contents
        payload = self._build_execve_event(event)
        self._producer.produce("endpoint-events", payload)

    def _on_connect(self, bpf, cpu, data, size) -> None:
        event = ct.cast(data, ct.POINTER(ConnectEvent)).contents
        payload = self._build_connect_event(event)
        self._producer.produce("network-events", payload)

    def _on_openat(self, bpf, cpu, data, size) -> None:
        event = ct.cast(data, ct.POINTER(OpenatEvent)).contents
        payload = self._build_openat_event(event)
        self._producer.produce("endpoint-events", payload)

    def stop(self) -> None:
        """Signal the sensor to stop."""
        self._running = False


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────

def main() -> None:
    """CLI entrypoint for the eBPF sensor agent."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    # Import here so this module can be loaded without Kafka deps for testing
    from .kafka_producer import CyberShieldKafkaProducer

    producer = CyberShieldKafkaProducer()
    sensor = EBPFSensor(kafka_producer=producer)
    sensor.start()
    producer.close()


if __name__ == "__main__":
    main()
