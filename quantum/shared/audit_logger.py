import os
import json
import time
import hashlib
import psycopg2

class QuantumAuditLogger:
    """Unified audit logging writing to TimescaleDB quantum_audit_trail
    with simulated CRYSTALS-Dilithium quantum signature on every entry."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            self.conn = psycopg2.connect(
                host=os.environ.get("TIMESCALE_HOST", "timescaledb"),
                port=int(os.environ.get("TIMESCALE_PORT", 5432)),
                dbname=os.environ.get("TIMESCALE_DB", "cybershield"),
                user=os.environ.get("TIMESCALE_USER", "postgres"),
                password=os.environ.get("TIMESCALE_PASSWORD", "postgres")
            )
            self.conn.autocommit = True
        except Exception:
            self.conn = None

    def _quantum_sign(self, data: str) -> str:
        """Simulate CRYSTALS-Dilithium signature (calls crypto engine in production)."""
        return hashlib.sha3_512(f"dilithium-sig:{data}:{time.time()}".encode()).hexdigest()

    def log(self, action: str, component: str, outcome: str, details: dict = None):
        payload = json.dumps({
            "action": action,
            "service": self.service_name,
            "component": component,
            "outcome": outcome,
            "details": details or {},
            "ts": time.time()
        }, sort_keys=True)
        signature = self._quantum_sign(payload)

        if self.conn:
            try:
                with self.conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO quantum_audit_trail (action, quantum_service, component, outcome, quantum_signature) "
                        "VALUES (%s, %s, %s, %s, %s)",
                        (action, self.service_name, component, outcome, signature)
                    )
            except Exception:
                self._connect()

        return {"signature": signature, "logged": True}
