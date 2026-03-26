import os
import json
import redis

class QuantumHealthChecker:
    """Health check library reporting quantum service status."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.redis = redis.Redis(
            host=os.environ.get("REDIS_HOST", "redis"),
            port=int(os.environ.get("REDIS_PORT", 6379)),
            db=0
        )

    def check(self) -> dict:
        checks = {
            "service": self.service_name,
            "status": "healthy",
            "checks": {}
        }

        # Redis connectivity
        try:
            self.redis.ping()
            checks["checks"]["redis"] = "ok"
        except Exception:
            checks["checks"]["redis"] = "unreachable"
            checks["status"] = "degraded"

        # Circuit cache availability
        try:
            cache_keys = len(self.redis.keys("qcircuit:*"))
            checks["checks"]["circuit_cache"] = {"cached": cache_keys}
        except Exception:
            checks["checks"]["circuit_cache"] = "unavailable"

        # QRNG key material availability
        try:
            rng_available = self.redis.get("qrng:available_bytes")
            checks["checks"]["qrng_material"] = int(rng_available or 0)
        except Exception:
            checks["checks"]["qrng_material"] = 0

        return checks

    def register_heartbeat(self):
        self.redis.setex(f"quantum:heartbeat:{self.service_name}", 30, "alive")
