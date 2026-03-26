import os
import json
import hashlib
import redis

class QuantumCircuitCache:
    """Cache compiled Qiskit quantum circuits in Redis to avoid recompilation overhead."""
    
    def __init__(self):
        self.redis = redis.Redis(
            host=os.environ.get("REDIS_HOST", "redis"),
            port=int(os.environ.get("REDIS_PORT", 6379)),
            db=3
        )
        self.ttl = 3600  # 1 hour

    def _circuit_hash(self, circuit_params: dict) -> str:
        raw = json.dumps(circuit_params, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, circuit_params: dict):
        key = f"qcircuit:{self._circuit_hash(circuit_params)}"
        cached = self.redis.get(key)
        if cached:
            return json.loads(cached)
        return None

    def put(self, circuit_params: dict, result: dict):
        key = f"qcircuit:{self._circuit_hash(circuit_params)}"
        self.redis.setex(key, self.ttl, json.dumps(result))

    def invalidate(self, circuit_params: dict):
        key = f"qcircuit:{self._circuit_hash(circuit_params)}"
        self.redis.delete(key)

    def stats(self) -> dict:
        keys = self.redis.keys("qcircuit:*")
        return {"cached_circuits": len(keys), "ttl_seconds": self.ttl}
