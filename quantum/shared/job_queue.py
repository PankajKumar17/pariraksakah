import os
import json
import redis
import uuid
import time

class QuantumJobQueue:
    """Manage quantum circuit execution jobs using Redis-backed priority queue."""

    def __init__(self):
        self.redis = redis.Redis(
            host=os.environ.get("REDIS_HOST", "redis"),
            port=int(os.environ.get("REDIS_PORT", 6379)),
            db=4
        )
        self.timeout = 30  # seconds
        self.max_retries = 3

    def enqueue(self, job_type: str, payload: dict, priority: str = "normal") -> str:
        job_id = str(uuid.uuid4())
        job = {
            "job_id": job_id,
            "type": job_type,
            "payload": payload,
            "priority": priority,
            "status": "queued",
            "retries": 0,
            "created_at": time.time()
        }
        queue_key = "qjobs:critical" if priority == "critical" else "qjobs:normal"
        self.redis.lpush(queue_key, json.dumps(job))
        self.redis.set(f"qjob:{job_id}", json.dumps(job), ex=300)
        return job_id

    def dequeue(self) -> dict | None:
        # Critical priority first
        for queue in ["qjobs:critical", "qjobs:normal"]:
            raw = self.redis.rpop(queue)
            if raw:
                job = json.loads(raw)
                job["status"] = "running"
                self.redis.set(f"qjob:{job['job_id']}", json.dumps(job), ex=self.timeout)
                return job
        return None

    def complete(self, job_id: str, result: dict):
        raw = self.redis.get(f"qjob:{job_id}")
        if raw:
            job = json.loads(raw)
            job["status"] = "completed"
            job["result"] = result
            job["completed_at"] = time.time()
            self.redis.set(f"qjob:{job_id}", json.dumps(job), ex=600)

    def fail(self, job_id: str, error: str):
        raw = self.redis.get(f"qjob:{job_id}")
        if raw:
            job = json.loads(raw)
            job["retries"] = job.get("retries", 0) + 1
            if job["retries"] < self.max_retries:
                job["status"] = "retry"
                queue_key = "qjobs:critical" if job.get("priority") == "critical" else "qjobs:normal"
                self.redis.lpush(queue_key, json.dumps(job))
            else:
                job["status"] = "failed"
                job["error"] = error
            self.redis.set(f"qjob:{job_id}", json.dumps(job), ex=600)

    def get_status(self, job_id: str) -> dict | None:
        raw = self.redis.get(f"qjob:{job_id}")
        return json.loads(raw) if raw else None

    def stats(self) -> dict:
        return {
            "critical_queue": self.redis.llen("qjobs:critical"),
            "normal_queue": self.redis.llen("qjobs:normal"),
            "timeout_seconds": self.timeout,
            "max_retries": self.max_retries
        }
