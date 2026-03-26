import os
import json
import redis

class QuantumDatasetLoader:
    """Shared utility loading and indexing datasets from /datasets/ into Redis."""

    def __init__(self):
        self.redis = redis.Redis(
            host=os.environ.get("REDIS_HOST", "redis"),
            port=int(os.environ.get("REDIS_PORT", 6379)),
            db=5
        )
        self.datasets_root = os.environ.get("DATASETS_PATH", "/datasets")

    def load_mitre_ttps(self) -> int:
        """Index MITRE ATT&CK TTPs for Grover oracle construction."""
        path = os.path.join(self.datasets_root, "mitre", "enterprise-attack.json")
        count = 0
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for obj in data.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    ttp_id = obj.get("external_references", [{}])[0].get("external_id", "")
                    if ttp_id:
                        self.redis.hset("quantum:mitre:ttps", ttp_id, json.dumps({
                            "name": obj.get("name", ""),
                            "description": obj.get("description", "")[:200],
                            "kill_chain": [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
                        }))
                        count += 1
        except FileNotFoundError:
            pass
        return count

    def load_malicious_ips(self) -> int:
        """Index malicious IPs for quantum threat search."""
        count = 0
        for filename in ["emerging-threats.txt", "firehol-level1.netset"]:
            path = os.path.join(self.datasets_root, "malicious-ips", filename)
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.redis.sadd("quantum:malicious:ips", line)
                            count += 1
            except FileNotFoundError:
                pass
        return count

    def load_cisa_kev(self) -> int:
        """Index CISA Known Exploited Vulnerabilities."""
        path = os.path.join(self.datasets_root, "stix", "cisa-kev.json")
        count = 0
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for vuln in data.get("vulnerabilities", data.get("objects", [])):
                cve_id = vuln.get("cveID", vuln.get("id", ""))
                if cve_id:
                    self.redis.hset("quantum:cisa:kev", cve_id, json.dumps(vuln))
                    count += 1
        except FileNotFoundError:
            pass
        return count

    def load_all(self) -> dict:
        mitre = self.load_mitre_ttps()
        ips = self.load_malicious_ips()
        kev = self.load_cisa_kev()
        return {"mitre_ttps": mitre, "malicious_ips": ips, "cisa_kev": kev}

    def get_malicious_ip_count(self) -> int:
        return self.redis.scard("quantum:malicious:ips")

    def is_malicious_ip(self, ip: str) -> bool:
        return self.redis.sismember("quantum:malicious:ips", ip)

    def get_ttp(self, ttp_id: str) -> dict | None:
        raw = self.redis.hget("quantum:mitre:ttps", ttp_id)
        return json.loads(raw) if raw else None
