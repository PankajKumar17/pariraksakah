"""
CyberShield-X Dataset Generator — D1: Network Intrusion Detection Dataset
Generates datasets/network_intrusion.csv with 5000 rows.
"""

import csv
import os
import uuid
import random
import math
from datetime import datetime, timedelta

random.seed(42)

COLUMNS = [
    "event_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes_sent", "bytes_received", "packets_sent", "packets_received",
    "flow_duration_ms", "tcp_flags", "ttl", "connection_frequency",
    "unique_dst_ips", "unique_dst_ports", "failed_connections", "bytes_per_packet",
    "is_off_hours", "geo_country", "is_known_threat_ip", "dns_query_count",
    "avg_inter_arrival_ms", "attack_type", "is_attack", "severity",
    "mitre_technique_id", "confidence_score"
]

ATTACK_DIST = {
    "BENIGN": 3000, "PortScan": 400, "BruteForce": 350, "DDoS": 300,
    "C2_Beaconing": 250, "DataExfiltration": 250, "LateralMovement": 200,
    "Ransomware": 150, "ZeroDay": 100,
}

MITRE_MAP = {
    "PortScan": "T1046", "BruteForce": "T1110", "DDoS": "T1498",
    "C2_Beaconing": "T1071", "DataExfiltration": "T1041",
    "LateralMovement": "T1021", "Ransomware": "T1486", "ZeroDay": "T1190",
    "BENIGN": "N/A",
}

SEVERITY_MAP = {
    "BENIGN": "NONE", "PortScan": "MEDIUM", "BruteForce": "HIGH",
    "DDoS": "HIGH", "C2_Beaconing": "HIGH", "DataExfiltration": "CRITICAL",
    "LateralMovement": "HIGH", "Ransomware": "CRITICAL", "ZeroDay": "CRITICAL",
}

COUNTRIES = ["US", "CN", "RU", "IN", "GB", "BR", "KR", "NG", "DE", "JP"]
PROTOCOLS = ["TCP"] * 65 + ["UDP"] * 25 + ["ICMP"] * 10
TCP_FLAGS_OPTIONS = ["SYN", "SYN,ACK", "ACK", "FIN", "RST", "PSH,ACK", "SYN,FIN", "RST,ACK"]
COMMON_PORTS = [22, 80, 443, 3389, 445, 8080, 53, 25, 110, 993]

START_DATE = datetime(2024, 1, 1)
END_DATE = datetime(2024, 12, 31)
TOTAL_SECONDS = int((END_DATE - START_DATE).total_seconds())


def random_ip(internal=False):
    if internal:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_timestamp():
    offset = random.randint(0, TOTAL_SECONDS)
    dt = START_DATE + timedelta(seconds=offset)
    # More attacks at night
    return dt


def gen_row(attack_type, add_noise=False):
    ts = random_timestamp()
    hour = ts.hour
    is_off = hour >= 23 or hour < 6
    proto = random.choice(PROTOCOLS)
    dst_port = random.choice(COMMON_PORTS) if random.random() < 0.6 else random.randint(1024, 65535)

    # Base values
    row = {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts.isoformat(),
        "src_ip": random_ip(internal=random.random() < 0.5),
        "dst_ip": random_ip(internal=random.random() < 0.7),
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": proto,
        "tcp_flags": random.choice(TCP_FLAGS_OPTIONS) if proto == "TCP" else "",
        "ttl": random.randint(32, 128),
        "is_off_hours": is_off,
        "geo_country": random.choice(COUNTRIES),
    }

    # Attack-specific feature distributions
    if attack_type == "BENIGN":
        row["bytes_sent"] = random.randint(100, 50000)
        row["bytes_received"] = random.randint(100, 80000)
        row["packets_sent"] = random.randint(1, 200)
        row["packets_received"] = random.randint(1, 300)
        row["flow_duration_ms"] = random.randint(50, 5000)
        row["connection_frequency"] = round(random.uniform(0.1, 5.0), 2)
        row["unique_dst_ips"] = random.randint(1, 10)
        row["unique_dst_ports"] = random.randint(1, 5)
        row["failed_connections"] = random.randint(0, 2)
        row["dns_query_count"] = random.randint(0, 20)
        row["avg_inter_arrival_ms"] = round(random.uniform(50, 5000), 1)
        row["is_known_threat_ip"] = False
        row["confidence_score"] = round(random.uniform(0.0, 0.3), 3)
    elif attack_type == "PortScan":
        row["bytes_sent"] = random.randint(40, 200)
        row["bytes_received"] = random.randint(0, 100)
        row["packets_sent"] = random.randint(1, 5)
        row["packets_received"] = random.randint(0, 3)
        row["flow_duration_ms"] = random.randint(1, 100)
        row["connection_frequency"] = round(random.uniform(50, 500), 2)
        row["unique_dst_ips"] = random.randint(50, 500)
        row["unique_dst_ports"] = random.randint(100, 1000)
        row["failed_connections"] = random.randint(20, 200)
        row["dns_query_count"] = random.randint(0, 5)
        row["avg_inter_arrival_ms"] = round(random.uniform(0.5, 10), 1)
        row["is_known_threat_ip"] = random.random() < 0.05
        row["confidence_score"] = round(random.uniform(0.7, 0.99), 3)
    elif attack_type == "BruteForce":
        row["dst_port"] = random.choice([22, 3389, 445, 21])
        row["bytes_sent"] = random.randint(100, 1000)
        row["bytes_received"] = random.randint(50, 500)
        row["packets_sent"] = random.randint(5, 50)
        row["packets_received"] = random.randint(5, 50)
        row["flow_duration_ms"] = random.randint(100, 2000)
        row["connection_frequency"] = round(random.uniform(20, 200), 2)
        row["unique_dst_ips"] = random.randint(1, 3)
        row["unique_dst_ports"] = random.randint(1, 2)
        row["failed_connections"] = random.randint(50, 500)
        row["dns_query_count"] = random.randint(0, 3)
        row["avg_inter_arrival_ms"] = round(random.uniform(100, 2000), 1)
        row["is_known_threat_ip"] = random.random() < 0.1
        row["confidence_score"] = round(random.uniform(0.75, 0.98), 3)
    elif attack_type == "DDoS":
        row["bytes_sent"] = random.randint(500000, 50000000)
        row["bytes_received"] = random.randint(0, 1000)
        row["packets_sent"] = random.randint(10000, 500000)
        row["packets_received"] = random.randint(0, 100)
        row["flow_duration_ms"] = random.randint(1000, 30000)
        row["connection_frequency"] = round(random.uniform(500, 10000), 2)
        row["unique_dst_ips"] = random.randint(1, 3)
        row["unique_dst_ports"] = random.randint(1, 5)
        row["failed_connections"] = random.randint(100, 5000)
        row["dns_query_count"] = random.randint(0, 2)
        row["avg_inter_arrival_ms"] = round(random.uniform(0.01, 1), 3)
        row["is_known_threat_ip"] = random.random() < 0.15
        row["confidence_score"] = round(random.uniform(0.85, 0.99), 3)
    elif attack_type == "C2_Beaconing":
        beacon_interval = random.choice([60000, 120000, 300000, 600000])
        row["bytes_sent"] = random.randint(100, 5000)
        row["bytes_received"] = random.randint(100, 10000)
        row["packets_sent"] = random.randint(1, 10)
        row["packets_received"] = random.randint(1, 15)
        row["flow_duration_ms"] = random.randint(500, 5000)
        row["connection_frequency"] = round(random.uniform(0.5, 2.0), 2)
        row["unique_dst_ips"] = random.randint(1, 3)
        row["unique_dst_ports"] = random.randint(1, 2)
        row["failed_connections"] = random.randint(0, 2)
        row["dns_query_count"] = random.randint(1, 5)
        row["avg_inter_arrival_ms"] = round(beacon_interval + random.uniform(-500, 500), 1)
        row["is_known_threat_ip"] = random.random() < 0.05
        row["confidence_score"] = round(random.uniform(0.65, 0.95), 3)
    elif attack_type == "DataExfiltration":
        row["bytes_sent"] = random.randint(1000000, 50000000)
        row["bytes_received"] = random.randint(100, 5000)
        row["packets_sent"] = random.randint(500, 50000)
        row["packets_received"] = random.randint(10, 200)
        row["flow_duration_ms"] = random.randint(5000, 60000)
        row["connection_frequency"] = round(random.uniform(0.1, 3.0), 2)
        row["unique_dst_ips"] = random.randint(1, 5)
        row["unique_dst_ports"] = random.randint(1, 3)
        row["failed_connections"] = random.randint(0, 3)
        row["dns_query_count"] = random.randint(5, 50)
        row["avg_inter_arrival_ms"] = round(random.uniform(100, 3000), 1)
        row["is_known_threat_ip"] = random.random() < 0.03
        row["confidence_score"] = round(random.uniform(0.80, 0.99), 3)
    elif attack_type == "LateralMovement":
        row["dst_port"] = random.choice([445, 135, 3389, 22, 5985])
        row["bytes_sent"] = random.randint(1000, 100000)
        row["bytes_received"] = random.randint(1000, 100000)
        row["packets_sent"] = random.randint(10, 500)
        row["packets_received"] = random.randint(10, 500)
        row["flow_duration_ms"] = random.randint(500, 30000)
        row["connection_frequency"] = round(random.uniform(5, 50), 2)
        row["unique_dst_ips"] = random.randint(10, 50)
        row["unique_dst_ports"] = random.randint(1, 5)
        row["failed_connections"] = random.randint(5, 30)
        row["dns_query_count"] = random.randint(5, 30)
        row["avg_inter_arrival_ms"] = round(random.uniform(500, 10000), 1)
        row["is_known_threat_ip"] = False
        row["confidence_score"] = round(random.uniform(0.70, 0.95), 3)
        row["src_ip"] = random_ip(internal=True)
        row["dst_ip"] = random_ip(internal=True)
    elif attack_type == "Ransomware":
        row["bytes_sent"] = random.randint(10000, 500000)
        row["bytes_received"] = random.randint(10000, 500000)
        row["packets_sent"] = random.randint(100, 5000)
        row["packets_received"] = random.randint(100, 5000)
        row["flow_duration_ms"] = random.randint(5000, 60000)
        row["connection_frequency"] = round(random.uniform(10, 100), 2)
        row["unique_dst_ips"] = random.randint(20, 200)
        row["unique_dst_ports"] = random.randint(1, 3)
        row["failed_connections"] = random.randint(10, 100)
        row["dns_query_count"] = random.randint(10, 100)
        row["avg_inter_arrival_ms"] = round(random.uniform(10, 500), 1)
        row["is_known_threat_ip"] = random.random() < 0.05
        row["confidence_score"] = round(random.uniform(0.85, 0.99), 3)
    elif attack_type == "ZeroDay":
        row["bytes_sent"] = random.randint(500, 100000)
        row["bytes_received"] = random.randint(500, 100000)
        row["packets_sent"] = random.randint(5, 200)
        row["packets_received"] = random.randint(5, 200)
        row["flow_duration_ms"] = random.randint(100, 10000)
        row["connection_frequency"] = round(random.uniform(1, 20), 2)
        row["unique_dst_ips"] = random.randint(1, 10)
        row["unique_dst_ports"] = random.randint(1, 10)
        row["failed_connections"] = random.randint(0, 10)
        row["dns_query_count"] = random.randint(0, 20)
        row["avg_inter_arrival_ms"] = round(random.uniform(100, 5000), 1)
        row["is_known_threat_ip"] = random.random() < 0.02
        row["confidence_score"] = round(random.uniform(0.50, 0.85), 3)

    row["bytes_per_packet"] = round(row["bytes_sent"] / max(row["packets_sent"], 1), 2)
    row["attack_type"] = attack_type
    row["is_attack"] = attack_type != "BENIGN"
    row["severity"] = SEVERITY_MAP[attack_type]
    row["mitre_technique_id"] = MITRE_MAP[attack_type]

    # 2% label noise
    if add_noise and random.random() < 0.02:
        row["is_attack"] = not row["is_attack"]

    return row


def main():
    rows = []
    for attack_type, count in ATTACK_DIST.items():
        for _ in range(count):
            rows.append(gen_row(attack_type, add_noise=True))

    random.shuffle(rows)

    outpath = "datasets/network_intrusion.csv"
    os.makedirs("datasets", exist_ok=True)
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Generated {len(rows)} rows -> {outpath}")


if __name__ == "__main__":
    main()
