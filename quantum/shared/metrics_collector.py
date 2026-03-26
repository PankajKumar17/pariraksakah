import time
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Standardized Prometheus metrics for all quantum services

quantum_circuit_depth = Gauge(
    "quantum_circuit_depth", "Current quantum circuit depth", ["service", "algorithm"]
)
quantum_qubit_count = Gauge(
    "quantum_qubit_count", "Number of qubits in current circuit", ["service", "algorithm"]
)
quantum_execution_time_ms = Histogram(
    "quantum_execution_time_ms", "Quantum circuit execution time in ms",
    ["service", "algorithm"],
    buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000]
)
quantum_advantage_ratio = Gauge(
    "quantum_advantage_ratio", "Quantum speedup over classical baseline", ["service", "algorithm"]
)
quantum_error_rate = Gauge(
    "quantum_error_rate", "Quantum circuit error rate", ["service"]
)
quantum_key_generation_rate = Counter(
    "quantum_key_generation_rate", "Quantum keys generated", ["service", "algorithm"]
)
quantum_rng_bits_generated = Counter(
    "quantum_rng_bits_generated", "Quantum random bits generated", ["entropy_source"]
)
quantum_trust_verifications = Counter(
    "quantum_trust_verifications_total", "Total quantum trust verifications", ["decision"]
)
quantum_supply_chain_verifications = Counter(
    "quantum_supply_chain_verifications_total", "Supply chain verifications", ["result"]
)


class QuantumMetricsCollector:
    """Collect standardized metrics across all quantum services."""

    @staticmethod
    def record_circuit_execution(service: str, algorithm: str, depth: int, qubits: int, exec_ms: float):
        quantum_circuit_depth.labels(service=service, algorithm=algorithm).set(depth)
        quantum_qubit_count.labels(service=service, algorithm=algorithm).set(qubits)
        quantum_execution_time_ms.labels(service=service, algorithm=algorithm).observe(exec_ms)

    @staticmethod
    def record_advantage(service: str, algorithm: str, ratio: float):
        quantum_advantage_ratio.labels(service=service, algorithm=algorithm).set(ratio)

    @staticmethod
    def record_error_rate(service: str, rate: float):
        quantum_error_rate.labels(service=service).set(rate)

    @staticmethod
    def record_key_generated(service: str, algorithm: str):
        quantum_key_generation_rate.labels(service=service, algorithm=algorithm).inc()

    @staticmethod
    def get_metrics_response():
        return generate_latest(), CONTENT_TYPE_LATEST
