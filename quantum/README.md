# Quantum Security Suite

Complete 8-capability quantum security platform for Parirakṣakaḥ.

## Services

| Service | Language | Port | Description |
|---|---|---|---|
| quantum-crypto-engine | Rust | 8080 | Unified PQC API (Kyber, Dilithium, FALCON, SPHINCS+, BIKE, HQC) |
| quantum-qkd-simulator | Python | 8081 | QKD protocol simulation (BB84, E91, B92) |
| quantum-rng-service | Rust | 8082 | Quantum random number generation + NIST tests |
| quantum-threat-detector | Python | 8083 | Grover search, quantum pattern matching |
| quantum-ml-anomaly | Python | 8084 | QSVM, VQE, QNN, QGAN anomaly detection |
| quantum-supply-chain | Go | 8085 | Quantum-signed Merkle tree supply chain |
| quantum-attack-simulator | Python | 8086 | Shor/Grover attack simulation |
| quantum-zero-trust | Go | 8087 | Quantum-enhanced zero trust verification |
| quantum-dashboard-api | Go | 8088 | Unified quantum metrics API |

## Architecture

```
API Gateway (Go :8080) → NeuromorphicMiddleware → QuantumZeroTrust
         ↓                                           ↓
    Kafka Bus ←→ All Quantum Services ←→ Shared Utilities
         ↓                                    ↓
    TimescaleDB / Neo4j / Redis          QRNG + QKD Keys
```
