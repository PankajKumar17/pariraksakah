# Threat Detection Service

AI-Powered Advanced Threat Detection Engine (ATDE) — the core ML inference pipeline of CyberShield-X.

## Features
- Real-time Kafka event ingestion (network, endpoint, auth, DNS events)
- Graph Neural Network (GAT) for network threat classification
- User & Entity Behavior Analytics (UEBA) anomaly detection
- MITRE ATT&CK auto-mapping
- SHAP-based explainability
- <5ms inference latency target

## Run locally
```bash
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8001
```
