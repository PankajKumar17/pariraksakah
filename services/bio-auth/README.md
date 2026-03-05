# Bio-Auth Service

Bio-Cyber Fusion Authentication (BCFA) for CyberShield-X — continuous authentication using involuntary physiological signals.

## Features
- ECG cardiac fingerprint processing (smartwatch integration)
- Keystroke micro-tremor dynamics at 1000Hz
- Siamese Neural Network for multi-signal fusion
- Continuous trust scoring every 30 seconds
- On-device processing via WASM (privacy-first)

## Run locally
```bash
pip install -r requirements.txt
uvicorn src.api.bio_auth_api:app --reload --port 8005
```
