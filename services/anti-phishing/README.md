# Anti-Phishing Service

AI Anti-Phishing & Social Engineering Defense Engine for CyberShield-X.

## Features
- Transformer-based phishing email classification (DistilBERT)
- URL reputation analysis + sandbox detonation (Playwright)
- Real-time deepfake voice detection
- Psychographic Attack Prediction Engine (PAPE)

## Run locally
```bash
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8003
```
