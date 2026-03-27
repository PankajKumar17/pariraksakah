# Anti-Phishing Service

AI Anti-Phishing & Social Engineering Defense Engine for CyberShield-X.

## Features
- Transformer-based phishing email classification (DistilBERT)
- URL reputation analysis + sandbox detonation (Playwright)
- Real-time deepfake voice detection
- Psychographic Attack Prediction Engine (PAPE)
- Analyst feedback persistence for retraining workflows

## Current Runtime Notes
- `/analyze/email` and `/analyze/url` are intended to work as primary production demo endpoints.
- `/analyze/detonate` uses full Playwright browser detonation when Chromium is installed.
- If Chromium is unavailable, `/analyze/detonate` now falls back to a degraded HTTP fetch + form inspection path instead of hard failing.
- `/analyze/voice` falls back to a lightweight FFT-based extractor if the librosa stack is unavailable at runtime.
- The phishing classifier now defaults to offline-safe startup behavior and falls back to heuristics if the transformer model is not cached locally.

## Run locally
```bash
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8003
```
