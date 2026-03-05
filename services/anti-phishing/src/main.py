"""CyberShield-X Anti-Phishing Service — Main Entry Point."""

import os
import logging
import time
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app, Counter, Histogram
from pydantic import BaseModel

from .phishing_classifier import PhishingClassifier
from .url_analyzer import URLAnalyzer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("anti-phishing")

REQUEST_COUNT = Counter("aphishing_requests_total", "Total requests", ["endpoint"])
DETECT_COUNT  = Counter("aphishing_detections_total", "Total detections", ["label"])
LATENCY       = Histogram("aphishing_latency_seconds", "Request latency", ["endpoint"])

app = FastAPI(
    title="CyberShield-X Anti-Phishing Engine",
    version="1.0.0",
    description="AI-powered phishing detection, URL analysis, and deepfake voice detection",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/metrics", make_asgi_app())

# ── Singletons ──────────────────────────────────
classifier = PhishingClassifier()
url_analyzer = URLAnalyzer()

# ── In-memory detection stats ───────────────────
_stats = {"emails_analyzed": 0, "urls_analyzed": 0, "phishing_blocked": 0, "legit_passed": 0}

# ── Schemas ─────────────────────────────────────

class EmailAnalyzeRequest(BaseModel):
    text: str
    sender: Optional[str] = None
    subject: Optional[str] = None

class URLAnalyzeRequest(BaseModel):
    url: str

class BatchEmailRequest(BaseModel):
    texts: List[str]

# ── Endpoints ────────────────────────────────────

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "anti-phishing",
        "version": "1.0.0",
        "stats": _stats,
    }

@app.post("/analyze/email")
async def analyze_email(req: EmailAnalyzeRequest):
    """Classify an email/message as phishing, spear-phishing, BEC, or legitimate."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_email").inc()

    full_text = f"Subject: {req.subject}\n\n{req.text}" if req.subject else req.text
    result = classifier.classify(full_text)

    _stats["emails_analyzed"] += 1
    if result.label != "legitimate":
        _stats["phishing_blocked"] += 1
    else:
        _stats["legit_passed"] += 1

    DETECT_COUNT.labels(label=result.label).inc()
    LATENCY.labels(endpoint="analyze_email").observe(time.time() - t0)

    return {
        "label": result.label,
        "confidence": round(result.confidence, 4),
        "probabilities": {k: round(v, 4) for k, v in result.probabilities.items()},
        "is_threat": result.label != "legitimate",
        "features_triggered": result.features_used,
        "sender": req.sender,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }

@app.post("/analyze/url")
async def analyze_url(req: URLAnalyzeRequest):
    """Analyze a URL for phishing indicators: homoglyphs, typosquatting, SSL, threat feeds."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_url").inc()

    result = await url_analyzer.analyze(req.url)

    _stats["urls_analyzed"] += 1
    if result.is_malicious:
        _stats["phishing_blocked"] += 1

    LATENCY.labels(endpoint="analyze_url").observe(time.time() - t0)

    return {
        "url": result.url,
        "risk_score": round(result.risk_score, 4),
        "is_malicious": result.is_malicious,
        "signals": result.signals,
        "homoglyph_detected": result.homoglyph_detected,
        "typosquat_target": result.typosquat_target,
        "threat_feed_hit": result.threat_feed_hit,
        "redirect_chain": result.redirect_chain,
        "cert_info": result.cert_info,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }

@app.post("/analyze/batch")
async def analyze_batch(req: BatchEmailRequest):
    """Batch classify multiple emails."""
    results = classifier.classify_batch(req.texts)
    _stats["emails_analyzed"] += len(results)
    return {
        "results": [
            {"label": r.label, "confidence": round(r.confidence, 4), "is_threat": r.label != "legitimate"}
            for r in results
        ],
        "total": len(results),
        "threats_found": sum(1 for r in results if r.label != "legitimate"),
    }

@app.get("/stats")
async def get_stats():
    return {"service": "anti-phishing", **_stats}

@app.on_event("startup")
async def startup_event():
    logger.info("Anti-Phishing Engine starting up — loading classifier...")
    classifier.load_model()
    logger.info("Anti-Phishing Engine ready. Classifier loaded=%s", classifier._loaded)
