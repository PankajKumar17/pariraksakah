"""
P07 — URL Detonator
Headless browser sandbox using Playwright for dynamic URL analysis.
Captures screenshots, DOM mutations, credential form detection, and
network requests for phishing verdict.
"""

import asyncio
import hashlib
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("cybershield.antiphishing.url_detonator")


@dataclass
class DetonationResult:
    url: str
    final_url: str = ""
    screenshot_path: Optional[str] = None
    dom_snapshot: Optional[str] = None
    network_requests: List[Dict] = field(default_factory=list)
    credential_forms: List[Dict] = field(default_factory=list)
    javascript_alerts: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    verdict: str = "unknown"
    detonation_time_ms: float = 0.0


class URLDetonator:
    """Sandbox URL detonation using headless Chromium (Playwright)."""

    def __init__(self, screenshot_dir: Optional[str] = None):
        self.screenshot_dir = screenshot_dir or tempfile.mkdtemp(prefix="cybershield_det_")
        os.makedirs(self.screenshot_dir, exist_ok=True)

    async def detonate(self, url: str, timeout_ms: int = 30000) -> DetonationResult:
        """Load URL in a sandboxed browser and analyse behaviour."""
        result = DetonationResult(url=url)
        start = datetime.now(timezone.utc)

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("Playwright not installed — returning stub result")
            result.verdict = "skipped"
            return result

        network_log: List[Dict] = []
        alerts: List[str] = []

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-gpu",
                        "--disable-dev-shm-usage",
                        "--disable-extensions",
                    ],
                )
                ctx = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
                    ),
                    ignore_https_errors=True,
                )
                page = await ctx.new_page()

                # Capture network requests
                page.on("request", lambda req: network_log.append({
                    "url": req.url,
                    "method": req.method,
                    "resource_type": req.resource_type,
                }))

                # Capture alerts/dialogs
                page.on("dialog", lambda dialog: (
                    alerts.append(dialog.message),
                    asyncio.ensure_future(dialog.dismiss()),
                ))

                # Navigate
                await page.goto(url, timeout=timeout_ms, wait_until="networkidle")
                result.final_url = page.url

                # Screenshot
                url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
                ss_path = os.path.join(self.screenshot_dir, f"{url_hash}.png")
                await page.screenshot(path=ss_path, full_page=True)
                result.screenshot_path = ss_path

                # DOM snapshot
                result.dom_snapshot = await page.content()

                # Detect credential forms
                result.credential_forms = await self._detect_credential_forms(page)

                result.network_requests = network_log
                result.javascript_alerts = alerts

                await browser.close()

        except Exception as e:
            logger.error("Detonation failed for %s: %s", url, e)
            result.verdict = "error"

        elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
        result.detonation_time_ms = elapsed

        # Score
        result.risk_score = self._compute_risk(result)
        result.verdict = "malicious" if result.risk_score >= 0.6 else "clean"

        return result

    async def _detect_credential_forms(self, page) -> List[Dict]:
        """Detect login/credential harvest forms in the page."""
        forms = []
        try:
            form_els = await page.query_selector_all("form")
            for form in form_els:
                inputs = await form.query_selector_all("input")
                input_types = []
                for inp in inputs:
                    itype = await inp.get_attribute("type") or "text"
                    iname = await inp.get_attribute("name") or ""
                    input_types.append({"type": itype, "name": iname})

                has_password = any(i["type"] == "password" for i in input_types)
                has_email = any(
                    i["type"] in ("email", "text") and any(
                        kw in i["name"].lower()
                        for kw in ("email", "user", "login", "account")
                    )
                    for i in input_types
                )

                if has_password or has_email:
                    action = await form.get_attribute("action") or ""
                    forms.append({
                        "action": action,
                        "has_password": has_password,
                        "has_email": has_email,
                        "inputs": input_types,
                    })
        except Exception:
            pass
        return forms

    def _compute_risk(self, result: DetonationResult) -> float:
        """Score detonation results."""
        score = 0.0

        # Credential forms are a strong signal
        if result.credential_forms:
            score += 0.5

        # URL changed domain after redirect
        if result.final_url and result.url:
            from urllib.parse import urlparse
            orig_host = urlparse(result.url).hostname
            final_host = urlparse(result.final_url).hostname
            if orig_host != final_host:
                score += 0.3

        # Excessive network requests to third parties
        if len(result.network_requests) > 50:
            score += 0.2

        # JavaScript alerts (social engineering)
        if result.javascript_alerts:
            score += 0.2

        return min(score, 1.0)
