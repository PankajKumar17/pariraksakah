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
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urljoin

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
    error_message: Optional[str] = None


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
            result.error_message = "playwright_not_installed"
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
            logger.warning("Playwright detonation failed for %s: %s", url, e)
            try:
                await self._http_fallback_detonation(
                    url=url,
                    timeout_ms=timeout_ms,
                    result=result,
                    original_error=str(e),
                )
            except Exception as fallback_error:
                logger.error(
                    "Fallback detonation failed for %s: %s",
                    url,
                    fallback_error,
                )
                result.verdict = "error"
                result.error_message = (
                    f"{e}; fallback_failed={fallback_error}"
                )

        elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
        result.detonation_time_ms = elapsed

        if result.verdict not in {"error", "skipped"}:
            result.risk_score = self._compute_risk(result)
            result.verdict = "malicious" if result.risk_score >= 0.6 else "clean"

        return result

    async def _http_fallback_detonation(
        self,
        url: str,
        timeout_ms: int,
        result: DetonationResult,
        original_error: str,
    ) -> None:
        """Best-effort fallback when a headless browser is unavailable."""
        import httpx

        timeout_seconds = max(timeout_ms / 1000.0, 1.0)
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout_seconds) as client:
            response = await client.get(url)

        result.final_url = str(response.url)
        result.dom_snapshot = response.text[:50000]
        result.network_requests = [
            {
                "url": str(item.url),
                "method": item.request.method,
                "resource_type": "document",
                "status_code": item.status_code,
            }
            for item in [*response.history, response]
        ]
        result.credential_forms = self._detect_credential_forms_from_html(
            html=response.text,
            base_url=str(response.url),
        )
        result.error_message = f"{original_error}; degraded_mode=http_fallback"

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

    def _detect_credential_forms_from_html(self, html: str, base_url: str) -> List[Dict]:
        """Detect credential-looking forms from static HTML when browser execution is unavailable."""
        forms: List[Dict] = []
        for form_match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
            attrs = form_match.group(1) or ""
            body = form_match.group(2) or ""
            inputs = []
            for input_match in re.finditer(r"<input\b([^>]*)>", body, re.IGNORECASE | re.DOTALL):
                raw_attrs = input_match.group(1) or ""
                itype = self._extract_html_attr(raw_attrs, "type") or "text"
                iname = self._extract_html_attr(raw_attrs, "name") or ""
                inputs.append({"type": itype.lower(), "name": iname})

            has_password = any(i["type"] == "password" for i in inputs)
            has_email = any(
                i["type"] in {"email", "text"} and any(
                    kw in i["name"].lower()
                    for kw in ("email", "user", "login", "account")
                )
                for i in inputs
            )
            if not (has_password or has_email):
                continue

            action = self._extract_html_attr(attrs, "action") or ""
            forms.append(
                {
                    "action": urljoin(base_url, action) if action else base_url,
                    "has_password": has_password,
                    "has_email": has_email,
                    "inputs": inputs,
                }
            )
        return forms

    @staticmethod
    def _extract_html_attr(raw_attrs: str, attr_name: str) -> str:
        pattern = rf'{attr_name}\s*=\s*["\']?([^"\'>\s]+)'
        match = re.search(pattern, raw_attrs, re.IGNORECASE)
        return match.group(1) if match else ""

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
