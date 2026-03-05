"""
P07 — URL Analyzer
Multi-signal URL threat analysis: threat feeds, homoglyph detection,
typosquat detection, certificate transparency analysis.
"""

import hashlib
import logging
import re
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("cybershield.antiphishing.url_analyzer")

# ── Homoglyph map (partial — extend in production) ─────────

HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["а", "ɑ", "α"],  # Cyrillic а, Latin ɑ, Greek α
    "e": ["е", "ε", "ё"],
    "o": ["о", "ο", "0"],
    "i": ["і", "ι", "1", "l"],
    "c": ["с", "ϲ"],
    "p": ["р", "ρ"],
    "s": ["ѕ", "ꜱ"],
    "d": ["ԁ", "ɗ"],
    "g": ["ɡ", "ꞡ"],
    "n": ["ո", "ñ"],
}

# Well-known brands for typosquat detection
BRAND_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "paypal.com", "netflix.com", "linkedin.com",
    "github.com", "dropbox.com", "bankofamerica.com", "chase.com",
]


@dataclass
class URLAnalysisResult:
    url: str
    risk_score: float = 0.0
    is_malicious: bool = False
    signals: List[str] = field(default_factory=list)
    homoglyph_detected: bool = False
    typosquat_target: Optional[str] = None
    cert_info: Dict = field(default_factory=dict)
    threat_feed_hit: bool = False
    redirect_chain: List[str] = field(default_factory=list)


class URLAnalyzer:
    """Analyzes URLs for phishing indicators using multiple signals."""

    def __init__(self):
        self.threat_feed_hashes: set = set()
        self._load_threat_feeds()

    def _load_threat_feeds(self):
        """Load URL hash blocklist (stub — integrate with OSINT feeds)."""
        # In production: fetch from PhishTank, OpenPhish, URLhaus
        self.threat_feed_hashes = set()
        logger.info("Threat feeds loaded (stub)")

    # ── Core analysis ───────────────────────────

    async def analyze(self, url: str) -> URLAnalysisResult:
        """Run all analysis signals on a URL."""
        result = URLAnalysisResult(url=url)
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        # 1. Threat feed lookup
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        if url_hash in self.threat_feed_hashes:
            result.threat_feed_hit = True
            result.risk_score += 0.9
            result.signals.append("threat_feed_match")

        # 2. Homoglyph detection
        if self._detect_homoglyphs(domain):
            result.homoglyph_detected = True
            result.risk_score += 0.7
            result.signals.append("homoglyph_domain")

        # 3. Typosquat detection
        target = self._detect_typosquat(domain)
        if target:
            result.typosquat_target = target
            result.risk_score += 0.6
            result.signals.append(f"typosquat:{target}")

        # 4. Suspicious URL patterns
        pattern_score = self._check_url_patterns(url, parsed)
        result.risk_score += pattern_score

        # 5. Certificate analysis
        if parsed.scheme == "https":
            cert = self._check_certificate(domain)
            result.cert_info = cert
            if cert.get("suspicious"):
                result.risk_score += 0.3
                result.signals.append("suspicious_cert")

        # 6. Follow redirects
        result.redirect_chain = await self._follow_redirects(url)
        if len(result.redirect_chain) > 3:
            result.risk_score += 0.2
            result.signals.append(f"redirect_chain:{len(result.redirect_chain)}")

        result.risk_score = min(result.risk_score, 1.0)
        result.is_malicious = result.risk_score >= 0.6
        return result

    # ── Signal detectors ────────────────────────

    def _detect_homoglyphs(self, domain: str) -> bool:
        """Check if domain contains lookalike Unicode characters."""
        for char in domain:
            for _original, glyphs in HOMOGLYPHS.items():
                if char in glyphs:
                    return True
        return False

    def _detect_typosquat(self, domain: str) -> Optional[str]:
        """Check if domain is a typosquat of a known brand."""
        domain_base = domain.split(".")[0] if "." in domain else domain
        for brand in BRAND_DOMAINS:
            brand_base = brand.split(".")[0]
            dist = self._levenshtein(domain_base, brand_base)
            if 0 < dist <= 2:
                return brand
        return None

    def _check_url_patterns(self, url: str, parsed) -> float:
        """Score suspicious URL patterns."""
        score = 0.0
        path = parsed.path or ""

        # IP address as hostname
        if parsed.hostname and re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.hostname):
            score += 0.4

        # Excessive subdomains
        if parsed.hostname and parsed.hostname.count(".") > 3:
            score += 0.2

        # Suspicious keywords in path
        suspicious_paths = ["login", "verify", "secure", "update", "confirm", "account", "signin"]
        for kw in suspicious_paths:
            if kw in path.lower():
                score += 0.1

        # @ symbol in URL (credential harvesting)
        if "@" in url:
            score += 0.5

        # Very long URL
        if len(url) > 200:
            score += 0.15

        # Data URI or javascript
        if parsed.scheme in ("data", "javascript"):
            score += 0.9

        return min(score, 0.8)

    def _check_certificate(self, domain: str) -> Dict:
        """Inspect TLS certificate for suspicious attributes."""
        info: Dict = {"domain": domain, "suspicious": False}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()

            info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            info["not_after"] = cert.get("notAfter", "")
            info["subject"] = dict(x[0] for x in cert.get("subject", []))

            # Free / short-lived certs from LE are common in phishing
            issuer_org = info["issuer"].get("organizationName", "")
            if "Let's Encrypt" in issuer_org:
                info["free_cert"] = True

            # Recently issued
            not_before = cert.get("notBefore", "")
            if not_before:
                try:
                    issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                    if (datetime.now(timezone.utc) - issued.replace(tzinfo=timezone.utc)).days < 7:
                        info["suspicious"] = True
                        info["recently_issued"] = True
                except ValueError:
                    pass

        except Exception as e:
            info["error"] = str(e)
            info["suspicious"] = True

        return info

    async def _follow_redirects(self, url: str, max_hops: int = 10) -> List[str]:
        """Follow HTTP redirects and record the chain."""
        chain: List[str] = [url]
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
                current = url
                for _ in range(max_hops):
                    resp = await client.get(current)
                    if resp.is_redirect and "location" in resp.headers:
                        current = resp.headers["location"]
                        chain.append(current)
                    else:
                        break
        except Exception:
            pass
        return chain

    # ── Utilities ───────────────────────────────

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return URLAnalyzer._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[len(s2)]
