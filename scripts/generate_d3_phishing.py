"""
CyberShield-X Dataset Generator — D3: Phishing Email & URL Dataset
Generates datasets/phishing_emails.csv (2000 rows) and datasets/malicious_urls.csv (3000 rows).
"""

import csv
import os
import uuid
import random
from datetime import datetime, timedelta

random.seed(44)

# ─── Phishing Emails ────────────────────────────────────────
EMAIL_LABELS = {
    "LEGITIMATE": 1000, "PHISHING": 400, "SPEAR_PHISHING": 250,
    "BEC": 200, "MALWARE_DELIVERY": 150,
}

LEGIT_DOMAINS = ["google.com", "microsoft.com", "amazon.com", "apple.com", "github.com",
                 "slack.com", "zoom.us", "salesforce.com", "adobe.com", "oracle.com"]
PHISH_DOMAINS = ["g00gle-secure.com", "micros0ft-verify.net", "amaz0n-alert.com",
                 "app1e-support.org", "github-security.io", "slack-verify.com",
                 "z00m-meeting.net", "sa1esforce-login.com", "ad0be-update.net",
                 "0racle-cloud.com", "paypa1-secure.com", "dhl-tracking.info"]

SUBJECTS_LEGIT = ["Your weekly digest", "Invoice #INV-{}", "Meeting recap: Q4 planning",
                  "Welcome to the team!", "Your order has shipped", "Monthly report attached"]
SUBJECTS_PHISH = ["URGENT: Verify your account NOW", "Action Required: Suspicious login detected",
                  "Your account will be suspended", "Confirm your identity immediately",
                  "Payment failed — update billing info", "Security alert: unauthorized access"]
SUBJECTS_BEC = ["Wire transfer needed ASAP", "Confidential: Change of bank details",
                "CEO request: Urgent payment", "Updated vendor payment instructions"]

ATTACHMENT_TYPES = ["pdf", "docx", "exe", "zip", "none"]
SPF_RESULTS = ["pass", "fail", "neutral", "softfail"]
DKIM_RESULTS = ["pass", "fail", "none"]
DMARC_RESULTS = ["pass", "fail", "none"]
PHISH_KITS = ["unknown", "GoPhish", "EvilGinx", "Modlishka", "King_Phisher", "SocialFish"]

EMAIL_COLUMNS = [
    "email_id", "timestamp", "sender_email", "sender_domain", "sender_domain_age_days",
    "reply_to_different", "spf_result", "dkim_result", "dmarc_result",
    "subject_line", "body_word_count", "url_count", "suspicious_url_ratio",
    "attachment_present", "attachment_type", "urgency_word_count",
    "authority_claim", "personalization_score", "target_user_id",
    "has_credential_harvest_link", "has_malware_payload",
    "label", "is_phishing", "phishing_kit_family",
]

START_DATE = datetime(2024, 1, 1)


def gen_email(label):
    ts = START_DATE + timedelta(seconds=random.randint(0, 31536000))
    is_phish = label != "LEGITIMATE"

    if is_phish:
        domain = random.choice(PHISH_DOMAINS)
        sender = f"{random.choice(['support','security','admin','billing','noreply'])}@{domain}"
        domain_age = random.randint(1, 60)
        spf = random.choice(["fail", "softfail", "neutral"])
        dkim = random.choice(["fail", "none"])
        dmarc = random.choice(["fail", "none"])
    else:
        domain = random.choice(LEGIT_DOMAINS)
        sender = f"{random.choice(['no-reply','info','support','team','hello'])}@{domain}"
        domain_age = random.randint(365, 7000)
        spf = "pass"
        dkim = random.choice(["pass", "pass", "none"])
        dmarc = random.choice(["pass", "pass", "none"])

    if label == "BEC":
        subject = random.choice(SUBJECTS_BEC)
    elif is_phish:
        subject = random.choice(SUBJECTS_PHISH)
    else:
        subject = random.choice(SUBJECTS_LEGIT).format(random.randint(1000, 9999))

    urgency = random.randint(3, 8) if is_phish else random.randint(0, 1)
    authority = is_phish and random.random() < 0.7
    personalization = round(random.uniform(0.6, 1.0), 2) if label == "SPEAR_PHISHING" else round(random.uniform(0.0, 0.3), 2)
    has_cred = is_phish and label != "MALWARE_DELIVERY" and random.random() < 0.8
    has_malware = label == "MALWARE_DELIVERY"

    att_type = "none"
    if has_malware:
        att_type = random.choice(["exe", "zip", "docx"])
    elif not is_phish and random.random() < 0.3:
        att_type = random.choice(["pdf", "docx"])

    return {
        "email_id": str(uuid.uuid4()),
        "timestamp": ts.isoformat(),
        "sender_email": sender,
        "sender_domain": domain,
        "sender_domain_age_days": domain_age,
        "reply_to_different": is_phish and random.random() < 0.6,
        "spf_result": spf,
        "dkim_result": dkim,
        "dmarc_result": dmarc,
        "subject_line": subject,
        "body_word_count": random.randint(50, 500),
        "url_count": random.randint(2, 8) if is_phish else random.randint(0, 3),
        "suspicious_url_ratio": round(random.uniform(0.5, 1.0), 2) if is_phish else round(random.uniform(0.0, 0.1), 2),
        "attachment_present": att_type != "none",
        "attachment_type": att_type,
        "urgency_word_count": urgency,
        "authority_claim": authority,
        "personalization_score": personalization,
        "target_user_id": f"USER_{random.randint(1,200):03d}",
        "has_credential_harvest_link": has_cred,
        "has_malware_payload": has_malware,
        "label": label,
        "is_phishing": is_phish,
        "phishing_kit_family": random.choice(PHISH_KITS) if is_phish else "none",
    }


# ─── Malicious URLs ─────────────────────────────────────────
URL_LABELS = {
    "BENIGN": 1500, "PHISHING": 600, "MALWARE": 350,
    "SCAM": 250, "TYPOSQUAT": 150, "HOMOGLYPH": 150,
}

BRANDS = ["PayPal", "Microsoft", "Google", "Amazon", "DHL", "Apple", "Netflix", "Facebook"]
TLDS_LEGIT = [".com", ".org", ".net", ".io", ".co"]
TLDS_MALICIOUS = [".xyz", ".info", ".top", ".club", ".buzz", ".tk", ".ml", ".cf"]
CERT_ISSUERS = ["DigiCert", "Comodo", "Let's Encrypt", "GlobalSign", "Sectigo"]

URL_COLUMNS = [
    "url_id", "url", "domain", "tld", "domain_age_days", "url_length",
    "num_subdomains", "num_special_chars", "has_ip_in_url", "redirect_count",
    "uses_https", "cert_age_days", "cert_issuer", "page_title_brand_match",
    "has_login_form", "has_password_field", "favicon_hash",
    "google_index_status", "whois_privacy", "alexa_rank",
    "label", "is_malicious", "targeted_brand",
]


def gen_url(label):
    is_mal = label != "BENIGN"
    brand = random.choice(BRANDS) if is_mal else "none"

    if label == "BENIGN":
        domain_base = random.choice(["example", "mysite", "coolapp", "techblog", "newsportal"])
        tld = random.choice(TLDS_LEGIT)
        domain = f"{domain_base}{tld}"
        url = f"https://{domain}/{random.choice(['home','about','products','blog','login'])}"
        domain_age = random.randint(365, 7000)
        subs = random.randint(0, 1)
        special = random.randint(0, 2)
    elif label == "PHISHING":
        domain = f"{brand.lower()}-secure-login{random.choice(TLDS_MALICIOUS)}"
        tld = domain.split(".")[-1]
        url = f"https://verify.account.{domain}/signin?ref={uuid.uuid4().hex[:8]}"
        domain_age = random.randint(1, 30)
        subs = random.randint(2, 5)
        special = random.randint(3, 8)
    elif label == "MALWARE":
        domain = f"download-update{random.randint(1,999)}{random.choice(TLDS_MALICIOUS)}"
        tld = domain.split(".")[-1]
        url = f"http://{domain}/files/setup.exe"
        domain_age = random.randint(1, 15)
        subs = random.randint(0, 2)
        special = random.randint(2, 6)
    elif label == "SCAM":
        domain = f"free-{random.choice(['iphone','prize','gift','crypto'])}{random.choice(TLDS_MALICIOUS)}"
        tld = domain.split(".")[-1]
        url = f"https://{domain}/claim-now/{uuid.uuid4().hex[:6]}"
        domain_age = random.randint(1, 45)
        subs = random.randint(0, 3)
        special = random.randint(4, 10)
    elif label == "TYPOSQUAT":
        typos = {"PayPal": "paypa1", "Microsoft": "micros0ft", "Google": "go0gle",
                 "Amazon": "amaz0n", "Apple": "app1e", "Netflix": "netf1ix"}
        typo = typos.get(brand, brand.lower().replace("o", "0"))
        tld = random.choice(TLDS_LEGIT)
        domain = f"{typo}{tld}"
        url = f"https://{domain}/login"
        domain_age = random.randint(5, 90)
        subs = random.randint(0, 2)
        special = random.randint(1, 4)
    else:  # HOMOGLYPH
        domain = f"{brand.lower().replace('a', 'а').replace('e', 'е')}{random.choice(TLDS_LEGIT)}"
        tld = domain.split(".")[-1]
        url = f"https://{domain}/account/verify"
        domain_age = random.randint(1, 30)
        subs = random.randint(1, 3)
        special = random.randint(2, 5)

    has_ip = not is_mal and False or (is_mal and random.random() < 0.1)
    uses_https = random.random() < 0.95 if not is_mal else random.random() < 0.6
    cert_age = random.randint(365, 3000) if not is_mal else random.randint(1, 60)
    cert_issuer = random.choice(CERT_ISSUERS)
    has_login = is_mal and random.random() < 0.7
    has_pw = has_login and random.random() < 0.9
    indexed = "indexed" if not is_mal else random.choice(["not_indexed", "not_indexed", "indexed"])
    alexa = random.randint(1, 500000) if not is_mal else -1

    return {
        "url_id": str(uuid.uuid4()),
        "url": url,
        "domain": domain,
        "tld": f".{tld}" if not tld.startswith(".") else tld,
        "domain_age_days": domain_age,
        "url_length": len(url),
        "num_subdomains": subs,
        "num_special_chars": special,
        "has_ip_in_url": has_ip,
        "redirect_count": random.randint(0, 1) if not is_mal else random.randint(1, 6),
        "uses_https": uses_https,
        "cert_age_days": cert_age,
        "cert_issuer": cert_issuer,
        "page_title_brand_match": brand if is_mal else "none",
        "has_login_form": has_login,
        "has_password_field": has_pw,
        "favicon_hash": uuid.uuid4().hex[:16],
        "google_index_status": indexed,
        "whois_privacy": is_mal and random.random() < 0.7,
        "alexa_rank": alexa,
        "label": label,
        "is_malicious": is_mal,
        "targeted_brand": brand,
    }


def main():
    # Emails
    email_rows = []
    for label, count in EMAIL_LABELS.items():
        for _ in range(count):
            email_rows.append(gen_email(label))
    random.shuffle(email_rows)

    os.makedirs("datasets", exist_ok=True)
    with open("datasets/phishing_emails.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EMAIL_COLUMNS)
        writer.writeheader()
        writer.writerows(email_rows)
    print(f"Generated {len(email_rows)} rows -> datasets/phishing_emails.csv")

    # URLs
    url_rows = []
    for label, count in URL_LABELS.items():
        for _ in range(count):
            url_rows.append(gen_url(label))
    random.shuffle(url_rows)

    with open("datasets/malicious_urls.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=URL_COLUMNS)
        writer.writeheader()
        writer.writerows(url_rows)
    print(f"Generated {len(url_rows)} rows -> datasets/malicious_urls.csv")


if __name__ == "__main__":
    main()
