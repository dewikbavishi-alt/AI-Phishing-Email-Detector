import re
import ipaddress
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu",
    "buzz", "click", "link", "work", "rest", "country", "support"
}

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "wallet", "unlock", "billing"
]

# Brands that are often impersonated, with the domains they really use
BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
}


def extract_urls(text):
    urls = []

    for match in URL_PATTERN.findall(text or ""):
        url = match.rstrip(".,;:!?")

        if url.lower().startswith("www."):
            url = "http://" + url

        if url not in urls:
            urls.append(url)

    return urls


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registered_domain(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(url):
    """Return a risk score (0-100) and the reasons for one URL."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    reasons = []
    score = 0

    if _is_ip(host):
        score += 35
        reasons.append("Uses a raw IP address instead of a domain name")

    if "@" in parsed.netloc:
        score += 30
        reasons.append("Contains '@', which hides the real destination")

    if host.startswith("xn--") or ".xn--" in host:
        score += 30
        reasons.append("Punycode domain (possible look-alike characters)")

    if _registered_domain(host) in SHORTENERS or host in SHORTENERS:
        score += 25
        reasons.append("URL shortener hides the real destination")

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"Top-level domain '.{tld}' is often used for abuse")

    if parsed.scheme == "http":
        score += 10
        reasons.append("Not encrypted (http instead of https)")

    if host.count(".") >= 4:
        score += 15
        reasons.append("Unusually many subdomains")

    if host.count("-") >= 2:
        score += 10
        reasons.append("Many hyphens in the domain name")

    if len(url) > 100:
        score += 10
        reasons.append("Very long URL")

    domain = _registered_domain(host)
    for brand, real_domains in BRANDS.items():
        if brand in host and domain not in real_domains:
            score += 35
            reasons.append(f"Mentions '{brand}' but is not an official {brand} domain")
            break

    found_words = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if found_words:
        score += min(5 * len(found_words), 15)
        reasons.append("Suspicious keywords: " + ", ".join(found_words))

    score = min(score, 100)

    if score >= 50:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return {"url": url, "domain": host, "score": score, "level": level, "reasons": reasons}


def analyze_urls(text):
    results = [analyze_url(url) for url in extract_urls(text)]
    results.sort(key=lambda r: r["score"], reverse=True)
    return results
