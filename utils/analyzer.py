import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

import joblib
import numpy as np
from bs4 import BeautifulSoup

from utils.preprocessing import preprocess
from utils.url_checker import analyze_urls

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "model", "detector.pkl")

TYPE_LABELS = {
    "credential_harvesting": "Credential harvesting",
    "urgency": "Urgency / pressure",
    "financial_scam": "Financial scam",
    "authority_scam": "Authority impersonation",
    "romance_dating": "Romance scam",
    "generic_phishing": "Generic phishing",
    "threats": "Threats / intimidation",
    "tech_support": "Tech support scam",
    "social_engineering": "Social engineering",
    "social_engineering_advanced": "Advanced social engineering",
}

_bundle = None


def load_model():
    global _bundle

    if _bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                "Model not found. Run 'python train_model.py' first."
            )
        _bundle = joblib.load(MODEL_PATH)

    return _bundle


def parse_eml(raw_bytes):
    """Read an uploaded .eml file into subject, sender, headers and body."""
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    body_part = message.get_body(preferencelist=("plain", "html"))
    body = body_part.get_content() if body_part else ""

    if body_part is not None and body_part.get_content_type() == "text/html":
        html = body
        body = BeautifulSoup(html, "html.parser").get_text("\n")
        # Keep link targets so the URL checker can see them
        hrefs = re.findall(r'href=["\']([^"\']+)', html, re.IGNORECASE)
        body += "\n" + "\n".join(hrefs)

    return {
        "subject": str(message.get("Subject", "")),
        "sender": str(message.get("From", "")),
        "headers": {key: str(value) for key, value in message.items()},
        "body": body,
    }


def _domain(address):
    _, email_address = parseaddr(address or "")
    return email_address.rsplit("@", 1)[-1].lower() if "@" in email_address else ""


def analyze_headers(headers):
    """Spot common sender-spoofing signs in the email headers."""
    findings = []

    if not headers:
        return findings

    sender = headers.get("From", "")
    display_name, _ = parseaddr(sender)
    from_domain = _domain(sender)

    reply_domain = _domain(headers.get("Reply-To", ""))
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(
            f"Reply-To domain ({reply_domain}) differs from sender domain ({from_domain})"
        )

    return_domain = _domain(headers.get("Return-Path", ""))
    if return_domain and from_domain and return_domain != from_domain:
        findings.append(
            f"Return-Path domain ({return_domain}) differs from sender domain ({from_domain})"
        )

    name_domain = re.search(r"[\w-]+\.(com|net|org|in|co)\b", display_name or "", re.IGNORECASE)
    if name_domain and from_domain and name_domain.group(0).lower() not in from_domain:
        findings.append(
            f"Display name shows '{name_domain.group(0)}' but the email comes from {from_domain}"
        )

    auth = headers.get("Authentication-Results", "").lower()
    for check in ("spf", "dkim", "dmarc"):
        if re.search(rf"{check}=(fail|softfail)", auth):
            findings.append(f"{check.upper()} authentication failed")

    return findings


def explain(clean_text, bundle, top_n=8):
    """Words in this email that pushed the model towards 'phishing'."""
    vector = bundle["vectorizer"].transform([clean_text])
    indices = vector.nonzero()[1]

    if len(indices) == 0:
        return []

    contributions = vector.toarray()[0][indices] * bundle["weights"][indices]
    names = bundle["vectorizer"].get_feature_names_out()

    order = np.argsort(contributions)[::-1]
    return [names[indices[i]] for i in order[:top_n] if contributions[i] > 0]


def analyze_email(body, subject="", sender="", headers=None):
    bundle = load_model()

    full_text = f"Subject: {subject}\n\n{body}" if subject else body
    clean_text = preprocess(full_text)
    vector = bundle["vectorizer"].transform([clean_text])

    ml_probability = float(bundle["model"].predict_proba(vector)[0][1])

    phishing_type = None
    if ml_probability >= 0.5:
        raw_type = bundle["type_model"].predict(vector)[0]
        phishing_type = TYPE_LABELS.get(raw_type, raw_type)

    urls = analyze_urls(full_text)
    max_url_score = max((u["score"] for u in urls), default=0)

    header_findings = analyze_headers(headers or {})

    # Combine the three signals into one 0-100 risk score
    risk_score = 0.7 * ml_probability * 100 + 0.3 * max_url_score
    risk_score += min(10 * len(header_findings), 30)

    # A dangerous link or spoofed sender is suspicious even if the wording looks normal
    if max_url_score >= 50 or len(header_findings) >= 2:
        risk_score = max(risk_score, 40)

    risk_score = int(round(min(risk_score, 100)))

    if risk_score >= 60:
        verdict = "Phishing"
    elif risk_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "subject": subject or "(no subject)",
        "sender": sender or "(unknown sender)",
        "body": body,
        "verdict": verdict,
        "risk_score": risk_score,
        "ml_probability": round(ml_probability, 4),
        "model_name": bundle["model_name"],
        "phishing_type": phishing_type,
        "keywords": explain(clean_text, bundle),
        "urls": urls,
        "header_findings": header_findings,
    }
