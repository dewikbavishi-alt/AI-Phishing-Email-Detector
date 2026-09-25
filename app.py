import os
import json

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, Response

from utils.analyzer import analyze_email, parse_eml, load_model
from utils.database import (
    init_db, save_scan, get_scan, get_recent_scans, get_stats,
    get_trusted_senders, list_trusted_senders, add_trusted_sender, remove_trusted_sender,
)
from utils.report_generator import build_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
METRICS_PATH = os.path.join(BASE_DIR, "model", "metrics.json")
MAX_TEXT_LENGTH = 50_000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024   # 2 MB upload limit
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

init_db()


def load_metrics():
    if not os.path.exists(METRICS_PATH):
        return None
    with open(METRICS_PATH) as file:
        return json.load(file)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("email_file")

    if uploaded and uploaded.filename:
        if not uploaded.filename.lower().endswith((".eml", ".txt")):
            flash("Please upload a .eml or .txt file.")
            return redirect(url_for("home"))

        raw = uploaded.read()

        if uploaded.filename.lower().endswith(".eml"):
            email_data = parse_eml(raw)
        else:
            email_data = {"subject": "", "sender": "", "headers": {},
                          "body": raw.decode("utf-8", errors="replace")}
    else:
        sender = request.form.get("sender", "").strip()
        email_data = {
            "subject": request.form.get("subject", "").strip(),
            "sender": sender,
            # A pasted sender can still be checked for a spoofed display name
            "headers": {"From": sender} if sender else {},
            "body": request.form.get("body", "").strip(),
        }

    if not email_data["body"].strip():
        flash("Please paste an email or upload a file to analyze.")
        return redirect(url_for("home"))

    email_data["body"] = email_data["body"][:MAX_TEXT_LENGTH]

    result = analyze_email(**email_data, trusted_senders=get_trusted_senders())
    scan_id = save_scan(result)

    return redirect(url_for("result", scan_id=scan_id))


@app.route("/trust/<int:scan_id>", methods=["POST"])
def trust_sender(scan_id):
    scan = get_scan(scan_id)
    if scan is None or not scan.get("sender_address"):
        abort(404)

    add_trusted_sender(scan["sender_address"])
    flash(f"{scan['sender_address']} added to trusted senders. The email was scanned again.")

    # Re-scan the same email so the trust decision is applied (or explained)
    result = analyze_email(
        body=scan["body"],
        subject="" if scan["subject"] == "(no subject)" else scan["subject"],
        sender=scan["sender"],
        headers=scan.get("headers", {}),
        trusted_senders=get_trusted_senders(),
    )
    return redirect(url_for("result", scan_id=save_scan(result)))


@app.route("/untrust", methods=["POST"])
def untrust_sender():
    address = request.form.get("address", "")
    remove_trusted_sender(address)
    flash(f"{address} removed from trusted senders.")
    return redirect(url_for("dashboard"))


@app.route("/result/<int:scan_id>")
def result(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)
    return render_template("result.html", result=scan)


@app.route("/report/<int:scan_id>.pdf")
def report(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)
    return Response(
        build_report(scan),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=phishing_report_{scan_id}.pdf"},
    )


@app.route("/dashboard")
def dashboard():
    return render_template(
        "dashboard.html",
        stats=get_stats(),
        scans=get_recent_scans(),
        metrics=load_metrics(),
        trusted=list_trusted_senders(),
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    body = str(data.get("body", "")).strip()

    if not body:
        return jsonify({"error": "Field 'body' is required."}), 400

    result = analyze_email(
        body=body[:MAX_TEXT_LENGTH],
        subject=str(data.get("subject", "")),
        sender=str(data.get("sender", "")),
        trusted_senders=get_trusted_senders(),
    )
    result.pop("body")
    result.pop("headers")
    return jsonify(result)


@app.errorhandler(413)
def too_large(error):
    flash("That file is too large (limit 2 MB).")
    return redirect(url_for("home"))


if __name__ == "__main__":
    load_model()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
