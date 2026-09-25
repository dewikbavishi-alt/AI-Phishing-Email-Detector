import os
import json
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.environ.get("PHISHGUARD_DB_DIR", os.path.join(BASE_DIR, "database"))
DB_PATH = os.path.join(DB_DIR, "scans.db")


def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                ml_probability REAL NOT NULL,
                phishing_type TEXT,
                url_count INTEGER NOT NULL,
                details TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS trusted_senders (
                address TEXT PRIMARY KEY,
                added_at TEXT NOT NULL
            )
        """)


def get_trusted_senders():
    with get_connection() as conn:
        return {row[0] for row in conn.execute("SELECT address FROM trusted_senders")}


def list_trusted_senders():
    with get_connection() as conn:
        return conn.execute(
            "SELECT address, added_at FROM trusted_senders ORDER BY address"
        ).fetchall()


def add_trusted_sender(address):
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO trusted_senders (address, added_at) VALUES (?, ?)",
            (address.lower(), datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )


def remove_trusted_sender(address):
    with get_connection() as conn:
        conn.execute("DELETE FROM trusted_senders WHERE address = ?", (address.lower(),))


def save_scan(result):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (created_at, subject, sender, verdict, risk_score,
                               ml_probability, phishing_type, url_count, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                result["subject"],
                result["sender"],
                result["verdict"],
                result["risk_score"],
                result["ml_probability"],
                result["phishing_type"],
                len(result["urls"]),
                json.dumps(result),
            ),
        )
        return cursor.lastrowid


def get_scan(scan_id):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    if row is None:
        return None

    result = json.loads(row["details"])
    result["id"] = row["id"]
    result["created_at"] = row["created_at"]
    return result


def get_recent_scans(limit=20):
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def get_stats():
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_verdict = dict(conn.execute(
            "SELECT verdict, COUNT(*) FROM scans GROUP BY verdict"
        ).fetchall())
        by_type = conn.execute(
            """
            SELECT phishing_type, COUNT(*) AS n FROM scans
            WHERE phishing_type IS NOT NULL
            GROUP BY phishing_type ORDER BY n DESC
            """
        ).fetchall()

    return {
        "total": total,
        "phishing": by_verdict.get("Phishing", 0),
        "suspicious": by_verdict.get("Suspicious", 0),
        "safe": by_verdict.get("Safe", 0),
        "by_type": [(row[0], row[1]) for row in by_type],
    }
