"""
app.py -- ACF Dashboard (read-only web UI)

A local Flask app that serves a live-updating dashboard over ACF's SQLite
database. Read-only: never modifies traffic/alerts/blocked_ips. Blocklist
management still goes through blocklist.py; this is for visibility only.

Usage:
  python app.py
  Then open http://127.0.0.1:5050 in a browser.
"""

import sqlite3
import time

from flask import Flask, jsonify, render_template

from utils import load_config

app = Flask(__name__)
cfg = load_config("config.yml")


def get_db():
    conn = sqlite3.connect(cfg["db_path"])
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/summary")
def api_summary():
    conn = get_db()
    traffic_count = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
    alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    first_ts = conn.execute("SELECT MIN(timestamp) FROM traffic").fetchone()[0]
    last_ts = conn.execute("SELECT MAX(timestamp) FROM traffic").fetchone()[0]
    conn.close()

    alert_rate = (alert_count / traffic_count * 100) if traffic_count else 0

    return jsonify({
        "traffic_count": traffic_count,
        "alert_count": alert_count,
        "blocked_count": blocked_count,
        "alert_rate": round(alert_rate, 4),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "dry_run": cfg.get("dry_run", True),
        "server_time": time.time(),
    })


@app.route("/api/alerts")
def api_alerts():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, timestamp, src_ip, dst_ip, action, score, rule_reason, "
        "top_reasons, feedback FROM alerts ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/blocklist")
def api_blocklist():
    conn = get_db()
    rows = conn.execute(
        "SELECT ip, blocked_at, reason, dry_run FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/traffic-timeline")
def api_traffic_timeline():
    """Bucket traffic into 1-minute windows for the sparkline, last 30 minutes."""
    conn = get_db()
    now = time.time()
    window_start = now - (30 * 60)
    rows = conn.execute(
        "SELECT CAST(timestamp / 60 AS INTEGER) * 60 AS bucket, COUNT(*) as count "
        "FROM traffic WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket",
        (window_start,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
