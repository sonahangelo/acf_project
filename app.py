"""
app.py -- ACF Dashboard (web UI)

A local Flask app serving a live-updating dashboard over ACF's SQLite
database. Mostly read-only, with one write path: marking alert feedback
(false_positive / confirmed_threat), which feeds back into training via
ai_model.py's exclusion logic. Blocklist management (unblocking, etc.)
still goes through blocklist.py -- not exposed here.

Usage:
  python app.py
  Then open http://127.0.0.1:5050 in a browser.
"""

import sqlite3
import time

from flask import Flask, jsonify, render_template, request

from utils import load_config

app = Flask(__name__)
cfg = load_config("config.yml")

REASON_CATEGORIES = {
    "port_scan": "port_scan",
    "syn_flood": "syn_flood",
    "repeated_port_probe": "repeated_port_probe",
    "possible_exfiltration": "exfiltration",
    "arp_spoofing": "arp_spoofing",
}


def get_db():
    conn = sqlite3.connect(cfg["db_path"])
    conn.row_factory = sqlite3.Row
    return conn


def categorize(rule_reason):
    if not rule_reason:
        return "ml_anomaly"
    for prefix, category in REASON_CATEGORIES.items():
        if rule_reason.startswith(prefix):
            return category
    return "ml_anomaly"


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


@app.route("/api/alerts/<int:alert_id>/feedback", methods=["POST"])
def api_mark_feedback(alert_id):
    data = request.get_json(silent=True) or {}
    label = data.get("label")

    if label not in ("false_positive", "confirmed_threat", None):
        return jsonify({"error": "label must be 'false_positive', 'confirmed_threat', or null to clear"}), 400

    conn = get_db()
    exists = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not exists:
        conn.close()
        return jsonify({"error": f"no alert with id {alert_id}"}), 404

    conn.execute("UPDATE alerts SET feedback = ? WHERE id = ?", (label, alert_id))
    conn.commit()
    conn.close()

    return jsonify({"id": alert_id, "feedback": label})


@app.route("/api/alerts")
def api_alerts():
    search = request.args.get("q", "").strip()
    reason_filter = request.args.get("reason", "").strip()
    feedback_filter = request.args.get("feedback", "").strip()
    limit = min(int(request.args.get("limit", 50)), 200)

    query = ("SELECT id, timestamp, src_ip, dst_ip, action, score, rule_reason, "
              "top_reasons, feedback FROM alerts WHERE 1=1")
    params = []

    if search:
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR rule_reason LIKE ? OR top_reasons LIKE ?)"
        like = f"%{search}%"
        params += [like, like, like, like]

    if feedback_filter == "none":
        query += " AND feedback IS NULL"
    elif feedback_filter in ("false_positive", "confirmed_threat"):
        query += " AND feedback = ?"
        params.append(feedback_filter)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit * 3 if reason_filter else limit)  # overfetch a bit when filtering by category client-unfilterable in SQL cheaply

    conn = get_db()
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()

    if reason_filter:
        rows = [r for r in rows if categorize(r["rule_reason"]) == reason_filter][:limit]

    return jsonify(rows)


@app.route("/api/alert-breakdown")
def api_alert_breakdown():
    conn = get_db()
    rows = conn.execute("SELECT rule_reason FROM alerts").fetchall()
    conn.close()

    counts = {}
    for (rule_reason,) in rows:
        cat = categorize(rule_reason)
        counts[cat] = counts.get(cat, 0) + 1

    breakdown = [{"category": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]
    return jsonify(breakdown)


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
