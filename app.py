"""
app.py -- ACF Dashboard (web UI)
"""

import os
import sqlite3
import subprocess
import time

from flask import Flask, Response, jsonify, render_template, request, g
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

from utils import load_config
from firewall import unblock_ip

app = Flask(__name__)
auth = HTTPBasicAuth()

# Basic Auth User Setup
USERS = {
    "admin": generate_password_hash("acfpassword123")
}

@auth.verify_password
def verify_password(username, password):
    if username in USERS and check_password_hash(USERS.get(username), password):
        return username

cfg = load_config("config.yml")
_dashboard_start_time = time.time()

REASON_CATEGORIES = {
    "port_scan": "port_scan",
    "syn_flood": "syn_flood",
    "repeated_port_probe": "repeated_port_probe",
    "possible_exfiltration": "exfiltration",
    "arp_spoofing": "arp_spoofing",
    "dns_tunneling": "dns_tunneling",
    "stealth_scan": "stealth_scan",
    "icmp_flood": "icmp_flood",
    "brute_force": "brute_force",
}


def get_db():
    db_path = cfg.get("db_path", "data/acf.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn
    
def categorize(rule_reason):
    if not rule_reason:
        return "ml_anomaly"
    for prefix, category in REASON_CATEGORIES.items():
        if rule_reason.startswith(prefix):
            return category
    return "ml_anomaly"


def check_service_status(service_name):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True, text=True, timeout=3,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


@app.route("/")
@auth.login_required
def index():
    return render_template("dashboard.html")


@app.route("/api/summary")
@auth.login_required
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


def get_db():
    db_path = cfg.get("db_path", "data/acf.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/api/health")
@auth.login_required
def api_health():
    conn = get_db()
    last_capture_ts = conn.execute("SELECT MAX(timestamp) FROM traffic").fetchone()[0]
    conn.close()

    model_path = cfg.get("model_path", "models/anomaly_model.pkl")
    model_last_trained = None
    if os.path.exists(model_path):
        model_last_trained = os.path.getmtime(model_path)

    db_path = cfg.get("db_path", "data/acf.db")
    db_size_bytes = 0
    if os.path.exists(db_path):
        db_size_bytes = os.path.getsize(db_path)

    return jsonify({
        "detect_service_status": check_service_status("acf-detect.service"),
        "dashboard_service_status": check_service_status("acf-dashboard.service"),
        "dashboard_uptime_seconds": round(time.time() - _dashboard_start_time),
        "model_last_trained": model_last_trained,
        "last_capture_ts": last_capture_ts,
        "db_size_bytes": db_size_bytes,
        "server_time": time.time(),
    })

@app.route("/api/alerts/<int:alert_id>/feedback", methods=["POST"])
@auth.login_required
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
@auth.login_required
def api_alerts():
    search = request.args.get("q", "").strip()
    reason_filter = request.args.get("reason", "").strip()
    feedback_filter = request.args.get("feedback", "").strip()
    limit = min(int(request.args.get("limit", 50)), 500)

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
    params.append(limit * 3 if reason_filter else limit)

    conn = get_db()
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()

    if reason_filter:
        rows = [r for r in rows if categorize(r["rule_reason"]) == reason_filter][:limit]

    return jsonify(rows)


@app.route("/api/stream-alerts")
@auth.login_required
def stream_alerts():
    def event_stream():
        last_seen_id = 0
        try:
            conn = get_db()
            row = conn.execute("SELECT MAX(id) as max_id FROM alerts").fetchone()
            if row and row["max_id"]:
                last_seen_id = row["max_id"]
            conn.close()
        except Exception:
            pass

        while True:
            try:
                conn = get_db()
                row = conn.execute("SELECT MAX(id) as max_id FROM alerts").fetchone()
                conn.close()

                current_max = row["max_id"] if (row and row["max_id"]) else 0

                if current_max > last_seen_id:
                    last_seen_id = current_max
                    yield "data: update\n\n"
            except Exception:
                pass

            time.sleep(1.5)

    return Response(event_stream(), mimetype="text/event-stream")


@app.route("/api/status")
@auth.login_required
def api_status():
    detection_active = False
    try:
        output = subprocess.check_output(["ps", "aux"]).decode("utf-8")
        for line in output.splitlines():
            if "main.py" in line and "--mode detect" in line and "grep" not in line:
                detection_active = True
                break
    except Exception:
        detection_active = False

    return jsonify({
        "status": "Active" if detection_active else "Inactive",
        "active": detection_active
    })


@app.route("/api/alert-breakdown")
@auth.login_required
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
@auth.login_required
def api_blocklist():
    conn = get_db()
    rows = conn.execute(
        "SELECT ip, blocked_at, reason, dry_run FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/blocklist/<ip>/unblock", methods=["POST"])
@auth.login_required
def api_unblock(ip):
    conn = get_db()
    exists = conn.execute("SELECT ip FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    if not exists:
        conn.close()
        return jsonify({"error": f"{ip} is not currently blocked"}), 404

    unblock_ip(conn, ip, dry_run=cfg.get("dry_run", True))
    conn.close()
    return jsonify({"ip": ip, "unblocked": True})


TIMELINE_RANGES = {
    "30m": (30 * 60, 60),
    "1h": (60 * 60, 120),
    "6h": (6 * 60 * 60, 600),
    "24h": (24 * 60 * 60, 1800),
}


@app.route("/api/traffic-timeline")
@auth.login_required
def api_traffic_timeline():
    range_key = request.args.get("range", "30m")
    window_seconds, bucket_seconds = TIMELINE_RANGES.get(range_key, TIMELINE_RANGES["30m"])

    conn = get_db()
    now = time.time()
    window_start = now - window_seconds
    rows = conn.execute(
        f"SELECT CAST(timestamp / {bucket_seconds} AS INTEGER) * {bucket_seconds} AS bucket, "
        f"COUNT(*) as count FROM traffic WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket",
        (window_start,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/top-offenders")
@auth.login_required
def api_top_offenders():
    limit = min(int(request.args.get("limit", 10)), 50)
    conn = get_db()
    rows = conn.execute(
        """
        SELECT a.src_ip,
               COUNT(*) as alert_count,
               MAX(a.timestamp) as last_seen,
               (SELECT rule_reason FROM alerts a2
                WHERE a2.src_ip = a.src_ip ORDER BY a2.id DESC LIMIT 1) as last_reason,
               (SELECT 1 FROM blocked_ips b WHERE b.ip = a.src_ip) as is_blocked
        FROM alerts a
        GROUP BY a.src_ip
        ORDER BY alert_count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
