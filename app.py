"""
app.py -- ACF Dashboard (web UI)
"""

import os
import secrets
import sqlite3
import subprocess
import time
from ipaddress import ip_address

from flask import Flask, Response, jsonify, render_template, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.exceptions import BadRequest
from werkzeug.security import generate_password_hash, check_password_hash

from utils import load_config
from detection_metadata import categorize_reason, mitre_for_category
from firewall import cleanup_expired_blocks, unblock_ip

app = Flask(__name__)
auth = HTTPBasicAuth()

DEFAULT_DASHBOARD_PASSWORD = "acfpassword123"
DASHBOARD_USER = os.environ.get("ACF_DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.environ.get("ACF_DASHBOARD_PASSWORD")
DASHBOARD_PASSWORD_HASH = os.environ.get("ACF_DASHBOARD_PASSWORD_HASH")
ALLOW_DEFAULT_PASSWORD = os.environ.get("ACF_ALLOW_DEFAULT_PASSWORD", "").lower() in ("1", "true", "yes")
CSRF_TOKEN = os.environ.get("ACF_CSRF_TOKEN") or secrets.token_urlsafe(32)

if DASHBOARD_PASSWORD_HASH:
    _dashboard_password_hash = DASHBOARD_PASSWORD_HASH
elif DASHBOARD_PASSWORD:
    _dashboard_password_hash = generate_password_hash(DASHBOARD_PASSWORD)
else:
    _dashboard_password_hash = generate_password_hash(DEFAULT_DASHBOARD_PASSWORD)

USERS = {DASHBOARD_USER: _dashboard_password_hash}


def using_insecure_default_password():
    return not (DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH or ALLOW_DEFAULT_PASSWORD)

@auth.verify_password
def verify_password(username, password):
    if username in USERS and check_password_hash(USERS.get(username), password):
        return username

cfg = load_config("config.yml")
_dashboard_start_time = time.time()

def get_db():
    db_path = cfg.get("db_path", "data/acf.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn
    
def categorize(rule_reason):
    category = categorize_reason(rule_reason)
    return "exfiltration" if category == "possible_exfiltration" else category


@app.before_request
def enforce_dashboard_security():
    if using_insecure_default_password() and not app.config.get("TESTING"):
        return jsonify({
            "error": "dashboard credentials are not configured",
            "details": "Set ACF_DASHBOARD_PASSWORD or ACF_DASHBOARD_PASSWORD_HASH before exposing ACF.",
        }), 503

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.headers.get("X-ACF-CSRF-Token")
        if not secrets.compare_digest(token or "", CSRF_TOKEN):
            return jsonify({"error": "missing or invalid CSRF token"}), 403


def parse_int_arg(name, default, minimum, maximum):
    raw = request.args.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise BadRequest(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise BadRequest(f"{name} must be between {minimum} and {maximum}")
    return value



@app.errorhandler(BadRequest)
def handle_bad_request(error):
    return jsonify({"error": error.description}), 400


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
    return render_template("dashboard.html", csrf_token=CSRF_TOKEN)


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
    limit = parse_int_arg("limit", 50, 1, 500)

    query = ("SELECT id, timestamp, src_ip, dst_ip, action, score, rule_reason, "
              "top_reasons, feedback, severity, mitre_technique, mitre_tactic FROM alerts WHERE 1=1")
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
    cleanup_expired_blocks(conn, dry_run=cfg.get("dry_run", True))
    rows = conn.execute(
        "SELECT ip, blocked_at, reason, dry_run, expires_at FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/blocklist/<ip>/unblock", methods=["POST"])
@auth.login_required
def api_unblock(ip):
    try:
        normalized_ip = str(ip_address(ip))
    except ValueError:
        return jsonify({"error": f"{ip} is not a valid IP address"}), 400

    conn = get_db()
    exists = conn.execute("SELECT ip FROM blocked_ips WHERE ip = ?", (normalized_ip,)).fetchone()
    if not exists:
        conn.close()
        return jsonify({"error": f"{normalized_ip} is not currently blocked"}), 404

    unblock_ip(conn, normalized_ip, dry_run=cfg.get("dry_run", True))
    conn.close()
    return jsonify({"ip": normalized_ip, "unblocked": True})


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
    limit = parse_int_arg("limit", 10, 1, 50)
    conn = get_db()
    rows = conn.execute(
        """
        SELECT a.src_ip,
               COUNT(*) as alert_count,
               MAX(a.timestamp) as last_seen,
               (SELECT rule_reason FROM alerts a2
                WHERE a2.src_ip = a.src_ip ORDER BY a2.id DESC LIMIT 1) as last_reason,
               (SELECT 1 FROM blocked_ips b WHERE b.ip = a.src_ip AND (b.expires_at IS NULL OR b.expires_at > strftime('%s','now'))) as is_blocked,
               (SELECT severity FROM alerts a3 WHERE a3.src_ip = a.src_ip ORDER BY a3.id DESC LIMIT 1) as severity,
               (SELECT mitre_technique FROM alerts a4 WHERE a4.src_ip = a.src_ip ORDER BY a4.id DESC LIMIT 1) as mitre_technique
        FROM alerts a
        GROUP BY a.src_ip
        ORDER BY alert_count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/investigate/<ip>")
@auth.login_required
def api_investigate_ip(ip):
    try:
        normalized_ip = str(ip_address(ip))
    except ValueError:
        return jsonify({"error": f"{ip} is not a valid IP address"}), 400

    conn = get_db()
    alert_rows = [dict(r) for r in conn.execute(
        """
        SELECT id, timestamp, src_ip, dst_ip, action, score, rule_reason, top_reasons,
               feedback, severity, mitre_technique, mitre_tactic
        FROM alerts
        WHERE src_ip = ? OR dst_ip = ?
        ORDER BY timestamp DESC
        LIMIT 100
        """,
        (normalized_ip, normalized_ip),
    ).fetchall()]
    traffic_summary = conn.execute(
        """
        SELECT COUNT(*) as traffic_count,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen,
               COUNT(DISTINCT dst_ip) as distinct_destinations,
               COUNT(DISTINCT dst_port) as distinct_ports,
               SUM(packet_length) as bytes_observed
        FROM traffic
        WHERE src_ip = ? OR dst_ip = ?
        """,
        (normalized_ip, normalized_ip),
    ).fetchone()
    blocked = conn.execute(
        "SELECT ip, blocked_at, reason, dry_run, expires_at FROM blocked_ips WHERE ip = ?",
        (normalized_ip,),
    ).fetchone()
    severity_counts = [dict(r) for r in conn.execute(
        """
        SELECT COALESCE(severity, 'unknown') as severity, COUNT(*) as count
        FROM alerts WHERE src_ip = ? OR dst_ip = ?
        GROUP BY COALESCE(severity, 'unknown')
        """,
        (normalized_ip, normalized_ip),
    ).fetchall()]
    conn.close()

    timeline = []
    if traffic_summary and traffic_summary["first_seen"]:
        timeline.append({"timestamp": traffic_summary["first_seen"], "event": "first_seen", "detail": "First traffic observed"})
    for alert in reversed(alert_rows[-25:]):
        category = categorize(alert.get("rule_reason"))
        timeline.append({
            "timestamp": alert.get("timestamp"),
            "event": category,
            "detail": alert.get("rule_reason") or "ML anomaly",
            "severity": alert.get("severity"),
        })
    if blocked:
        timeline.append({"timestamp": blocked["blocked_at"], "event": "blocked", "detail": blocked["reason"] or "Blocked"})

    return jsonify({
        "ip": normalized_ip,
        "traffic": dict(traffic_summary) if traffic_summary else {},
        "blocked": dict(blocked) if blocked else None,
        "severity_counts": severity_counts,
        "alerts": alert_rows,
        "timeline": sorted(timeline, key=lambda e: e.get("timestamp") or 0),
    })


@app.route("/api/report")
@auth.login_required
def api_report():
    conn = get_db()
    summary = {
        "traffic_count": conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0],
        "alert_count": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "blocked_count": conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0],
        "generated_at": time.time(),
    }
    severity_rows = [dict(r) for r in conn.execute(
        "SELECT COALESCE(severity, 'unknown') as severity, COUNT(*) as count FROM alerts GROUP BY COALESCE(severity, 'unknown')"
    ).fetchall()]
    top_alerts = [dict(r) for r in conn.execute(
        """
        SELECT timestamp, src_ip, dst_ip, severity, mitre_technique, mitre_tactic, rule_reason, feedback
        FROM alerts ORDER BY id DESC LIMIT 25
        """
    ).fetchall()]
    top_offenders = [dict(r) for r in conn.execute(
        """
        SELECT src_ip, COUNT(*) as alert_count, MAX(timestamp) as last_seen,
               MAX(COALESCE(severity, 'unknown')) as severity
        FROM alerts GROUP BY src_ip ORDER BY alert_count DESC LIMIT 10
        """
    ).fetchall()]
    conn.close()

    def esc(value):
        return str(value if value is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows = "".join(
        f"<tr><td>{esc(a['timestamp'])}</td><td>{esc(a['src_ip'])}</td><td>{esc(a['dst_ip'])}</td>"
        f"<td>{esc(a['severity'])}</td><td>{esc(a['mitre_technique'])}</td><td>{esc(a['mitre_tactic'])}</td>"
        f"<td>{esc(a['rule_reason'])}</td><td>{esc(a['feedback'] or 'unlabeled')}</td></tr>"
        for a in top_alerts
    )
    sev = "".join(f"<li>{esc(r['severity'])}: {esc(r['count'])}</li>" for r in severity_rows)
    offenders = "".join(f"<li>{esc(o['src_ip'])}: {esc(o['alert_count'])} alerts</li>" for o in top_offenders)
    html = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>ACF Security Report</title>
<style>body{{font-family:Arial,sans-serif;margin:32px;color:#111827}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #d1d5db;padding:8px;font-size:12px}}th{{background:#f3f4f6;text-align:left}}.stats{{display:flex;gap:16px}}.card{{border:1px solid #d1d5db;padding:12px 16px}}</style>
</head><body><h1>ACF Security Report</h1><p>Generated at Unix time {summary['generated_at']:.0f}</p>
<div class='stats'><div class='card'><b>Traffic</b><br>{summary['traffic_count']}</div><div class='card'><b>Alerts</b><br>{summary['alert_count']}</div><div class='card'><b>Blocked IPs</b><br>{summary['blocked_count']}</div></div>
<h2>Severity Summary</h2><ul>{sev}</ul><h2>Top Offenders</h2><ul>{offenders}</ul>
<h2>Recent Alerts</h2><table><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Severity</th><th>MITRE</th><th>Tactic</th><th>Reason</th><th>Feedback</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
