"""
app.py -- ACF Dashboard (web UI)
"""

import os
import secrets
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from ipaddress import ip_address

from flask import Flask, Response, jsonify, render_template, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.exceptions import BadRequest
from werkzeug.security import generate_password_hash, check_password_hash

from utils import load_config
from db import get_connection, init_db
from detection_metadata import categorize_reason, mitre_for_category
from firewall import cleanup_expired_blocks, unblock_ip

app = Flask(__name__)
auth = HTTPBasicAuth()

CONFIG_PATH = os.environ.get("ACF_CONFIG", "config.yml")
DEFAULT_DASHBOARD_PASSWORD = "acfpassword123"
DASHBOARD_USER = os.environ.get("ACF_DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.environ.get("ACF_DASHBOARD_PASSWORD")
DASHBOARD_PASSWORD_HASH = os.environ.get("ACF_DASHBOARD_PASSWORD_HASH")
ALLOW_DEFAULT_PASSWORD = os.environ.get("ACF_ALLOW_DEFAULT_PASSWORD", "").lower() in ("1", "true", "yes")
CSRF_TOKEN = os.environ.get("ACF_CSRF_TOKEN") or secrets.token_urlsafe(32)
FORCE_HTTPS = os.environ.get("ACF_FORCE_HTTPS", "").lower() in ("1", "true", "yes")
_auth_failures = {}
_auth_lock = threading.Lock()

if DASHBOARD_PASSWORD_HASH:
    _dashboard_password_hash = DASHBOARD_PASSWORD_HASH
elif DASHBOARD_PASSWORD:
    _dashboard_password_hash = generate_password_hash(DASHBOARD_PASSWORD)
else:
    _dashboard_password_hash = generate_password_hash(DEFAULT_DASHBOARD_PASSWORD)

USERS = {DASHBOARD_USER: _dashboard_password_hash}


def using_insecure_default_password():
    return not (DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH or ALLOW_DEFAULT_PASSWORD)


def _client_ip():
    return request.remote_addr or "unknown"


def _auth_rate_limited(client_ip):
    now = time.monotonic()
    with _auth_lock:
        attempts = [ts for ts in _auth_failures.get(client_ip, []) if now - ts < AUTH_WINDOW_SECONDS]
        if attempts:
            _auth_failures[client_ip] = attempts
        else:
            _auth_failures.pop(client_ip, None)
        return len(attempts) >= AUTH_MAX_ATTEMPTS


@auth.verify_password
def verify_password(username, password):
    client_ip = _client_ip()
    if _auth_rate_limited(client_ip):
        return None
    if username in USERS and check_password_hash(USERS.get(username), password):
        with _auth_lock:
            _auth_failures.pop(client_ip, None)
        return username


@auth.error_handler
def unauthorized():
    client_ip = _client_ip()
    if _auth_rate_limited(client_ip):
        return jsonify({"error": "too many login attempts; try again later"}), 429
    with _auth_lock:
        _auth_failures.setdefault(client_ip, []).append(time.monotonic())
    return jsonify({"error": "authentication required"}), 401

cfg = load_config(CONFIG_PATH)
_dashboard_start_time = time.time()


def get_db():
    db_path = cfg.get("db_path", "data/acf.db")
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def env_int(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


AUTH_WINDOW_SECONDS = env_int("ACF_AUTH_WINDOW_SECONDS", 900)
AUTH_MAX_ATTEMPTS = env_int("ACF_AUTH_MAX_ATTEMPTS", 10)

    
def categorize(rule_reason):
    category = categorize_reason(rule_reason)
    return "exfiltration" if category == "possible_exfiltration" else category


@app.before_request
def enforce_dashboard_security():
    if request.path in ("/healthz", "/readyz"):
        return None

    if using_insecure_default_password() and not app.config.get("TESTING"):
        return jsonify({
            "error": "dashboard credentials are not configured",
            "details": "Set ACF_DASHBOARD_PASSWORD or ACF_DASHBOARD_PASSWORD_HASH before exposing ACF.",
        }), 503

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.headers.get("X-ACF-CSRF-Token")
        if not secrets.compare_digest(token or "", CSRF_TOKEN):
            return jsonify({"error": "missing or invalid CSRF token"}), 403


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'",
    )
    if request.path == "/" or request.path.startswith("/api/") or request.path == "/metrics":
        response.headers.setdefault("Cache-Control", "no-store")
    if request.is_secure or FORCE_HTTPS:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def parse_int_arg(name, default, minimum, maximum):
    raw = request.args.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise BadRequest(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise BadRequest(f"{name} must be between {minimum} and {maximum}")
    return value


REPORT_RANGES = {
    "24h": (24 * 60 * 60, "Last 24 hours"),
    "7d": (7 * 24 * 60 * 60, "Last 7 days"),
    "30d": (30 * 24 * 60 * 60, "Last 30 days"),
    "all": (None, "All available data"),
}


def format_report_time(ts):
    if ts is None or ts == "":
        return "-"
    try:
        ts_float = float(ts)
    except (TypeError, ValueError):
        return str(ts)
    if ts_float <= 0:
        return "-"
    return datetime.fromtimestamp(ts_float, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def severity_rank(severity):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((severity or "").lower(), 0)


def coalesce_alert_metadata(alert):
    category = categorize_reason(alert.get("rule_reason"))
    severity = alert.get("severity") or "unknown"
    mitre = mitre_for_category(category)
    return {
        **alert,
        "severity": severity,
        "mitre_technique": alert.get("mitre_technique") or mitre["technique"],
        "mitre_tactic": alert.get("mitre_tactic") or mitre["tactic"],
        "category": category,
    }


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


def engine_service_status(conn):
    row = conn.execute(
        "SELECT last_heartbeat, status FROM service_heartbeats WHERE service = ?",
        ("acf-engine",),
    ).fetchone()
    if not row or row["status"] != "active":
        return "inactive"

    max_age = cfg.get("block_maintenance_interval_seconds", 30) * 2 + 5
    return "active" if time.time() - row["last_heartbeat"] <= max_age else "inactive"


@app.route("/")
@auth.login_required
def index():
    return render_template("dashboard.html", csrf_token=CSRF_TOKEN)


@app.route("/healthz")
def healthz():
    return jsonify({
        "status": "ok",
        "service": "acf-dashboard",
        "server_time": time.time(),
    })


@app.route("/readyz")
def readyz():
    try:
        conn = get_db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
    except sqlite3.Error:
        return jsonify({"status": "unavailable", "service": "acf-dashboard"}), 503

    return jsonify({
        "status": "ready",
        "service": "acf-dashboard",
        "server_time": time.time(),
    })


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


@app.route("/metrics")
@auth.login_required
def metrics():
    conn = get_db()
    traffic_count = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
    alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    engine_active = engine_service_status(conn) == "active"
    conn.close()

    body = "\n".join([
        "# HELP acf_traffic_rows_total Total traffic records retained by ACF.",
        "# TYPE acf_traffic_rows_total gauge",
        f"acf_traffic_rows_total {traffic_count}",
        "# HELP acf_alerts_total Total alerts retained by ACF.",
        "# TYPE acf_alerts_total gauge",
        f"acf_alerts_total {alert_count}",
        "# HELP acf_blocked_ips Total currently persisted ACF blocks.",
        "# TYPE acf_blocked_ips gauge",
        f"acf_blocked_ips {blocked_count}",
        "# HELP acf_engine_active Whether the detection engine heartbeat is current.",
        "# TYPE acf_engine_active gauge",
        f"acf_engine_active {1 if engine_active else 0}",
        "",
    ])
    return Response(body, mimetype="text/plain; version=0.0.4; charset=utf-8")


@app.route("/api/health")
@auth.login_required
def api_health():
    conn = get_db()
    last_capture_ts = conn.execute("SELECT MAX(timestamp) FROM traffic").fetchone()[0]
    detect_service_status = engine_service_status(conn)
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
        "detect_service_status": detect_service_status,
        "dashboard_service_status": "active",
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
    conn = get_db()
    detection_active = engine_service_status(conn) == "active"
    conn.close()

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
    range_key = request.args.get("range", "all").strip().lower() or "all"
    if range_key not in REPORT_RANGES:
        raise BadRequest("range must be one of: 24h, 7d, 30d, all")
    window_seconds, range_label = REPORT_RANGES[range_key]
    generated_at = time.time()
    window_start = generated_at - window_seconds if window_seconds else None

    where_clause = "WHERE timestamp >= ?" if window_start else ""
    params = (window_start,) if window_start else ()

    conn = get_db()
    summary = {
        "traffic_count": conn.execute(
            f"SELECT COUNT(*) FROM traffic {where_clause}", params
        ).fetchone()[0],
        "alert_count": conn.execute(
            f"SELECT COUNT(*) FROM alerts {where_clause}", params
        ).fetchone()[0],
        "blocked_count": conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0],
        "generated_at": generated_at,
        "dry_run": cfg.get("dry_run", True),
        "range_label": range_label,
    }
    top_alerts = [coalesce_alert_metadata(dict(r)) for r in conn.execute(
        f"""
        SELECT timestamp, src_ip, dst_ip, severity, mitre_technique, mitre_tactic, rule_reason, feedback
        FROM alerts {where_clause} ORDER BY id DESC LIMIT 50
        """,
        params,
    ).fetchall()]
    blocked_rows = [dict(r) for r in conn.execute(
        "SELECT ip, blocked_at, reason, dry_run, expires_at FROM blocked_ips ORDER BY blocked_at DESC LIMIT 25"
    ).fetchall()]
    conn.close()

    severity_counts = {}
    mitre_counts = {}
    offender_counts = {}
    for alert in top_alerts:
        severity_counts[alert["severity"]] = severity_counts.get(alert["severity"], 0) + 1
        technique = alert.get("mitre_technique") or "Unmapped"
        tactic = alert.get("mitre_tactic") or "Unknown"
        mitre_counts[(technique, tactic)] = mitre_counts.get((technique, tactic), 0) + 1
        src_ip = alert.get("src_ip") or "unknown"
        offender_counts[src_ip] = offender_counts.get(src_ip, 0) + 1

    def esc(value):
        return str(value if value is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def badge(severity):
        key = (severity or "unknown").lower()
        return f"<span class='badge badge-{esc(key)}'>{esc(key.upper())}</span>"

    severity_order = sorted(severity_counts.items(), key=lambda item: (-severity_rank(item[0]), item[0]))
    severity_cards = "".join(
        f"<div class='mini-card'><span>{esc(label.upper())}</span><strong>{count}</strong></div>"
        for label, count in severity_order
    ) or "<div class='muted'>No alerts in this report window.</div>"

    mitre_rows = "".join(
        f"<tr><td>{esc(technique)}</td><td>{esc(tactic)}</td><td>{count}</td></tr>"
        for (technique, tactic), count in sorted(mitre_counts.items(), key=lambda item: -item[1])
    ) or "<tr><td colspan='3' class='muted'>No MITRE mappings in this report window.</td></tr>"

    offender_rows = "".join(
        f"<tr><td>{esc(ip)}</td><td>{count}</td></tr>"
        for ip, count in sorted(offender_counts.items(), key=lambda item: -item[1])[:10]
    ) or "<tr><td colspan='2' class='muted'>No offenders in this report window.</td></tr>"

    alert_rows = "".join(
        f"<tr><td>{esc(format_report_time(a['timestamp']))}</td><td>{esc(a['src_ip'])}</td><td>{esc(a['dst_ip'])}</td>"
        f"<td>{badge(a['severity'])}</td><td>{esc(a['mitre_technique'] or '-')}</td><td>{esc(a['mitre_tactic'] or '-')}</td>"
        f"<td>{esc(a['rule_reason'] or 'ML anomaly')}</td><td>{esc(a['feedback'] or 'unlabeled')}</td></tr>"
        for a in top_alerts
    ) or "<tr><td colspan='8' class='muted'>No alerts in this report window.</td></tr>"

    block_rows = "".join(
        f"<tr><td>{esc(b['ip'])}</td><td>{esc(format_report_time(b['blocked_at']))}</td>"
        f"<td>{esc(format_report_time(b['expires_at']) if b['expires_at'] else 'Permanent')}</td>"
        f"<td>{esc('dry-run' if b['dry_run'] else 'live')}</td><td>{esc(b['reason'] or '')}</td></tr>"
        for b in blocked_rows
    ) or "<tr><td colspan='5' class='muted'>No blocked IPs.</td></tr>"

    generated_label = format_report_time(summary["generated_at"])
    mode_label = "Dry run" if summary["dry_run"] else "Live enforcement"
    html = f"""<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<title>ACF Security Report</title>
<style>
:root {{ --ink:#111827; --muted:#64748b; --line:#d1d5db; --soft:#f8fafc; --panel:#ffffff; --blue:#0369a1; --red:#b91c1c; --amber:#b45309; --green:#047857; }}
body {{ font-family: Arial, sans-serif; margin: 32px; color: var(--ink); background: #f3f4f6; }}
.report {{ max-width: 1180px; margin: 0 auto; background: var(--panel); border: 1px solid var(--line); padding: 28px; }}
h1 {{ margin: 0 0 6px; font-size: 30px; }}
h2 {{ margin-top: 28px; font-size: 18px; }}
.meta {{ color: var(--muted); margin: 0 0 22px; }}
.stats, .mini-grid {{ display: flex; flex-wrap: wrap; gap: 12px; }}
.card, .mini-card {{ border: 1px solid var(--line); background: var(--soft); padding: 12px 16px; min-width: 130px; }}
.card span, .mini-card span {{ display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }}
.card strong, .mini-card strong {{ display: block; font-size: 24px; margin-top: 6px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
td, th {{ border: 1px solid var(--line); padding: 8px; font-size: 12px; vertical-align: top; }}
th {{ background: #e5e7eb; text-align: left; }}
.badge {{ display:inline-block; min-width:68px; text-align:center; padding:3px 7px; border-radius:4px; font-size:10px; font-weight:700; }}
.badge-critical {{ background:#fee2e2; color:#991b1b; }} .badge-high {{ background:#ffedd5; color:#9a3412; }}
.badge-medium {{ background:#fef3c7; color:#92400e; }} .badge-low {{ background:#dbeafe; color:#1e40af; }} .badge-unknown {{ background:#e5e7eb; color:#475569; }}
.muted {{ color: var(--muted); }}
.footer {{ margin-top: 28px; color: var(--muted); font-size: 12px; }}
@media print {{ body {{ background: white; margin: 0; }} .report {{ border: none; }} }}
</style>
</head>
<body>
<div class='report'>
<h1>ACF Security Report</h1>
<p class='meta'>Generated {esc(generated_label)} | Scope: {esc(summary['range_label'])} | Mode: {esc(mode_label)}</p>
<div class='stats'>
  <div class='card'><span>Traffic Logged</span><strong>{summary['traffic_count']}</strong></div>
  <div class='card'><span>Alerts</span><strong>{summary['alert_count']}</strong></div>
  <div class='card'><span>Blocked IPs</span><strong>{summary['blocked_count']}</strong></div>
</div>
<h2>Executive Summary</h2>
<p>This report summarizes ACF observations for {esc(summary['range_label'].lower())}. Review high and critical findings first, validate older unmapped alerts as needed, and confirm firewall blocks before enabling or keeping live enforcement.</p>
<h2>Severity Summary</h2><div class='mini-grid'>{severity_cards}</div>
<h2>MITRE ATT&CK Summary</h2><table><thead><tr><th>Technique</th><th>Tactic</th><th>Alerts</th></tr></thead><tbody>{mitre_rows}</tbody></table>
<h2>Top Offenders</h2><table><thead><tr><th>Source IP</th><th>Alerts</th></tr></thead><tbody>{offender_rows}</tbody></table>
<h2>Current Blocklist</h2><table><thead><tr><th>IP</th><th>Blocked At</th><th>Expires</th><th>Mode</th><th>Reason</th></tr></thead><tbody>{block_rows}</tbody></table>
<h2>Recent Alerts</h2><table><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Severity</th><th>MITRE</th><th>Tactic</th><th>Reason</th><th>Feedback</th></tr></thead><tbody>{alert_rows}</tbody></table>
<p class='footer'>Generated by ACF - Adaptive Cognitive Firewall. Use this report for study, research, triage, and defensive analysis.</p>
</div>
</body>
</html>"""
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    app.run(host=os.environ.get("ACF_HOST", "0.0.0.0"), port=env_int("ACF_PORT", 5050), debug=False)
