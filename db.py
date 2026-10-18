"""
db.py -- SQLite storage layer

Replaces the CSV logging from earlier in the project. Same data, but
indexed, atomic, and scales far better once you're logging continuously.
"""

import os
import sqlite3
import time

TRAFFIC_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "packet_length", "tcp_flags", "ttl",
    "flow_duration", "flow_packet_count", "flow_byte_count", "flow_pps", "flow_bps",
    "scan_distinct_ports", "scan_pps", "syn_count", "port_repeat_count", "icmp_count",
    "slow_flow_count",
]

ALERT_EXTRA_COLUMNS = ["action", "score", "top_reasons", "rule_reason", "severity", "mitre_technique", "mitre_tactic"]


def get_connection(db_path, timeout=30):
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=timeout)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.isolation_level = None
    return conn


def init_db(conn):
    traffic_cols_sql = ", ".join(f'"{c}" REAL' if c not in ("src_ip", "dst_ip", "protocol", "tcp_flags")
                                  else f'"{c}" TEXT' for c in TRAFFIC_COLUMNS)
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            {traffic_cols_sql}
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            blocked_at REAL,
            reason TEXT,
            dry_run INTEGER,
            expires_at REAL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_src_ip ON traffic(src_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp)")

    alert_cols_sql = traffic_cols_sql + ", " + ", ".join(
        f'"{c}" TEXT' if c in ("action", "top_reasons", "rule_reason") else f'"{c}" REAL'
        for c in ALERT_EXTRA_COLUMNS
    )
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            {alert_cols_sql}
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip_timestamp ON alerts(src_ip, timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires_at ON blocked_ips(expires_at)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS service_heartbeats (
            service TEXT PRIMARY KEY,
            last_heartbeat REAL NOT NULL,
            status TEXT NOT NULL
        )
    """)

    # Add columns if they do not exist yet (safe to run repeatedly).
    existing_cols = [row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()]
    for col in ("feedback", "severity", "mitre_technique", "mitre_tactic"):
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")

    blocked_cols = [row[1] for row in conn.execute("PRAGMA table_info(blocked_ips)").fetchall()]
    if "expires_at" not in blocked_cols:
        conn.execute("ALTER TABLE blocked_ips ADD COLUMN expires_at REAL")

def insert_row(conn, table, row_dict):
    cols = list(row_dict.keys())
    placeholders = ", ".join("?" for _ in cols)
    col_sql = ", ".join(f'"{c}"' for c in cols)
    conn.execute(
        f'INSERT INTO {table} ({col_sql}) VALUES ({placeholders})',
        [row_dict[c] for c in cols],
    )


def update_service_heartbeat(conn, service, status="active"):
    conn.execute(
        "INSERT INTO service_heartbeats (service, last_heartbeat, status) VALUES (?, ?, ?) "
        "ON CONFLICT(service) DO UPDATE SET last_heartbeat = excluded.last_heartbeat, status = excluded.status",
        (service, time.time(), status),
    )
