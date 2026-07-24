"""
db.py -- SQLite storage layer

Replaces the CSV logging from earlier in the project. Same data, but
indexed, atomic, and scales far better once you're logging continuously.
"""

import sqlite3

TRAFFIC_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "packet_length", "tcp_flags",
    "flow_duration", "flow_packet_count", "flow_byte_count", "flow_pps", "flow_bps",
    "scan_distinct_ports", "scan_pps", "syn_count", "port_repeat_count",
]

ALERT_EXTRA_COLUMNS = ["action", "score", "top_reasons", "rule_reason"]


def get_connection(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
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


def insert_row(conn, table, row_dict):
    cols = list(row_dict.keys())
    placeholders = ", ".join("?" for _ in cols)
    col_sql = ", ".join(f'"{c}"' for c in cols)
    conn.execute(
        f'INSERT INTO {table} ({col_sql}) VALUES ({placeholders})',
        [row_dict[c] for c in cols],
    )
