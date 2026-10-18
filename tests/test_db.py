import sqlite3

from db import get_connection, init_db, update_service_heartbeat


def test_get_connection_creates_parent_directory(tmp_path):
    db_path = tmp_path / "nested" / "acf.db"
    conn = get_connection(str(db_path))
    init_db(conn)
    conn.close()

    assert db_path.exists()


def test_init_db_adds_production_indexes():
    conn = sqlite3.connect(":memory:")
    init_db(conn)

    indexes = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
    }
    conn.close()

    assert "idx_alerts_timestamp" in indexes
    assert "idx_alerts_src_ip_timestamp" in indexes
    assert "idx_blocked_ips_expires_at" in indexes


def test_service_heartbeat_is_persisted():
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    update_service_heartbeat(conn, "acf-engine")

    row = conn.execute(
        "SELECT status FROM service_heartbeats WHERE service = ?", ("acf-engine",)
    ).fetchone()
    conn.close()

    assert row[0] == "active"
