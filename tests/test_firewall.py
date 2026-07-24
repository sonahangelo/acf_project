import sys, os, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from db import init_db
from firewall import block_ip, unblock_ip, load_blocked_ips


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    init_db(c)
    yield c
    c.close()


def test_block_ip_persists_to_db(conn):
    block_ip(conn, "1.2.3.4", dry_run=True, reason="test")
    blocked = load_blocked_ips(conn)
    assert "1.2.3.4" in blocked


def test_blocking_same_ip_twice_does_not_duplicate(conn):
    block_ip(conn, "1.2.3.4", dry_run=True)
    block_ip(conn, "1.2.3.4", dry_run=True)
    rows = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE ip = ?", ("1.2.3.4",)).fetchone()
    assert rows[0] == 1


def test_unblock_removes_from_db(conn):
    block_ip(conn, "1.2.3.4", dry_run=True)
    unblock_ip(conn, "1.2.3.4", dry_run=True)
    blocked = load_blocked_ips(conn)
    assert "1.2.3.4" not in blocked


def test_load_blocked_ips_reflects_persisted_state(conn):
    # Regression test: this is the whole point of the persistence work --
    # blocks must survive a fresh connection (simulating a restart).
    block_ip(conn, "5.6.7.8", dry_run=True, reason="syn_flood test")
    reloaded = load_blocked_ips(conn)
    assert reloaded == {"5.6.7.8"}
