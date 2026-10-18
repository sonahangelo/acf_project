import sys, os, sqlite3
from types import SimpleNamespace
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from db import init_db
import firewall
from firewall import block_ip, unblock_ip, load_blocked_ips, cleanup_expired_blocks


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


def test_block_ip_rejects_invalid_ip(conn):
    with pytest.raises(ValueError):
        block_ip(conn, "not-an-ip", dry_run=True)


def test_unblock_ip_rejects_invalid_ip(conn):
    with pytest.raises(ValueError):
        unblock_ip(conn, "1.2.3.4;rm -rf /", dry_run=True)


def test_block_ip_sets_expiration(conn):
    block_ip(conn, "9.9.9.9", dry_run=True, duration_seconds=60)
    row = conn.execute("SELECT blocked_at, expires_at FROM blocked_ips WHERE ip = ?", ("9.9.9.9",)).fetchone()
    assert row[1] > row[0]


def test_cleanup_expired_blocks_removes_old_rows(conn):
    block_ip(conn, "9.9.9.9", dry_run=True, duration_seconds=1)
    conn.execute("UPDATE blocked_ips SET expires_at = 1 WHERE ip = ?", ("9.9.9.9",))
    cleanup_expired_blocks(conn, dry_run=True)
    assert "9.9.9.9" not in load_blocked_ips(conn)


def test_container_firewall_commands_do_not_require_sudo(monkeypatch):
    monkeypatch.setenv("ACF_FIREWALL_USE_SUDO", "false")
    assert firewall._iptables_command("-L") == ["iptables", "-L"]


def test_native_firewall_commands_require_sudo_by_default(monkeypatch):
    monkeypatch.delenv("ACF_FIREWALL_USE_SUDO", raising=False)
    assert firewall._iptables_command("-L") == ["sudo", "iptables", "-L"]


def test_live_block_uses_dedicated_acf_chain(conn, monkeypatch):
    calls = []

    def fake_iptables(*args):
        calls.append(args)
        return SimpleNamespace(returncode=1 if args in {
            ("-nL", firewall.FIREWALL_CHAIN),
            ("-C", "INPUT", "-j", firewall.FIREWALL_CHAIN),
        } else 0, stderr="")

    monkeypatch.setattr(firewall, "_run_iptables", fake_iptables)
    block_ip(conn, "1.2.3.4", dry_run=False)

    assert ("-N", firewall.FIREWALL_CHAIN) in calls
    assert ("-I", "INPUT", "1", "-j", firewall.FIREWALL_CHAIN) in calls
    assert ("-A", firewall.FIREWALL_CHAIN, "-s", "1.2.3.4", "-j", "DROP") in calls
