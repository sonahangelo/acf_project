"""
firewall.py -- Firewall Controller (persistent)

Blocks are recorded in the blocked_ips table so they survive restarts:
no duplicate iptables rules after a restart, and no re-alerting on IPs
already known to be blocked.
"""

import os
import subprocess
import time
from ipaddress import ip_address

FIREWALL_CHAIN = "ACF_BLOCK"


def _iptables_command(*args):
    use_sudo = os.environ.get("ACF_FIREWALL_USE_SUDO", "true").lower() in ("1", "true", "yes")
    prefix = ["sudo"] if use_sudo else []
    return [*prefix, "iptables", *args]


def _run_iptables(*args):
    return subprocess.run(_iptables_command(*args), capture_output=True, text=True)


def _ensure_firewall_chain():
    chain_check = _run_iptables("-nL", FIREWALL_CHAIN)
    if chain_check.returncode != 0:
        create_chain = _run_iptables("-N", FIREWALL_CHAIN)
        if create_chain.returncode != 0:
            return False, create_chain.stderr.strip()

    jump_check = _run_iptables("-C", "INPUT", "-j", FIREWALL_CHAIN)
    if jump_check.returncode != 0:
        insert_jump = _run_iptables("-I", "INPUT", "1", "-j", FIREWALL_CHAIN)
        if insert_jump.returncode != 0:
            return False, insert_jump.stderr.strip()
    return True, ""


def load_blocked_ips(conn):
    """Returns a set of IPs currently recorded as blocked."""
    rows = conn.execute(
        "SELECT ip FROM blocked_ips WHERE expires_at IS NULL OR expires_at > ?",
        (time.time(),),
    ).fetchall()
    return {row[0] for row in rows}


def cleanup_expired_blocks(conn, dry_run=True):
    now = time.time()
    rows = conn.execute(
        "SELECT ip, dry_run FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?",
        (now,),
    ).fetchall()
    for ip, row_dry_run in rows:
        if not dry_run and not row_dry_run:
            result = _run_iptables("-D", FIREWALL_CHAIN, "-s", ip, "-j", "DROP")
            if result.returncode != 0:
                print(f"[firewall] FAILED to expire block for {ip}: {result.stderr.strip()}")
                continue
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        print(f"[firewall] Expired block for {ip}")


def _normalize_ip(ip):
    try:
        return str(ip_address(ip))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {ip!r}") from exc


def block_ip(conn, ip, dry_run=True, reason="", duration_seconds=None):
    ip = _normalize_ip(ip)
    already = conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    if already:
        return  # already recorded as blocked, avoid duplicate rules

    if dry_run:
        print(f"[firewall][DRY-RUN] Would block {ip} in {FIREWALL_CHAIN}")
    else:
        chain_ready, error = _ensure_firewall_chain()
        if not chain_ready:
            print(f"[firewall] FAILED to prepare {FIREWALL_CHAIN}: {error}")
            return
        result = _run_iptables("-A", FIREWALL_CHAIN, "-s", ip, "-j", "DROP")
        if result.returncode != 0:
            print(f"[firewall] FAILED to block {ip}: {result.stderr.strip()}")
            return
        print(f"[firewall] Blocked {ip}")

    blocked_at = time.time()
    expires_at = blocked_at + duration_seconds if duration_seconds else None
    conn.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason, dry_run, expires_at) VALUES (?, ?, ?, ?, ?)",
        (ip, blocked_at, reason, 1 if dry_run else 0, expires_at),
    )

def unblock_ip(conn, ip, dry_run=True):
    ip = _normalize_ip(ip)
    if not dry_run:
        result = _run_iptables("-D", FIREWALL_CHAIN, "-s", ip, "-j", "DROP")
        if result.returncode != 0:
            print(f"[firewall] FAILED to unblock {ip}: {result.stderr.strip()}")
            return
        print(f"[firewall] Unblocked {ip}")
    else:
        print(f"[firewall][DRY-RUN] Would unblock {ip}")

    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
