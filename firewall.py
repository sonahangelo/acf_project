"""
firewall.py -- Firewall Controller (persistent)

Blocks are recorded in the blocked_ips table so they survive restarts:
no duplicate iptables rules after a restart, and no re-alerting on IPs
already known to be blocked.
"""

import subprocess
import time


def load_blocked_ips(conn):
    """Returns a set of IPs currently recorded as blocked."""
    rows = conn.execute("SELECT ip FROM blocked_ips").fetchall()
    return {row[0] for row in rows}


def block_ip(conn, ip, dry_run=True, reason=""):
    already = conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    if already:
        return  # already recorded as blocked, avoid duplicate rules

    if dry_run:
        print(f"[firewall][DRY-RUN] Would block {ip} (iptables -A INPUT -s {ip} -j DROP)")
    else:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[firewall] FAILED to block {ip}: {result.stderr.strip()}")
            return
        print(f"[firewall] Blocked {ip}")

    conn.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason, dry_run) VALUES (?, ?, ?, ?)",
        (ip, time.time(), reason, 1 if dry_run else 0),
    )


def unblock_ip(conn, ip, dry_run=True):
    if not dry_run:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[firewall] FAILED to unblock {ip}: {result.stderr.strip()}")
            return
        print(f"[firewall] Unblocked {ip}")
    else:
        print(f"[firewall][DRY-RUN] Would unblock {ip}")

    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
