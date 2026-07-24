"""
firewall.py -- Firewall Controller

Applies iptables rules based on Decision Engine output.
SAFETY: dry_run=True by default -- logs what it *would* do without
actually touching iptables. Flip config.yml's dry_run to false only
after testing in an isolated lab network.
"""

import subprocess

_blocked_ips = set()


def block_ip(ip, dry_run=True):
    if ip in _blocked_ips:
        return  # already blocked, avoid duplicate rules

    if dry_run:
        print(f"[firewall][DRY-RUN] Would block {ip} (iptables -A INPUT -s {ip} -j DROP)")
        _blocked_ips.add(ip)
        return

    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[firewall] Blocked {ip}")
        _blocked_ips.add(ip)
    else:
        print(f"[firewall] FAILED to block {ip}: {result.stderr.strip()}")


def unblock_ip(ip, dry_run=True):
    if dry_run:
        print(f"[firewall][DRY-RUN] Would unblock {ip}")
        _blocked_ips.discard(ip)
        return

    cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[firewall] Unblocked {ip}")
        _blocked_ips.discard(ip)
    else:
        print(f"[firewall] FAILED to unblock {ip}: {result.stderr.strip()}")
