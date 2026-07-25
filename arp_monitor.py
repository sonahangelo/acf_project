"""
arp_monitor.py -- ARP spoofing detection via IP-to-MAC binding tracking

Watches ARP traffic and remembers which MAC address claimed each IP.
If an IP that was previously bound to one MAC suddenly shows up bound
to a different MAC, that's the classic signature of ARP spoofing --
an attacker impersonating another device (often the gateway) to
intercept traffic on the local network segment.

IMPORTANT LIMITATION: this is a Layer 2 attack. Blocking the offending
IP via iptables (Layer 3) does NOT stop an ARP spoofing attack -- the
attacker is on your local network segment regardless of IP-level rules.
This module provides detection/alerting, not prevention. Real mitigation
requires switch-level protections (Dynamic ARP Inspection) or static
ARP entries for critical hosts (e.g. your gateway).
"""


class ArpBindingTracker:
    def __init__(self):
        self._bindings = {}  # ip -> mac

    def check(self, ip, mac):
        """
        Record this IP->MAC binding and report whether it conflicts with
        a previously seen binding for the same IP.

        Returns (is_conflict, previous_mac_or_None).
        """
        if not ip or not mac:
            return False, None

        previous = self._bindings.get(ip)
        self._bindings.get(ip)
        self._bindings[ip] = mac

        if previous is None:
            return False, None
        if previous == mac:
            return False, previous

        return True, previous
