"""
ttl_monitor.py -- TTL-based IP spoofing detection

Real hosts send packets with a consistent TTL, since it's derived from a
fixed OS starting value (64 Linux/Mac, 128 Windows, 255 some network gear)
minus the number of hops on a stable network path. If the same source IP
suddenly shows a wildly different TTL, that's a strong signal someone is
crafting packets claiming to be that IP -- the attacker's actual path/OS
doesn't match the real host's.

LIMITATION: legitimate route changes can occasionally shift TTL by a
few hops, causing a rare false positive. The baseline is fixed on first
sighting (like arp_monitor's IP-to-MAC baseline) rather than adaptive,
so this is a simple, honest heuristic -- not a guarantee.
"""


class TtlTracker:
    def __init__(self):
        self._baseline = {}  # ip -> first-seen ttl

    def check(self, ip, ttl):
        """
        Records this (ip, ttl) observation. Returns (baseline_ttl, diff):
          - baseline_ttl is None on the very first sighting of this IP
            (nothing to compare against yet).
          - diff is the absolute difference from the established baseline,
            0 on first sighting.
        The caller compares diff against a threshold to decide if it's
        an anomaly -- this class just tracks state, it doesn't judge.
        """
        if not ip or ttl is None:
            return None, 0

        baseline = self._baseline.get(ip)
        if baseline is None:
            self._baseline[ip] = ttl
            return None, 0

        diff = abs(baseline - ttl)
        return baseline, diff
