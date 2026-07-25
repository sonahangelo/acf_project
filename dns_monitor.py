"""
dns_monitor.py -- DNS tunneling detection

DNS tunneling smuggles data (exfiltration, or a C2 channel) by encoding it
into DNS query names -- typically many unique, random-looking subdomains
under one attacker-controlled base domain, e.g.:

  a8f3k2x9.tunnel.evil.com
  b91d7xq2.tunnel.evil.com
  ...

Two signals catch most tunneling tools:
  1. Many distinct subdomains under one base domain, queried quickly by
     one source -- normal browsing rarely generates this pattern.
  2. High-entropy, long subdomain labels -- encoded data looks
     statistically random, unlike human-chosen subdomains ("www", "cdn-1").
"""

import math
from collections import Counter, defaultdict, deque


def shannon_entropy(s):
    """Bits of entropy per character. Random alphanumeric ~4.5-4.7,
    English words/typical subdomains ~2.5-3.5."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class DnsTunnelTracker:
    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        # (src_ip, base_domain) -> deque of (timestamp, leftmost_label)
        self._history = defaultdict(deque)

    def record(self, src_ip, base_domain, leftmost_label, timestamp):
        """
        Records this query and returns the number of DISTINCT subdomain
        labels seen for this (src_ip, base_domain) pair within the
        current sliding window.
        """
        key = (src_ip, base_domain)
        history = self._history[key]
        history.append((timestamp, leftmost_label))

        cutoff = timestamp - self.window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

        distinct_labels = len({label for _, label in history})
        return distinct_labels
