"""
flow_tracker.py -- Per-connection (5-tuple) flow tracking + per-source scan tracking
nano flow_tracker.py
Two layers of state are maintained:
1. Per-flow (src_ip, src_port, dst_ip, dst_port, protocol) stats: how long this
   specific connection has been active, how many packets/bytes have moved,
   and its current rate. This is connection-level detection.
2. Per-source-IP scan tracking (sliding window): how many distinct destination
   ports has this IP contacted recently, regardless of which flow. This is what
   specifically catches port scans, which spread across many short-lived flows
   rather than looking unusual within any single flow.
"""

import time
from collections import defaultdict, deque


class FlowTracker:
    def __init__(self, scan_window_seconds=5, flow_timeout_seconds=30):
        self.scan_window_seconds = scan_window_seconds
        self.flow_timeout_seconds = flow_timeout_seconds

        # 5-tuple -> {start, last, packet_count, byte_count}
        self._flows = {}

        # src_ip -> deque of (timestamp, dst_port) -- for scan detection
        self._scan_history = defaultdict(deque)

    def _flow_key(self, feats):
        return (feats["src_ip"], feats.get("src_port"), feats["dst_ip"],
                feats.get("dst_port"), feats["protocol"])

    def update(self, feats):
        """
        feats: the per-packet feature dict from features.extract_features().
        Returns a dict of flow-level features to merge into feats.
        """
        ts = feats["timestamp"]
        length = feats.get("packet_length", 0)

        # --- per-flow (connection-level) stats ---
        key = self._flow_key(feats)
        flow = self._flows.get(key)
        if flow is None:
            flow = {"start": ts, "last": ts, "packet_count": 0, "byte_count": 0}
            self._flows[key] = flow

        flow["packet_count"] += 1
        flow["byte_count"] += length
        flow["last"] = ts

        duration = flow["last"] - flow["start"]
        if flow["packet_count"] > 1 and duration > 0:
            flow_pps = flow["packet_count"] / duration
            flow_bps = flow["byte_count"] / duration
        else:
            # Not enough data yet to estimate a rate -- avoid a misleading spike.
            flow_pps = 0.0
            flow_bps = 0.0

        # --- per-source-IP scan tracking (sliding window, across all flows) ---
        # --- per-source-IP scan tracking (sliding window, across all flows) ---
        # Exclude DNS (UDP/53): resolver bursts from normal browsing look like
        # "many quick lookups" but aren't the same phenomenon as a port scan.
        src_ip = feats["src_ip"]
        is_dns = feats.get("protocol") == "UDP" and feats.get("dst_port") == 53
        history = self._scan_history[src_ip]
        if not is_dns:
            history.append((ts, feats.get("dst_port")))
        cutoff = ts - self.scan_window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()
        distinct_ports = len({p for _, p in history if p is not None})
        if len(history) > 1:
            span = ts - history[0][0]
            scan_pps = (len(history) / span) if span > 0 else 0.0
        else:
            scan_pps = 0.0

        self._expire_flows(ts)

        return {
            "flow_duration": round(duration, 3),
            "flow_packet_count": flow["packet_count"],
            "flow_byte_count": flow["byte_count"],
            "flow_pps": round(flow_pps, 2),
            "flow_bps": round(flow_bps, 2),
            "scan_distinct_ports": distinct_ports,
            "scan_pps": round(scan_pps, 2),
        }

    def _expire_flows(self, now):
        """Drop inactive flows past the timeout, to bound memory use."""
        stale = [k for k, f in self._flows.items() if now - f["last"] > self.flow_timeout_seconds]
        for k in stale:
            del self._flows[k]
