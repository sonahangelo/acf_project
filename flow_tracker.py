"""
flow_tracker.py -- Per-connection (5-tuple) flow tracking + attack-pattern signals

Tracks several layers of state, each aimed at a different attack shape:

1. Per-flow (src_ip, src_port, dst_ip, dst_port, protocol) stats: duration,
   packet/byte counts, rate. General connection-level detection.

2. Per-source-IP scan tracking: distinct destination ports contacted
   recently, regardless of flow. Catches port scans (spread across many
   ports). DNS (UDP/53) is excluded -- resolver bursts aren't scans.

3. Per-source-IP SYN tracking: count of bare SYN packets (new connection
   attempts, no ACK yet) recently. Catches SYN floods -- many connection
   attempts, few/none completed.

4. Per-(source, destination, port) repeat-attempt tracking: count of SYNs
   to the *same* specific endpoint recently. Catches repeated probing of
   one port/service (distinct from a scan, which spreads across ports).
"""

import time
from collections import defaultdict, deque


class FlowTracker:
    def __init__(self, scan_window_seconds=5, flow_timeout_seconds=30,
                 syn_window_seconds=5, port_repeat_window_seconds=10):
        self.scan_window_seconds = scan_window_seconds
        self.flow_timeout_seconds = flow_timeout_seconds
        self.syn_window_seconds = syn_window_seconds
        self.port_repeat_window_seconds = port_repeat_window_seconds

        self._flows = {}  # 5-tuple -> {start, last, packet_count, byte_count}
        self._scan_history = defaultdict(deque)          # src_ip -> deque of (ts, dst_port)
        self._syn_history = defaultdict(deque)            # src_ip -> deque of ts
        self._port_attempt_history = defaultdict(deque)   # (src_ip,dst_ip,dst_port) -> deque of ts

    def _flow_key(self, feats):
        return (feats["src_ip"], feats.get("src_port"), feats["dst_ip"],
                feats.get("dst_port"), feats["protocol"])

    @staticmethod
    def _is_bare_syn(feats):
        """A connection attempt: SYN set, ACK not set."""
        flags = feats.get("tcp_flags") or ""
        return feats.get("protocol") == "TCP" and "S" in flags and "A" not in flags

    def update(self, feats):
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
            flow_pps = 0.0
            flow_bps = 0.0

        # --- per-source-IP scan tracking (DNS excluded) ---
        src_ip = feats["src_ip"]
        is_dns = feats.get("protocol") == "UDP" and feats.get("dst_port") == 53
        scan_hist = self._scan_history[src_ip]
        if not is_dns:
            scan_hist.append((ts, feats.get("dst_port")))
        cutoff = ts - self.scan_window_seconds
        while scan_hist and scan_hist[0][0] < cutoff:
            scan_hist.popleft()
        distinct_ports = len({p for _, p in scan_hist if p is not None})
        if len(scan_hist) > 1:
            span = ts - scan_hist[0][0]
            scan_pps = (len(scan_hist) / span) if span > 0 else 0.0
        else:
            scan_pps = 0.0

        # --- per-source-IP SYN tracking (connection attempts) ---
        is_syn = self._is_bare_syn(feats)
        syn_hist = self._syn_history[src_ip]
        if is_syn:
            syn_hist.append(ts)
        syn_cutoff = ts - self.syn_window_seconds
        while syn_hist and syn_hist[0] < syn_cutoff:
            syn_hist.popleft()
        syn_count = len(syn_hist)

        # --- repeated attempts to the same specific (dst_ip, dst_port) ---
        port_key = (src_ip, feats["dst_ip"], feats.get("dst_port"))
        port_hist = self._port_attempt_history[port_key]
        if is_syn:
            port_hist.append(ts)
        port_cutoff = ts - self.port_repeat_window_seconds
        while port_hist and port_hist[0] < port_cutoff:
            port_hist.popleft()
        port_repeat_count = len(port_hist)

        self._expire_flows(ts)

        return {
            "flow_duration": round(duration, 3),
            "flow_packet_count": flow["packet_count"],
            "flow_byte_count": flow["byte_count"],
            "flow_pps": round(flow_pps, 2),
            "flow_bps": round(flow_bps, 2),
            "scan_distinct_ports": distinct_ports,
            "scan_pps": round(scan_pps, 2),
            "syn_count": syn_count,
            "port_repeat_count": port_repeat_count,
        }

    def _expire_flows(self, now):
        stale = [k for k, f in self._flows.items() if now - f["last"] > self.flow_timeout_seconds]
        for k in stale:
            del self._flows[k]
