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

5. Per-source-IP ICMP tracking: count of ICMP packets recently. Catches
   ping floods.

6. Slowloris: counts, per (source, destination, port), how many currently
   active flows have both a long duration AND a very low byte rate --
   the "many slow trickling connections" signature that exhausts a
   server's connection pool without ever looking like a volume flood.
"""

import time
from collections import defaultdict, deque


class FlowTracker:
    def __init__(self, scan_window_seconds=5, flow_timeout_seconds=30,
                 syn_window_seconds=5, port_repeat_window_seconds=10,
                 icmp_window_seconds=5, slowloris_min_duration=30,
                 slowloris_max_bps=100):
        self.scan_window_seconds = scan_window_seconds
        self.flow_timeout_seconds = flow_timeout_seconds
        self.syn_window_seconds = syn_window_seconds
        self.port_repeat_window_seconds = port_repeat_window_seconds
        self.icmp_window_seconds = icmp_window_seconds
        self.slowloris_min_duration = slowloris_min_duration
        self.slowloris_max_bps = slowloris_max_bps

        self._flows = {}  # 5-tuple -> {start, last, packet_count, byte_count}
        self._scan_history = defaultdict(deque)          # src_ip -> deque of (ts, dst_port)
        self._syn_history = defaultdict(deque)            # src_ip -> deque of ts
        self._port_attempt_history = defaultdict(deque)   # (src_ip,dst_ip,dst_port) -> deque of ts
        self._icmp_history = defaultdict(deque)            # src_ip -> deque of ts

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
        src_ip = feats["src_ip"]

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

        # --- per-source-IP ICMP tracking (ping flood detection) ---
        icmp_count = 0
        if feats.get("protocol") == "ICMP":
            icmp_hist = self._icmp_history[src_ip]
            icmp_hist.append(ts)
            icmp_cutoff = ts - self.icmp_window_seconds
            while icmp_hist and icmp_hist[0] < icmp_cutoff:
                icmp_hist.popleft()
            icmp_count = len(icmp_hist)

        self._expire_flows(ts)

        # --- Slowloris: many concurrent long-duration, low-throughput
        # flows from this source to the same destination port. Scans the
        # currently-tracked flows (bounded by flow_timeout expiry, so
        # this stays small in practice) rather than keeping a separate
        # running counter, since flows naturally come and go.
        slow_flow_count = 0
        dst_port_for_slow_check = feats.get("dst_port")
        for other_key, other_flow in self._flows.items():
            if (other_key[0] != src_ip or other_key[2] != feats["dst_ip"]
                    or other_key[3] != dst_port_for_slow_check):
                continue
            other_duration = other_flow["last"] - other_flow["start"]
            if other_duration <= 0:
                continue
            other_bps = other_flow["byte_count"] / other_duration
            if other_duration >= self.slowloris_min_duration and other_bps <= self.slowloris_max_bps:
                slow_flow_count += 1

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
            "icmp_count": icmp_count,
            "slow_flow_count": slow_flow_count,
        }

    def _expire_flows(self, now):
        stale = [k for k, f in self._flows.items() if now - f["last"] > self.flow_timeout_seconds]
        for k in stale:
            del self._flows[k]
