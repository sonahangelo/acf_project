"""
features.py -- Feature Extraction Module

Per-packet features come from extract_features(). Flow-level and scan-level
features are merged in by main.py via FlowTracker before logging/prediction.
"""

import time
from scapy.all import IP, TCP, UDP


def extract_features(pkt):
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    src_port = dst_port = None
    protocol = "OTHER"
    tcp_flags = ""

    if pkt.haslayer(TCP):
        protocol = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        tcp_flags = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return {
        "timestamp": time.time(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_length": len(pkt),
        "tcp_flags": tcp_flags,
    }


# Columns used for the ML model (must be numeric).
MODEL_FEATURE_COLUMNS = [
    "packet_length",
    "src_port",
    "dst_port",
    "flow_duration",
    "flow_packet_count",
    "flow_byte_count",
    "flow_pps",
    "flow_bps",
    "scan_distinct_ports",
    "scan_pps",
]


def to_model_vector(feature_dict):
    return [feature_dict.get(col, 0) or 0 for col in MODEL_FEATURE_COLUMNS]
