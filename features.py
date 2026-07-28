"""
features.py -- Feature Extraction Module

Per-packet features come from extract_features(). Flow-level and scan-level
features are merged in by main.py via FlowTracker before logging/prediction.
"""

import time
from scapy.all import IP, TCP, UDP, ARP, DNS, DNSQR, ICMP, DHCP, BOOTP


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
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"

    return {
        "timestamp": time.time(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_length": len(pkt),
        "tcp_flags": tcp_flags,
	"ttl": ip_layer.ttl,
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
    "syn_count",
    "port_repeat_count",
    "icmp_count",
    "slow_flow_count",
]


def to_model_vector(feature_dict):
    return [feature_dict.get(col, 0) or 0 for col in MODEL_FEATURE_COLUMNS]
def extract_arp_features(pkt):
    """
    Extract fields from an ARP packet. Returns None if not ARP.
    Kept separate from extract_features()/MODEL_FEATURE_COLUMNS since
    ARP spoofing detection is a rule-based check (IP-to-MAC binding
    conflicts), not part of the ML anomaly model.
    """
    import time
    if not pkt.haslayer(ARP):
        return None

    arp = pkt[ARP]
    return {
        "timestamp": time.time(),
        "src_ip": arp.psrc,
        "dst_ip": arp.pdst,
        "src_mac": arp.hwsrc,
        "op": arp.op,  # 1 = request, 2 = reply
        "packet_length": len(pkt),
        "protocol": "ARP",
    }
def extract_dns_features(pkt):
    """
    Extract fields from a DNS query packet. Returns None if not a DNS
    query (only queries carry the encoded subdomain data in tunneling;
    responses are handled separately if ever needed).
    """
    import time
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
        return None
    if pkt[DNS].qr != 0:  # 0 = query, 1 = response -- only care about queries
        return None
    if not pkt.haslayer(IP):
        return None

    try:
        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    except Exception:
        return None

    if not qname:
        return None

    labels = qname.split(".")
    base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else qname
    leftmost_label = labels[0] if labels else ""

    return {
        "timestamp": time.time(),
        "src_ip": pkt[IP].src,
        "qname": qname,
        "base_domain": base_domain,
        "leftmost_label": leftmost_label,
        "qtype": pkt[DNSQR].qtype,
        "packet_length": len(pkt),
    }
def extract_dhcp_features(pkt):
    """
    Extract fields from a DHCP server response (OFFER or ACK). Returns
    None if this isn't a DHCP server message -- client requests
    (DISCOVER, REQUEST) aren't relevant here, only server responses that
    establish "who is acting as the DHCP server."
    """
    import time
    if not (pkt.haslayer(DHCP) and pkt.haslayer(IP)):
        return None

    msg_type = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            msg_type = opt[1]
            break

    # DHCP message types: 2 = OFFER, 5 = ACK (both are server -> client)
    if msg_type not in (2, 5):
        return None

    return {
        "timestamp": time.time(),
        "server_ip": pkt[IP].src,
        "msg_type": msg_type,
    }
