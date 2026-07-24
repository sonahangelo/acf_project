"""
decision.py -- Decision Engine

Interprets model output (-1 = anomaly, 1 = normal) and decides an action.
"""

MIN_FLOW_PACKETS_FOR_DECISION = 2


def decide(label, score, src_ip, whitelist, flow_packet_count=None):
    """
    Returns one of: "ALLOW", "BLOCK", "ALERT"
    """
    if src_ip in whitelist:
        return "ALLOW"

    # Not enough data yet on this flow to trust rate-based features --
    # avoid judging a connection off its first packet alone.
    if flow_packet_count is not None and flow_packet_count < MIN_FLOW_PACKETS_FOR_DECISION:
        return "ALLOW"

    if label == -1:
        return "BLOCK"

    return "ALLOW"
