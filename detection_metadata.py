"""Detection metadata for analyst workflow features."""

MITRE_MAPPINGS = {
    "port_scan": {"technique": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "syn_flood": {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "repeated_port_probe": {"technique": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "possible_exfiltration": {"technique": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "arp_spoofing": {"technique": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    "dns_tunneling": {"technique": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
    "stealth_scan": {"technique": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "icmp_flood": {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "brute_force": {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "invalid_flags": {"technique": "T1001", "name": "Data Obfuscation", "tactic": "Command and Control"},
    "ttl_anomaly": {"technique": "T1036", "name": "Masquerading", "tactic": "Defense Evasion"},
    "slowloris": {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "smurf_attack": {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "rogue_dhcp": {"technique": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    "threat_intel": {"technique": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    "ml_anomaly": {"technique": "", "name": "Unmapped anomaly", "tactic": "Unknown"},
}

SEVERITY_BY_CATEGORY = {
    "threat_intel": "critical",
    "possible_exfiltration": "critical",
    "arp_spoofing": "critical",
    "rogue_dhcp": "critical",
    "syn_flood": "high",
    "icmp_flood": "high",
    "slowloris": "high",
    "brute_force": "high",
    "dns_tunneling": "high",
    "stealth_scan": "medium",
    "invalid_flags": "medium",
    "ttl_anomaly": "medium",
    "port_scan": "medium",
    "repeated_port_probe": "low",
    "ml_anomaly": "low",
}

REASON_CATEGORIES = {
    "port_scan": "port_scan",
    "syn_flood": "syn_flood",
    "repeated_port_probe": "repeated_port_probe",
    "possible_exfiltration": "possible_exfiltration",
    "arp_spoofing": "arp_spoofing",
    "dns_tunneling": "dns_tunneling",
    "stealth_scan": "stealth_scan",
    "icmp_flood": "icmp_flood",
    "brute_force": "brute_force",
    "invalid_flags": "invalid_flags",
    "ttl_anomaly": "ttl_anomaly",
    "slowloris": "slowloris",
    "smurf_attack": "smurf_attack",
    "rogue_dhcp": "rogue_dhcp",
    "threat_intel": "threat_intel",
}


def categorize_reason(rule_reason):
    if not rule_reason:
        return "ml_anomaly"
    for prefix, category in REASON_CATEGORIES.items():
        if rule_reason.startswith(prefix):
            return category
    return "ml_anomaly"


def mitre_for_category(category):
    return MITRE_MAPPINGS.get(category, MITRE_MAPPINGS["ml_anomaly"])


def severity_for_alert(rule_reason=None, score=0.0, action="ALLOW"):
    category = categorize_reason(rule_reason)
    severity = SEVERITY_BY_CATEGORY.get(category, "low")
    if category == "ml_anomaly" and action == "BLOCK":
        try:
            if score is not None and float(score) < -0.15:
                return "medium"
        except (TypeError, ValueError):
            pass
    return severity
