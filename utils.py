"""
utils.py -- Shared utilities, including config loading + validation.
"""

import sys
import yaml

REQUIRED_KEYS = {
    "interface": str,
    "bpf_filter": str,
    "contamination": (int, float),
    "dry_run": bool,
    "whitelist": list,
    "db_path": str,
    "model_path": str,
}

OPTIONAL_NUMERIC_KEYS = [
    "scan_window_seconds", "flow_timeout_seconds",
    "syn_window_seconds", "syn_flood_threshold",
    "port_repeat_window_seconds", "port_repeat_threshold",
    "exfil_bytes_threshold", "exfil_min_duration_seconds",
    "scan_zscore_threshold", "scan_min_distinct_ports",
    "dns_window_seconds", "dns_min_distinct_subdomains",
    "dns_entropy_threshold", "dns_min_label_length",
    "icmp_window_seconds", "icmp_flood_threshold",
    "brute_force_threshold", "ttl_anomaly_threshold",
    "slowloris_min_duration_seconds", "slowloris_max_bps",
    "slowloris_min_connections",
]

OPTIONAL_LIST_KEYS = ["brute_force_ports", "threat_intel_files", "threat_intel_indicators"]


def load_config(path="config.yml"):
    try:
        with open(path, "r") as f:
            cfg = yaml.safe_load(f)
    except FileNotFoundError:
        _fail(f"Config file not found: '{path}'. Did you mean to run from the project directory?")
    except yaml.YAMLError as e:
        _fail(
            f"'{path}' is not valid YAML and could not be parsed.\n"
            f"  Parser error: {e}\n"
            f"  Common causes: mismatched indentation, a stray tab, or two keys merged onto one line.\n"
            f"  Tip: run this to check syntax without starting ACF:\n"
            f"    python3 -c \"import yaml; yaml.safe_load(open('{path}'))\""
        )

    if cfg is None:
        _fail(f"'{path}' is empty or contains no valid settings.")

    validate_config(cfg, path)
    return cfg


def validate_config(cfg, path="config.yml"):
    errors = []

    for key, expected_type in REQUIRED_KEYS.items():
        if key not in cfg:
            errors.append(f"missing required key '{key}'")
            continue
        if not isinstance(cfg[key], expected_type):
            type_name = expected_type.__name__ if not isinstance(expected_type, tuple) \
                else " or ".join(t.__name__ for t in expected_type)
            errors.append(
                f"'{key}' should be a {type_name}, got {type(cfg[key]).__name__} ({cfg[key]!r})"
            )

    if "whitelist" in cfg and isinstance(cfg["whitelist"], list):
        for i, entry in enumerate(cfg["whitelist"]):
            if not isinstance(entry, str):
                errors.append(f"whitelist[{i}] should be a string IP, got {type(entry).__name__} ({entry!r})")

    for key in OPTIONAL_LIST_KEYS:
        if key in cfg and not isinstance(cfg[key], list):
            errors.append(f"'{key}' should be a list, got {type(cfg[key]).__name__} ({cfg[key]!r})")

    if "model_sha256" in cfg and cfg["model_sha256"]:
        digest = str(cfg["model_sha256"])
        if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            errors.append("'model_sha256' should be a 64-character SHA-256 hex digest")

    for key in OPTIONAL_NUMERIC_KEYS:
        if key in cfg and not isinstance(cfg[key], (int, float)):
            errors.append(f"'{key}' should be a number, got {type(cfg[key]).__name__} ({cfg[key]!r})")
        elif key in cfg and cfg[key] < 0:
            errors.append(f"'{key}' should not be negative, got {cfg[key]}")

    if "contamination" in cfg and isinstance(cfg["contamination"], (int, float)):
        if not (0 < cfg["contamination"] < 1):
            errors.append(f"'contamination' should be between 0 and 1 (exclusive), got {cfg['contamination']}")

    if errors:
        error_list = "\n".join(f"  - {e}" for e in errors)
        _fail(f"'{path}' has {len(errors)} problem(s):\n{error_list}")


def _fail(message):
    print(f"[config error] {message}", file=sys.stderr)
    sys.exit(1)
