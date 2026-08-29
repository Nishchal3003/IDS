"""
ml/threat_assessment.py
-----------------------
Lightweight rule-based Threat Assessment layer.

Called AFTER LiveInferenceEngine.process_flow() to compute:
    - threat_type
    - severity      (NONE / LOW / MEDIUM / HIGH / CRITICAL)
    - confidence
    - recommended_action
    - evidence summary

SEVERITY MODEL (transparent, documented)
-----------------------------------------
NONE
    final_decision is BENIGN, UNKNOWN, or NO_MODEL.

LOW
    ML detects an attack class with confidence < LOW_CONF_THRESHOLD (0.60).
    Weak signal — monitor only.

MEDIUM
    ML detects an attack class with confidence >= LOW_CONF_THRESHOLD
    but < HIGH_CONF_THRESHOLD (0.80), AND no behavioural confirmation.
    Suspicious but insufficient for critical classification.

HIGH
    Confirmed PortScan (behavioural OR ML with confidence >= HIGH_CONF_THRESHOLD).
    Multiple unique destination ports observed.

CRITICAL
    Confirmed DoS/SYNFlood (behavioural OR ML with confidence >= HIGH_CONF_THRESHOLD).
    High SYN rate with low ACK ratio observed.

OVERRIDES
    Behavioural detection always produces at least HIGH (PortScan) or
    CRITICAL (DoS) regardless of ML confidence, because the behavioural
    rule is deterministic.

THRESHOLDS (configurable at module level)
    LOW_CONF_THRESHOLD  = 0.60
    HIGH_CONF_THRESHOLD = 0.80
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Configurable thresholds
# ---------------------------------------------------------------------------

LOW_CONF_THRESHOLD  = 0.60   # below this → LOW severity for ML-only detections
HIGH_CONF_THRESHOLD = 0.80   # above this → HIGH/CRITICAL for ML-only detections

# ---------------------------------------------------------------------------
# Severity ranking (used for comparisons)
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {
    "NONE"    : 0,
    "LOW"     : 1,
    "MEDIUM"  : 2,
    "HIGH"    : 3,
    "CRITICAL": 4,
}


def _max_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


# ---------------------------------------------------------------------------
# Recommended actions
# ---------------------------------------------------------------------------

_ACTIONS = {
    "NONE"    : "No action required — traffic appears benign.",
    "LOW"     : "Monitor source IP for further suspicious activity.",
    "MEDIUM"  : "Investigate source IP; review connection pattern.",
    "HIGH"    : "Investigate source host immediately. Consider temporary block if activity continues.",
    "CRITICAL": "Isolate source host if malicious activity is confirmed. Alert network administrator.",
}

_ATTACK_NOTES = {
    "PortScan"    : "Multiple unique destination ports observed in a short time window, indicating reconnaissance activity.",
    "DoS"         : "High SYN packet rate with very low ACK ratio, indicating a SYN-flood type denial-of-service attempt.",
    "DDoS"        : "Distributed high-volume traffic pattern consistent with DDoS activity.",
    "BruteForce"  : "Repeated authentication attempts detected against a single service.",
    "WebAttack"   : "Abnormal HTTP traffic patterns suggesting web application attack.",
    "Botnet"      : "Traffic characteristics consistent with botnet command-and-control communication.",
    "Infiltration": "Traffic pattern suggests lateral movement or data exfiltration attempt.",
    "Heartbleed"  : "TLS heartbeat request pattern associated with CVE-2014-0160 (Heartbleed).",
}


# ---------------------------------------------------------------------------
# Core assessment function
# ---------------------------------------------------------------------------

def assess(result: dict) -> dict:
    """
    Compute a threat assessment from a LiveInferenceEngine result dict.

    Parameters
    ----------
    result : dict
        Output from LiveInferenceEngine.process_flow(), containing:
        final_decision, ml_prediction, confidence,
        behavioural_detection, is_attack, detection_reason,
        src_ip, dst_ip, src_port, dst_port

    Returns
    -------
    dict with keys:
        threat_type        : str   (final_decision or 'BENIGN')
        severity           : str   (NONE/LOW/MEDIUM/HIGH/CRITICAL)
        confidence         : float (0.0–1.0)
        source_ip          : str
        destination_ip     : str
        detection_method   : str   ('ML', 'Behavioural', 'Hybrid', 'None')
        evidence           : str   (human-readable summary)
        recommended_action : str
        is_attack          : bool
    """
    final     = result.get("final_decision", "UNKNOWN")
    ml_pred   = result.get("ml_prediction", "NO_MODEL")
    conf      = float(result.get("confidence") or 0.0)
    behav     = result.get("behavioural_detection")
    is_attack = result.get("is_attack", False)
    reason    = result.get("detection_reason", "")

    # ── Detection method ─────────────────────────────────────────────────────
    if behav and ml_pred not in ("BENIGN", "NO_MODEL", "UNKNOWN", "MODEL_ERROR"):
        method = "Hybrid"
    elif behav:
        method = "Behavioural"
    elif ml_pred not in ("BENIGN", "NO_MODEL", "UNKNOWN", "MODEL_ERROR", "NONE"):
        method = "ML"
    else:
        method = "None"

    # ── Severity calculation ──────────────────────────────────────────────────
    if not is_attack or final in ("BENIGN", "UNKNOWN", "NO_MODEL", "MODEL_ERROR", "NONE"):
        severity = "NONE"

    elif final in ("DoS", "DDoS", "DoS_SYNFlood"):
        # DoS is always CRITICAL when behavioural is confirmed
        if behav in ("DoS_SYNFlood", "DDoS"):
            severity = "CRITICAL"
        elif conf >= HIGH_CONF_THRESHOLD:
            severity = "CRITICAL"
        elif conf >= LOW_CONF_THRESHOLD:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

    elif final == "PortScan":
        # PortScan is HIGH when behavioural is confirmed
        if behav == "PortScan":
            severity = "HIGH"
        elif conf >= HIGH_CONF_THRESHOLD:
            severity = "HIGH"
        elif conf >= LOW_CONF_THRESHOLD:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    elif is_attack:
        # Other ML-detected attack classes
        if conf >= HIGH_CONF_THRESHOLD:
            severity = "HIGH"
        elif conf >= LOW_CONF_THRESHOLD:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    else:
        severity = "NONE"

    # ── Evidence summary ──────────────────────────────────────────────────────
    note = _ATTACK_NOTES.get(final, "")
    if reason:
        evidence = reason
        if note:
            evidence = "{} | {}".format(reason, note)
    elif note:
        evidence = note
    else:
        evidence = "No specific evidence recorded."

    return {
        "threat_type"       : final if is_attack else "BENIGN",
        "severity"          : severity,
        "confidence"        : round(conf, 4),
        "source_ip"         : result.get("src_ip", ""),
        "destination_ip"    : result.get("dst_ip", ""),
        "src_port"          : result.get("src_port", 0),
        "dst_port"          : result.get("dst_port", 0),
        "detection_method"  : method,
        "evidence"          : evidence,
        "recommended_action": _ACTIONS[severity],
        "is_attack"         : is_attack,
    }


# ---------------------------------------------------------------------------
# Severity helpers (for dashboard colour coding)
# ---------------------------------------------------------------------------

SEVERITY_COLOURS = {
    "NONE"    : "#27ae60",   # green
    "LOW"     : "#f39c12",   # amber
    "MEDIUM"  : "#e67e22",   # orange
    "HIGH"    : "#e74c3c",   # red
    "CRITICAL": "#8e44ad",   # purple
}

SEVERITY_EMOJI = {
    "NONE"    : "✅",
    "LOW"     : "🟡",
    "MEDIUM"  : "🟠",
    "HIGH"    : "🔴",
    "CRITICAL": "🚨",
}


def severity_colour(severity: str) -> str:
    return SEVERITY_COLOURS.get(severity, "#95a5a6")


def severity_emoji(severity: str) -> str:
    return SEVERITY_EMOJI.get(severity, "❓")


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_cases = [
        {
            "name": "BENIGN flow",
            "result": {
                "final_decision": "BENIGN", "ml_prediction": "BENIGN",
                "confidence": 0.99, "behavioural_detection": None,
                "is_attack": False, "detection_reason": "ML (99.0%)",
                "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1",
                "src_port": 55000, "dst_port": 443,
            },
            "expected_severity": "NONE",
        },
        {
            "name": "PortScan (behavioural)",
            "result": {
                "final_decision": "PortScan", "ml_prediction": "NO_MODEL",
                "confidence": 0.0, "behavioural_detection": "PortScan",
                "is_attack": True, "detection_reason": "Behavioural PortScan: 15 unique ports",
                "src_ip": "10.0.0.99", "dst_ip": "192.168.1.1",
                "src_port": 55000, "dst_port": 80,
            },
            "expected_severity": "HIGH",
        },
        {
            "name": "DoS (behavioural)",
            "result": {
                "final_decision": "DoS", "ml_prediction": "NO_MODEL",
                "confidence": 0.0, "behavioural_detection": "DoS_SYNFlood",
                "is_attack": True, "detection_reason": "Behavioural SYNFlood: 500 SYN, ACK ratio=0.02",
                "src_ip": "10.0.0.99", "dst_ip": "192.168.1.1",
                "src_port": 55001, "dst_port": 80,
            },
            "expected_severity": "CRITICAL",
        },
        {
            "name": "ML attack (low confidence)",
            "result": {
                "final_decision": "BruteForce", "ml_prediction": "BruteForce",
                "confidence": 0.45, "behavioural_detection": None,
                "is_attack": True, "detection_reason": "ML (45.0%)",
                "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1",
                "src_port": 50000, "dst_port": 22,
            },
            "expected_severity": "LOW",
        },
    ]

    print("\nThreat Assessment Self-Test\n" + "=" * 40)
    all_pass = True
    for tc in test_cases:
        a = assess(tc["result"])
        passed = a["severity"] == tc["expected_severity"]
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_pass = False
        print(f"  {status}: {tc['name']}")
        print(f"         severity={a['severity']} (expected {tc['expected_severity']})")
        print(f"         method={a['detection_method']}")
        print(f"         action={a['recommended_action'][:60]}...")
        print()

    print("Result:", "ALL PASS" if all_pass else "FAILURES EXIST")
