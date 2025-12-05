# classifier.py
#
# Mother event + chain classifier (Phase 3)
# Pure logic only. No dependencies on state or other modules.

import datetime
from collections import Counter


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _parse_ts(ts):
    """Convert ISO timestamp → datetime object."""
    try:
        return datetime.datetime.fromisoformat(ts)
    except Exception:
        return datetime.datetime.utcnow()


def _seconds_ago(ts):
    dt = _parse_ts(ts)
    return (datetime.datetime.utcnow() - dt).total_seconds()


# ------------------------------------------------------------
# Event Classification
# ------------------------------------------------------------

def classify_event(event):
    """
    Classify a single event into risk, confidence, factors.

    Output:
    {
        "risk":      "low|medium|high|critical",
        "confidence": float,
        "factors":   [str, ...]
    }
    """

    stage = event.get("stage", "")
    severity = event.get("severity", "benign")
    source_ip = event.get("source_ip")
    age = _seconds_ago(event.get("timestamp"))

    factors = []
    conf = 0.3  # baseline confidence

    # --- Noise ---------------------------------------------------------------
    if stage == "noise":
        factors.append("noise category → low risk")
        return {
            "risk": "low",
            "confidence": 0.2,
            "factors": factors
        }

    # --- Recon ---------------------------------------------------------------
    if stage == "recon":
        conf += 0.1
        factors.append("recon activity detected")
        risk = "medium"

    # --- Intrusion -----------------------------------------------------------
    elif stage == "intrusion":
        conf += 0.25
        factors.append("intrusion indicators present")
        risk = "high"

    # --- Exploit -------------------------------------------------------------
    elif stage == "exploit":
        conf += 0.45
        factors.append("exploit behavior detected")
        risk = "critical"

    # Fallback
    else:
        risk = "medium"
        factors.append("unknown stage → assume medium risk")

    # --- Severity multiplier -------------------------------------------------
    if severity == "malicious":
        conf += 0.15
        factors.append("severity=malicious → increased risk")
    elif severity == "critical":
        conf += 0.3
        factors.append("severity=critical → high concern")

    # --- Recent activity boost (<60s) ---------------------------------------
    if age < 60:
        conf += 0.1
        factors.append("recent activity (<60s)")

    # Clamp confidence
    conf = max(0.0, min(conf, 1.0))

    return {
        "risk": risk,
        "confidence": conf,
        "factors": factors
    }


# ------------------------------------------------------------
# Chain Classification
# ------------------------------------------------------------

def classify_chain(chain_events):
    """
    Aggregate classification of a chain.

    Output:
    {
        "risk": "low|medium|high|critical",
        "confidence": float,
        "stages": [...distinct stage sequence...],
        "ip": source_ip (dominant),
        "factors": [...],
    }
    """

    if not chain_events:
        return {
            "risk": "low",
            "confidence": 0.0,
            "stages": [],
            "ip": None,
            "factors": ["empty chain"]
        }

    # Collect sequence info
    stages = [e.get("stage") for e in chain_events]
    sev = [e.get("severity") for e in chain_events]
    ips = [e.get("source_ip") for e in chain_events]

    distinct_stages = list(dict.fromkeys(stages))  # preserve order
    factors = []
    conf = 0.4

    # Rule: recon-only → medium
    if set(distinct_stages) == {"recon"}:
        factors.append("recon-only chain → medium risk")
        risk = "medium"

    # Rule: recon → intrusion → exploit → critical
    elif "exploit" in stages:
        factors.append("exploit stage present → critical risk")
        risk = "critical"
        conf += 0.35

    elif "intrusion" in stages:
        factors.append("intrusion indicators → high risk")
        risk = "high"
        conf += 0.20

    elif "recon" in stages:
        factors.append("recon sequence → medium risk")
        risk = "medium"
        conf += 0.10

    else:
        factors.append("default chain rule → low risk")
        risk = "low"

    # Severity influence
    if "critical" in sev:
        conf += 0.25
        factors.append("critical severity event in chain")
    elif "malicious" in sev:
        conf += 0.15
        factors.append("malicious severity in chain")

    # Duplicate indicators (multiple probes from same IP)
    ip_counts = Counter(ips)
    dominant_ip, count = ip_counts.most_common(1)[0]
    if count > 1:
        conf += 0.1
        factors.append(f"{count} repeated actions from IP {dominant_ip}")

    # Clamp confidence
    conf = max(0.0, min(conf, 1.0))

    return {
        "risk": risk,
        "confidence": conf,
        "stages": distinct_stages,
        "ip": dominant_ip,
        "factors": factors
    }
