# posture.py
#
# Mother posture engine.
# Pure logic. No global state, no imports from other modules.
#
# determine_posture(recent_events, chain_summaries)
#   → "MONITOR" | "ELEVATED" | "RESTRICT" | "LOCKDOWN"
#
# Rules implemented exactly as specified:
# • Any chain classified as critical → LOCKDOWN
# • Multiple malicious events from same IP (<30s) → RESTRICT
# • Only benign/noise → MONITOR
# • Suspicious but stable → ELEVATED

import datetime
from collections import Counter


def _parse_ts(ts):
    try:
        return datetime.datetime.fromisoformat(ts)
    except Exception:
        return datetime.datetime.utcnow()


def _seconds_ago(ts):
    dt = _parse_ts(ts)
    return (datetime.datetime.utcnow() - dt).total_seconds()


# ------------------------------------------------------------
# MAIN LOGIC
# ------------------------------------------------------------

def determine_posture(recent_events, chain_summaries):
    """
    Inputs:
      recent_events → list of raw event dicts from state.py (most recent N)
      chain_summaries → list of classifier outputs:
            {
                "risk": "...",
                "confidence": float,
                ...
            }

    Returns:
      posture string:
        • "MONITOR"
        • "ELEVATED"
        • "RESTRICT"
        • "LOCKDOWN"
    """

    # --------------------------------------------------------
    # 1. Critical chain → LOCKDOWN
    # --------------------------------------------------------
    for summary in chain_summaries:
        if summary.get("risk") == "critical":
            return "LOCKDOWN"

    # --------------------------------------------------------
    # 2. Multiple malicious events from same IP within 30s → RESTRICT
    # --------------------------------------------------------
    malicious_ips = []

    for evt in recent_events:
        if evt.get("severity") == "malicious":
            if _seconds_ago(evt.get("timestamp")) <= 30:
                malicious_ips.append(evt.get("source_ip"))

    if malicious_ips:
        counts = Counter(malicious_ips)
        if any(v >= 2 for v in counts.values()):
            return "RESTRICT"

    # --------------------------------------------------------
    # 3. Only benign/noise → MONITOR
    # --------------------------------------------------------
    if all(evt.get("severity") == "benign" for evt in recent_events):
        return "MONITOR"

    # --------------------------------------------------------
    # 4. Suspicious but stable → ELEVATED
    # --------------------------------------------------------
    # If we reached here, we have some mix of suspicious/malicious
    # but not triggering higher tiers.
    return "ELEVATED"
