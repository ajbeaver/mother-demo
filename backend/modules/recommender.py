# recommender.py
#
# Mother recommendation engine.
# Pure logic. No imports from state or other modules.
#
# Required functions:
#   • recommend_for_event(event, classification)
#   • recommend_for_chain(chain_summary)
#   • global_recommendations(posture)

# ------------------------------------------------------------
# Event-level Recommendations
# ------------------------------------------------------------

def recommend_for_event(event, classification):
    """
    Inputs:
      event → raw event dict
      classification → output of classify_event(event)

    Returns:
      {
        "action": "investigate|watch|block|isolate",
        "reason": str,
        "priority": int 1–5
      }
    """

    stage = event.get("stage")
    sev = event.get("severity")
    factors = classification.get("factors", [])
    risk = classification.get("risk")

    # Default recommendation
    result = {
        "action": "watch",
        "reason": "baseline monitoring",
        "priority": 1
    }

    # Noise → watch
    if stage == "noise":
        result.update({
            "action": "watch",
            "reason": "noise category event",
            "priority": 1
        })
        return result

    # Recon → investigate
    if stage == "recon":
        result.update({
            "action": "investigate",
            "reason": "recon activity detected",
            "priority": 2
        })
        return result

    # Intrusion → block
    if stage == "intrusion":
        result.update({
            "action": "block",
            "reason": "intrusion indicators observed",
            "priority": 4
        })
        return result

    # Exploit → isolate (highest severity)
    if stage == "exploit":
        result.update({
            "action": "isolate",
            "reason": "exploit behavior detected",
            "priority": 5
        })
        return result

    # Fallback based on risk
    if risk == "high":
        result.update({
            "action": "block",
            "reason": "high-risk classification",
            "priority": 4
        })
    elif risk == "critical":
        result.update({
            "action": "isolate",
            "reason": "critical risk classification",
            "priority": 5
        })

    return result


# ------------------------------------------------------------
# Chain-level Recommendations
# ------------------------------------------------------------

def recommend_for_chain(chain_summary):
    """
    Inputs:
      chain_summary → result from classifier.classify_chain()

    Rules:
      • recon → intrusion → exploit → isolate
      • recon-only → watch
      • repeated intrusion → block
      • privilege behavior (exploit) → isolate + high priority
    """

    stages = chain_summary.get("stages", [])
    risk = chain_summary.get("risk")
    factors = chain_summary.get("factors", [])

    # recon-only
    if stages == ["recon"]:
        return {
            "action": "watch",
            "reason": "recon-only chain",
            "priority": 2
        }

    # privilege / exploit behavior
    if "exploit" in stages:
        return {
            "action": "isolate",
            "reason": "exploit stage present",
            "priority": 5
        }

    # repeated intrusion or multi-stage attacks
    if "intrusion" in stages:
        return {
            "action": "block",
            "reason": "intrusion indicators across chain",
            "priority": 4
        }

    # fallback: use chain risk
    if risk == "high":
        return {
            "action": "block",
            "reason": "high-risk chain",
            "priority": 4
        }

    if risk == "critical":
        return {
            "action": "isolate",
            "reason": "critical chain",
            "priority": 5
        }

    return {
        "action": "watch",
        "reason": "default low-risk chain",
        "priority": 1
    }


# ------------------------------------------------------------
# Global Posture Recommendations
# ------------------------------------------------------------

def global_recommendations(posture):
    """
    Inputs:
      posture → posture string from posture.determine_posture()

    Outputs:
      { "action": str, "reason": str }
    """

    if posture == "MONITOR":
        return {
            "action": "none",
            "reason": "environment stable"
        }

    if posture == "ELEVATED":
        return {
            "action": "enhance_logging",
            "reason": "suspicious activity detected"
        }

    if posture == "RESTRICT":
        return {
            "action": "rate_limit",
            "reason": "malicious activity from repeated IPs"
        }

    if posture == "LOCKDOWN":
        return {
            "action": "close_external_interfaces",
            "reason": "critical chain detected"
        }

    return {
        "action": "none",
        "reason": "unknown posture"
    }
