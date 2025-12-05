import random
from backend.modules.utils import Event
from backend.lib.ip_utils import random_ip, random_common_port

# 3–5 simple noise templates
_NOISE_TEMPLATES = [
    ("Healthcheck ping",        {"type": "healthcheck"}),
    ("Metrics scrape request",  {"type": "metrics"}),
    ("Web crawler fetch",       {"type": "crawler"}),
    ("Idle tick",               {"type": "idle"}),
    ("DNS lookup",              {"type": "dns"}),
]


def generate_noise_event() -> Event:
    """
    Create a benign background event with minimal structured metadata.
    Never raises; always returns a valid Event instance.
    """

    try:
        raw, parsed_simple = random.choice(_NOISE_TEMPLATES)

        # Lift simple metadata into richer structure to mimic attack engine shape
        parsed = {
            "surface": "noise",
            "action": parsed_simple["type"],
        }

        return Event(
            id=0,  # state.add_event() will assign the real ID
            source_ip=random_ip(),
            dest_port=random_common_port(),
            phase="noise",
            category="noise",          # was 'benign'
            severity="benign",
            stage="noise",             # NEW
            raw=raw,
            parsed=parsed,             # NEW enriched form
            chain_id=None,             # noise has no chain by default
        )

    except Exception:
        # Absolute fallback — should never happen
        return Event(
            id=0,
            source_ip="1.1.1.1",
            dest_port=80,
            phase="noise",
            category="noise",
            severity="benign",
            stage="noise",
            raw="Fallback noise",
            parsed={"surface": "noise", "action": "fallback"},
            chain_id=None,
        )
