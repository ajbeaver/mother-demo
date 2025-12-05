import random
import uuid

from backend.modules.utils import Event
from backend.lib.ip_utils import random_ip, random_common_port


# Supported attack surfaces
_SURFACES = ("ssh", "http")

# Templates per stage + surface.
# category is intentionally aligned with stage: recon | intrusion | exploit.

_RECON_TEMPLATES = {
    "ssh": [
        {
            "category": "recon",
            "raw": "SSH banner grab from unknown host",
            "parsed": {
                "stage": "recon",
                "vector": "ssh",
                "method": "banner_grab",
            },
        },
        {
            "category": "recon",
            "raw": "SSH version probe against exposed service",
            "parsed": {
                "stage": "recon",
                "vector": "ssh",
                "method": "version_probe",
            },
        },
    ],
    "http": [
        {
            "category": "recon",
            "raw": "HTTP directory probe detected",
            "parsed": {
                "stage": "recon",
                "vector": "http",
                "paths": ["/admin", "/login", "/.git/"],
            },
        },
        {
            "category": "recon",
            "raw": "HTTP endpoint scan from remote host",
            "parsed": {
                "stage": "recon",
                "vector": "http",
                "paths": ["/", "/status", "/metrics"],
            },
        },
    ],
}

_INTRUSION_TEMPLATES = {
    "ssh": [
        {
            "category": "intrusion",
            "raw": "SSH brute force — repeated failed password logins",
            "parsed": {
                "stage": "intrusion",
                "vector": "ssh",
                "attempts": 24,
                "auth_type": "password",
            },
        },
        {
            "category": "intrusion",
            "raw": "SSH brute force — rapid key-exchange failures",
            "parsed": {
                "stage": "intrusion",
                "vector": "ssh",
                "attempts": 18,
                "auth_type": "publickey",
            },
        },
    ],
    "http": [
        {
            "category": "intrusion",
            "raw": "Repeated login failures on web auth endpoint",
            "parsed": {
                "stage": "intrusion",
                "vector": "http",
                "endpoint": "/login",
                "attempts": 15,
            },
        },
        {
            "category": "intrusion",
            "raw": "Elevated error rate on web auth endpoint",
            "parsed": {
                "stage": "intrusion",
                "vector": "http",
                "endpoint": "/login",
                "status_codes": [401, 403],
            },
        },
    ],
}

_EXPLOIT_TEMPLATES = {
    "ssh": [
        {
            "category": "exploit",
            "raw": "SSH privilege escalation attempt detected",
            "parsed": {
                "stage": "exploit",
                "vector": "ssh",
                "indicator": "suspicious sudo failure pattern",
            },
        },
        {
            "category": "exploit",
            "raw": "SSH command execution pattern blocked",
            "parsed": {
                "stage": "exploit",
                "vector": "ssh",
                "indicator": "abnormal shell command sequence",
            },
        },
    ],
    "http": [
        {
            "category": "exploit",
            "raw": "Exploit payload upload attempt detected",
            "parsed": {
                "stage": "exploit",
                "vector": "http",
                "indicator": "suspicious binary upload",
            },
        },
        {
            "category": "exploit",
            "raw": "Remote command injection attempt blocked",
            "parsed": {
                "stage": "exploit",
                "vector": "http",
                "indicator": "command injection pattern",
            },
        },
    ],
}


def _pick_template(stage: str, surface: str) -> dict:
    """
    Pick a template for the given stage/surface.
    Returns a shallow copy so parsed can be mutated safely if needed.
    """
    if surface not in _SURFACES:
        surface = "http"

    if stage == "recon":
        pool = _RECON_TEMPLATES[surface]
    elif stage == "intrusion":
        pool = _INTRUSION_TEMPLATES[surface]
    elif stage == "exploit":
        pool = _EXPLOIT_TEMPLATES[surface]
    else:
        # Fallback: treat unknown as recon
        pool = _RECON_TEMPLATES[surface]

    tpl = random.choice(pool)
    return {
        "category": tpl["category"],
        "raw": tpl["raw"],
        "parsed": dict(tpl["parsed"]),
    }


def _build_event_from_template(
    *,
    severity: str,
    stage: str,
    chain_id: str,
    raw: str,
    parsed: dict,
    source_ip: str,
    dest_port: int,
) -> Event:
    """
    Construct an Event for a single step in the chain.

    - category == stage ("recon" | "intrusion" | "exploit")
    - phase is always "attack"
    - chain_id / stage populated so the UI and inspector can follow one actor.
    """
    return Event(
        id=0,  # state.add_event will assign a real ID
        source_ip=source_ip,
        dest_port=dest_port,
        phase="attack",
        category=stage,
        severity=severity,
        raw=raw,
        parsed=parsed,
        chain_id=chain_id,
        stage=stage,
    )


def _build_stage_sequence() -> list[str]:
    """
    Build a stage sequence for a single attacker.

    Always ordered and sequential (no shuffling):
      - base: recon -> intrusion -> exploit
      - length 3–5 with possible extra recon or exploit steps.
    """
    base = ["recon", "intrusion", "exploit"]
    length = random.randint(3, 5)

    if length == 3:
        return base

    if length == 4:
        # Either more recon up front or more exploit at the end
        return random.choice(
            [
                ["recon", "recon", "intrusion", "exploit"],
                ["recon", "intrusion", "exploit", "exploit"],
            ]
        )

    # length == 5
    return ["recon", "recon", "intrusion", "exploit", "exploit"]


def _severity_for_stage(stage: str) -> str:
    """
    Map stage -> severity. Keeps the scoring consistent:
      recon     -> suspicious
      intrusion -> malicious
      exploit   -> critical
    """
    if stage == "recon":
        return "suspicious"
    if stage == "intrusion":
        return "malicious"
    if stage == "exploit":
        return "critical"
    return "benign"


def _build_attack_plan(
    *,
    chain_id: str,
    source_ip: str,
    dest_port: int,
    surface: str,
    events: list[Event],
) -> dict:
    """
    Take a list of Events (already ordered by stage) and build a timed plan.

    - duration: random float between 20 and 40 seconds
    - delays: monotonically increasing, starting at 0.0, ending at ~duration
    - plan: list of { "delay": float, "event": Event }
    """
    if not events:
        # Should not happen with current _build_stage_sequence, but fail soft.
        return {
            "chain_id": chain_id,
            "source_ip": source_ip,
            "dest_port": dest_port,
            "surface": surface,
            "duration": 0.0,
            "plan": [],
        }

    duration = random.uniform(20.0, 40.0)
    count = len(events)

    if count == 1:
        delays = [0.0]
    else:
        step = duration / (count - 1)
        delays = [i * step for i in range(count)]

    plan = [
        {
            "delay": float(f"{delay:.3f}"),
            "event": event,
        }
        for delay, event in zip(delays, events)
    ]

    return {
        "chain_id": chain_id,
        "source_ip": source_ip,
        "dest_port": dest_port,
        "surface": surface,
        "duration": duration,
        "plan": plan,
    }


def generate_attack_scenario() -> dict:
    """
    Generate a single coherent attack chain as a timed plan object.

    Returned shape:

        {
            "chain_id": str,          # 8-char id
            "source_ip": str,
            "dest_port": int,
            "surface": "ssh" | "http",
            "duration": float,        # 20–40 seconds
            "plan": [
                {
                    "delay": float,   # seconds from start
                    "event": Event,   # fully populated Event
                },
                ...
            ]
        }

    Notes:
      - All Events share source_ip / dest_port / chain_id / surface.
      - Stages are sequential: recon -> intrusion -> exploit
        (with optional extra recon or exploit steps).
      - This function does NOT sleep or schedule; it only describes the chain.
    """
    source_ip = random_ip()
    dest_port = random_common_port()
    surface = random.choice(_SURFACES)
    chain_id = uuid.uuid4().hex[:8]

    stages = _build_stage_sequence()
    events: list[Event] = []

    for stage in stages:
        tpl = _pick_template(stage, surface)
        severity = _severity_for_stage(stage)

        event = _build_event_from_template(
            severity=severity,
            stage=stage,
            chain_id=chain_id,
            raw=tpl["raw"],
            parsed=tpl["parsed"],
            source_ip=source_ip,
            dest_port=dest_port,
        )
        events.append(event)

    return _build_attack_plan(
        chain_id=chain_id,
        source_ip=source_ip,
        dest_port=dest_port,
        surface=surface,
        events=events,
    )
