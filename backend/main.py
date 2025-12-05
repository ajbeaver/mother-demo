import asyncio
import random
import os
import time
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.modules.event_generator import generate_noise_event
from backend.modules.attack_engine import generate_attack_scenario
from backend.modules.state import (
    add_event,
    get_dashboard_counts,
    get_all_events,
    get_event_by_id,
    serialize_event,
    get_posture,
    get_deltas,
)

app = FastAPI()

FRONTEND_DIR = "/opt/mother-demo/frontend"
app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")


# ------------------------------------------------------------
# INTERNAL ATTACK PLAN QUEUE
# ------------------------------------------------------------

# Each entry in _attack_plans is a dict:
# {
#     "chain_id": str,
#     "duration": float,
#     "plan": [
#         {"delay": float, "event": Event},
#         ...
#     ],
#     "start_time": float,
#     "index": int,
# }
_attack_plans = []
MAX_ACTIVE_PLANS = 15


def _normalize_attack_plan(raw):
    """
    Normalize the output from generate_attack_scenario() into a single format:

        {
            "chain_id": str,
            "duration": float,
            "plan": [
                {"delay": float, "event": Event},
                ...
            ],
        }

    Supports both:
    - New-style dict plan (already in this format).
    - Old-style list[Event] (we wrap it with evenly spaced delays).
    """
    # New-style dict with "plan" key
    if isinstance(raw, dict) and "plan" in raw:
        chain_id = raw.get("chain_id", "unknown")
        duration = float(raw.get("duration", 0.0))
        plan_entries = raw.get("plan") or []
        # Ensure entries are of the form {"delay": float, "event": Event}
        normalized_entries = []
        for idx, entry in enumerate(plan_entries):
            if isinstance(entry, dict) and "event" in entry:
                delay = float(entry.get("delay", 0.0))
                ev = entry["event"]
            else:
                # Fallback if someone passed bare Event objects in the list
                delay = float(idx)
                ev = entry
            normalized_entries.append({"delay": delay, "event": ev})

        return {
            "chain_id": chain_id,
            "duration": duration,
            "plan": normalized_entries,
        }

    # Old-style: list[Event]
    if isinstance(raw, list):
        events = raw
        if not events:
            return {
                "chain_id": "invalid",
                "duration": 0.0,
                "plan": [],
            }

        # Evenly space events over 20–40s
        duration = random.uniform(20.0, 40.0)
        per_event = duration / max(len(events), 1)

        chain_id = getattr(events[0], "chain_id", "unknown")
        plan_entries = []
        for idx, ev in enumerate(events):
            plan_entries.append({"delay": idx * per_event, "event": ev})

        return {
            "chain_id": chain_id,
            "duration": duration,
            "plan": plan_entries,
        }

    # Completely unexpected output — fail safe.
    return {
        "chain_id": "invalid",
        "duration": 0.0,
        "plan": [],
    }


def _create_runtime_plan():
    """
    Call the attack engine, normalize its output, and attach runtime state:

        start_time: when this plan was scheduled
        index:      next entry index to emit
    """
    raw = generate_attack_scenario()
    normalized = _normalize_attack_plan(raw)

    # If plan is empty, just return None and let caller handle it.
    if not normalized["plan"]:
        return None

    normalized["start_time"] = time.time()
    normalized["index"] = 0
    return normalized


# ------------------------------------------------------------
# API ROUTES
# ------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"ok": True}


@app.get("/api/dashboard")
async def dashboard():
    counts = get_dashboard_counts()
    posture = get_posture()
    delta = get_deltas()
    return {
        "posture": posture,
        "counts": counts["by_severity"],
        "total": counts["total"],
        "delta": delta,
    }


@app.get("/api/events")
async def events():
    return [serialize_event(e) for e in get_all_events()]


@app.get("/api/events/{event_id}")
async def event_detail(event_id: int):
    e = get_event_by_id(event_id)
    if e is None:
        return {"error": "not found"}
    return serialize_event(e)


# Simple in-memory rate bucket per IP
_LAST_TRIGGER = {}          # ip -> timestamp of last call
_TRIGGER_COOLDOWN = 1.5     # seconds between allowed triggers per IP
_MAX_TRIGGERS_PER_MIN = 30  # hard cap per IP per 60s
_TRIGGER_HISTORY = {}       # ip -> list[timestamps]


@app.post("/api/attack/trigger")
async def trigger_attack(request: Request):
    """
    Request a new attack chain.
    Includes:
      - active chain limit
      - per-IP cooldown
      - per-IP rolling rate limit
    """
    client_ip = request.client.host

    # --- Rate-limit: cooldown ---
    now = time.time()
    last = _LAST_TRIGGER.get(client_ip, 0)
    if now - last < _TRIGGER_COOLDOWN:
        return {
            "status": "throttled",
            "reason": "cooldown_active",
            "retry_after": round(_TRIGGER_COOLDOWN - (now - last), 2),
        }
    _LAST_TRIGGER[client_ip] = now

    # --- Rate-limit: max triggers per minute ---
    history = _TRIGGER_HISTORY.setdefault(client_ip, [])
    # prune old entries
    one_minute_ago = now - 60
    history = [t for t in history if t >= one_minute_ago]
    _TRIGGER_HISTORY[client_ip] = history

    if len(history) >= _MAX_TRIGGERS_PER_MIN:
        return {
            "status": "throttled",
            "reason": "rate_limit_per_minute",
            "limit": _MAX_TRIGGERS_PER_MIN,
        }

    history.append(now)

    # --- NEW: active chain limit check ---
    if len(_attack_plans) >= MAX_ACTIVE_PLANS:
        return {
            "status": "busy",
            "reason": "max_active_plans_reached",
            "active": len(_attack_plans),
            "limit": MAX_ACTIVE_PLANS,
        }

    plan = _create_runtime_plan()
    if plan is None:
        return {
            "status": "skipped",
            "reason": "no_attack_generated",
        }

    _attack_plans.append(plan)

    return {
        "status": "scheduled",
        "chain_id": plan["chain_id"],
        "approx_duration_sec": round(plan["duration"], 1),
        "active": len(_attack_plans),
        "limit": MAX_ACTIVE_PLANS,
    }

# ------------------------------------------------------------
# SPA FALLBACK
# ------------------------------------------------------------

@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    if full_path.startswith("api/"):
        return {"error": "not found"}
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


# ------------------------------------------------------------
# BACKGROUND TASKS
# ------------------------------------------------------------

async def noise_loop():
    """
    Continuous background noise:
      - Every 0.5–0.8 seconds emit one benign Event.
    """
    while True:
        try:
            add_event(generate_noise_event())
        except Exception:
            # Fail closed on noise — dashboard should not die because of noise.
            pass
        await asyncio.sleep(random.uniform(0.5, 0.8))


async def attack_scheduler_loop():
    """
    Every 0.5s:
      - Iterate over active attack plans.
      - For each plan:
          * Emit any events whose scheduled time has passed.
          * Advance plan.index.
          * When all entries emitted, mark plan as done and drop it.
    """
    while True:
        now = time.time()
        done = []

        for plan in _attack_plans:
            entries = plan.get("plan", [])
            idx = plan.get("index", 0)
            start = plan.get("start_time", now)

            # Emit all events whose delay has elapsed.
            while idx < len(entries):
                entry = entries[idx]
                delay = float(entry.get("delay", 0.0))
                target_time = start + delay

                if now >= target_time:
                    ev = entry.get("event")
                    if ev is not None:
                
                        # Assign timestamp at the moment the event fires
                        ev.timestamp = datetime.utcnow().isoformat()
                
                        try:
                            add_event(ev)
                        except Exception:
                            pass
                    idx += 1
                    plan["index"] = idx
                else:
                    # Next event not due yet; move to next plan.
                    break

            # If we emitted all entries, mark this plan as complete.
            if idx >= len(entries):
                done.append(plan)

        # Remove completed plans
        for p in done:
            if p in _attack_plans:
                _attack_plans.remove(p)

        await asyncio.sleep(0.5)


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(noise_loop())
    asyncio.create_task(attack_scheduler_loop())
