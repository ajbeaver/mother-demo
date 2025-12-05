from collections import deque
from typing import Deque, List, Optional, Dict
from datetime import datetime, timedelta

from backend.modules import classifier, posture, recommender
from backend.modules.utils import Event

# Rolling buffer of recent events
_MAX_EVENTS: int = 500
_events: Deque[Event] = deque(maxlen=_MAX_EVENTS)

# Global event counter
_event_counter: int = 0


def next_event_id() -> int:
    """
    Return the next global event ID.
    Sequential, starting from 1.
    """
    global _event_counter
    _event_counter += 1
    return _event_counter


def _ensure_timestamp(event: Event) -> None:
    """
    Make sure the event has a valid ISO-8601 timestamp.
    If it is missing/empty, fill with current UTC.
    """
    ts = getattr(event, "timestamp", None)
    if not ts:
        event.timestamp = datetime.utcnow().isoformat()


def _sorted_events_newest_first(events: Deque[Event]) -> List[Event]:
    """
    Return events ordered by (timestamp, id) newest-first.
    """
    for e in events:
        _ensure_timestamp(e)

    return sorted(
        list(events),
        key=lambda e: (e.timestamp, e.id),
        reverse=True,
    )


def add_event(event: Event) -> Event:
    """
    Store an Event in the rolling buffer.
    Assign ID + timestamp if missing.
    """
    global _events

    if getattr(event, "id", None) in (None, 0):
        event.id = next_event_id()

    _ensure_timestamp(event)

    _events.append(event)
    return event


def get_all_events() -> List[Event]:
    """
    Return all events newest-first.
    """
    return _sorted_events_newest_first(_events)


def get_events_by_severity(severity: str) -> List[Event]:
    """
    Return events filtered by severity.
    """
    filtered = [e for e in _events if e.severity == severity]
    return sorted(
        filtered,
        key=lambda e: (e.timestamp, e.id),
        reverse=True,
    )


def get_event_by_id(event_id: int) -> Optional[Event]:
    """
    Find an event by ID.
    """
    for e in reversed(_events):
        if e.id == event_id:
            return e
    return None


def get_dashboard_counts() -> Dict[str, Dict[str, int]]:
    """
    Total count + per-severity counts.
    """
    total = len(_events)
    counts = {
        "benign": 0,
        "suspicious": 0,
        "malicious": 0,
        "critical": 0,
    }

    for e in _events:
        if e.severity in counts:
            counts[e.severity] += 1

    return {
        "total": total,
        "by_severity": counts,
    }


def serialize_event(e: Event) -> Dict:
    """
    Convert an Event to a JSON-serializable dict.
    RECOMMENDATION FIELD PATCHED:
    Now uses recommender.recommend_for_event() and extracts ONLY .action
    """

    event_dict = {
        "id": e.id,
        "timestamp": getattr(e, "timestamp", None),
        "chain_id": getattr(e, "chain_id", None),
        "stage": getattr(e, "stage", None),
        "source_ip": e.source_ip,
        "dest_port": e.dest_port,
        "phase": e.phase,
        "category": e.category,
        "severity": e.severity,
        "raw": e.raw,
        "parsed": e.parsed,
    }

    # classification for this specific event
    classification = classifier.classify_event(event_dict)

    # only return the action string, NOT full dict
    rec = recommender.recommend_for_event(event_dict, classification)
    action = rec.get("action", "none")

    return {
        **event_dict,
        "recommendation": action,
    }


def get_recent_events(limit: int = 25) -> List[Event]:
    """
    Latest N events.
    """
    return _sorted_events_newest_first(_events)[:limit]


def get_events_in_window(seconds: int) -> List[Event]:
    """
    Return events within the past N seconds.
    """
    cutoff = datetime.utcnow() - timedelta(seconds=seconds)
    result: List[Event] = []

    for e in _events:
        ts_str = getattr(e, "timestamp", None)
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            continue

        if ts >= cutoff:
            result.append(e)

    return sorted(
        result,
        key=lambda e: (e.timestamp, e.id),
        reverse=True,
    )


def get_posture(window_seconds: int = 15) -> str:
    """
    Compute Mother posture from:
    • per-event classifications
    • per-chain classifications
    """
    recent = get_events_in_window(window_seconds)

    recent_dicts = [
        {
            "id": e.id,
            "timestamp": getattr(e, "timestamp", None),
            "chain_id": getattr(e, "chain_id", None),
            "stage": getattr(e, "stage", None),
            "source_ip": e.source_ip,
            "dest_port": e.dest_port,
            "phase": e.phase,
            "category": e.category,
            "severity": e.severity,
            "raw": e.raw,
            "parsed": e.parsed,
        }
        for e in recent
    ]

    chains = {}
    for ev in recent_dicts:
        cid = ev.get("chain_id")
        if not cid:
            continue
        chains.setdefault(cid, []).append(ev)

    chain_summaries = []
    for cid, evts in chains.items():
        summary = classifier.classify_chain(evts)
        summary["chain_id"] = cid
        chain_summaries.append(summary)

    return posture.determine_posture(
        recent_events=recent_dicts,
        chain_summaries=chain_summaries,
    )


def get_deltas(window_seconds: int = 15) -> Dict[str, int]:
    """
    Count severities in last N seconds.
    """
    recent = get_events_in_window(window_seconds)
    delta = {
        "benign": 0,
        "suspicious": 0,
        "malicious": 0,
        "critical": 0,
    }

    for e in recent:
        if e.severity in delta:
            delta[e.severity] += 1

    return delta
