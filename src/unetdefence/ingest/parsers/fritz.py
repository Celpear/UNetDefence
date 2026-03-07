"""FRITZ!Box / router event parser."""

from datetime import datetime
from typing import Any

from unetdefence.models import RouterEvent
from unetdefence.models.types import EventSource


def parse_fritz_event(
    payload: dict[str, Any],
    raw_ref: str | None = None,
) -> RouterEvent | None:
    """Parse a FRITZ!Box or router API event into RouterEvent."""
    ts = payload.get("timestamp") or payload.get("ts")
    if ts is None:
        ts = datetime.utcnow()
    elif isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.utcnow()
    elif isinstance(ts, (int, float)):
        ts = datetime.utcfromtimestamp(ts)

    event_type = payload.get("event_type") or payload.get("type") or "unknown"
    return RouterEvent(
        ts=ts,
        source=EventSource.FRITZ,
        raw_ref=raw_ref,
        code=str(event_type),
        message=payload.get("message") or payload.get("description"),
        severity=payload.get("severity"),
        raw_payload=payload,
    )
