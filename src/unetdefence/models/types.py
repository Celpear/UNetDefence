"""Shared types for the event schema."""

from enum import Enum


class EventSource(str, Enum):
    """Origin of the event (sensor or connector)."""

    ZEEK = "zeek"
    SURICATA = "suricata"
    FRITZ = "fritz"
    INTERNAL = "internal"


class EventType(str, Enum):
    """Normalised event type."""

    FLOW = "flow"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    ALERT = "alert"
    ROUTER = "router"
