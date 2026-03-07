"""Normalised internal event schema (event-normalised representation)."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from unetdefence.models.types import EventSource, EventType


class NormalisedEvent(BaseModel):
    """Base for all normalised events; common fields and versioning."""

    id: UUID | None = None
    ts: datetime
    source: EventSource
    event_type: EventType
    sensor: str | None = None
    raw_ref: str | None = Field(default=None, description="Reference to raw log line or file")
    version: int = 1


class FlowEvent(NormalisedEvent):
    """Normalised network flow (from Zeek conn.log or Suricata flow)."""

    event_type: EventType = EventType.FLOW
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str | None = None
    transport: str | None = None
    service: str | None = None
    device_id: UUID | None = None
    dst_country_code: str | None = None
    dst_asn: int | None = None
    dst_asn_org: str | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    duration_ms: float | None = None
    dns_query: str | None = None
    http_host: str | None = None
    tls_sni: str | None = None


class DnsEvent(NormalisedEvent):
    """DNS-specific event (query/response)."""

    event_type: EventType = EventType.DNS
    device_id: UUID | None = None
    src_ip: str
    query: str
    qtype: str | None = None
    answer_count: int = 0
    rcode: int = 0
    resolved_ips: list[str] = Field(default_factory=list)


class HttpEvent(NormalisedEvent):
    """HTTP request metadata."""

    event_type: EventType = EventType.HTTP
    device_id: UUID | None = None
    host: str
    uri: str | None = None
    method: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    dst_ip: str | None = None
    dst_country_code: str | None = None


class TlsEvent(NormalisedEvent):
    """TLS/SSL connection metadata (SNI, certificate)."""

    event_type: EventType = EventType.TLS
    device_id: UUID | None = None
    dst_ip: str
    sni: str | None = None
    ja3: str | None = None
    issuer: str | None = None
    subject: str | None = None
    validation_status: str | None = None


class AlertEvent(NormalisedEvent):
    """Security alert (e.g. from Suricata)."""

    event_type: EventType = EventType.ALERT
    device_id: UUID | None = None
    src_ip: str
    dst_ip: str
    signature: str
    category: str | None = None
    severity: str
    engine: str | None = None
    status: str | None = None
    explanation: str | None = None


class RouterEvent(NormalisedEvent):
    """FRITZ!Box / router context event."""

    event_type: EventType = EventType.ROUTER
    device_id: UUID | None = None
    code: str = Field(..., description="Router event kind: e.g. new_device, wan_reconnect")
    message: str | None = None
    severity: str | None = None
    raw_payload: dict[str, Any] | None = None
