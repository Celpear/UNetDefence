"""Suricata eve.json event parser."""

from datetime import datetime
from typing import Any

from unetdefence.models import FlowEvent, DnsEvent, HttpEvent, TlsEvent, AlertEvent
from unetdefence.models.types import EventSource


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def parse_suricata_event(
    event: dict[str, Any],
    raw_ref: str | None = None,
    sensor: str | None = None,
) -> FlowEvent | DnsEvent | HttpEvent | TlsEvent | AlertEvent | None:
    """Parse a single Suricata eve.json event into a normalised event."""
    event_type = event.get("event_type")
    ts = _ts(event.get("timestamp"))
    if ts is None:
        return None

    if event_type == "flow":
        return _parse_flow(event, ts, raw_ref, sensor)
    if event_type == "dns":
        return _parse_dns(event, ts, raw_ref, sensor)
    if event_type == "http":
        return _parse_http(event, ts, raw_ref, sensor)
    if event_type == "tls":
        return _parse_tls(event, ts, raw_ref, sensor)
    if event_type == "alert":
        return _parse_alert(event, ts, raw_ref, sensor)
    return None


def _parse_flow(
    e: dict[str, Any],
    ts: datetime,
    raw_ref: str | None,
    sensor: str | None,
) -> FlowEvent | None:
    src_ip = e.get("src_ip") or e.get("source", {}).get("ip", "")
    dst_ip = e.get("dest_ip") or e.get("destination", {}).get("ip", "")
    if not src_ip or not dst_ip:
        return None
    return FlowEvent(
        ts=ts,
        source=EventSource.SURICATA,
        sensor=sensor,
        raw_ref=raw_ref,
        src_ip=src_ip,
        src_port=int(e.get("src_port") or e.get("source", {}).get("port", 0)),
        dst_ip=dst_ip,
        dst_port=int(e.get("dest_port") or e.get("destination", {}).get("port", 0)),
        proto=e.get("proto") or None,
        bytes_in=int(e.get("bytes_to_server") or e.get("flow", {}).get("bytes_toserver", 0)),
        bytes_out=int(e.get("bytes_to_client") or e.get("flow", {}).get("bytes_toclient", 0)),
        packets_in=int(e.get("flow", {}).get("pkts_toserver", 0)),
        packets_out=int(e.get("flow", {}).get("pkts_toclient", 0)),
    )


def _parse_dns(
    e: dict[str, Any],
    ts: datetime,
    raw_ref: str | None,
    sensor: str | None,
) -> DnsEvent | None:
    dns = e.get("dns", {})
    query = dns.get("query") or dns.get("rdata") or ""
    if not query:
        return None
    answers = dns.get("answers") or []
    resolved = [a.get("rdata", a) for a in answers if isinstance(a, dict)] or [a for a in answers if isinstance(a, str)]
    return DnsEvent(
        ts=ts,
        source=EventSource.SURICATA,
        sensor=sensor,
        raw_ref=raw_ref,
        src_ip=e.get("src_ip") or "",
        query=query,
        qtype=dns.get("type") or None,
        answer_count=len(resolved),
        rcode=0,
        resolved_ips=[str(r) for r in resolved],
    )


def _parse_http(
    e: dict[str, Any],
    ts: datetime,
    raw_ref: str | None,
    sensor: str | None,
) -> HttpEvent | None:
    http = e.get("http", {})
    host = http.get("hostname") or http.get("host") or ""
    if not host:
        return None
    return HttpEvent(
        ts=ts,
        source=EventSource.SURICATA,
        sensor=sensor,
        raw_ref=raw_ref,
        host=host,
        uri=http.get("url") or None,
        method=http.get("http_method") or None,
        status_code=http.get("status_code") or None,
        user_agent=http.get("http_user_agent") or None,
        dst_ip=e.get("dest_ip") or None,
    )


def _parse_tls(
    e: dict[str, Any],
    ts: datetime,
    raw_ref: str | None,
    sensor: str | None,
) -> TlsEvent | None:
    tls = e.get("tls", {})
    sni = tls.get("sni") or tls.get("subject") or ""
    dst_ip = e.get("dest_ip") or e.get("dest_ip") or ""
    if not dst_ip and not sni:
        return None
    return TlsEvent(
        ts=ts,
        source=EventSource.SURICATA,
        sensor=sensor,
        raw_ref=raw_ref,
        dst_ip=dst_ip or "0.0.0.0",
        sni=sni or None,
        ja3=tls.get("ja3") or None,
        issuer=None,
        subject=tls.get("subject") or None,
        validation_status=None,
    )


def _parse_alert(
    e: dict[str, Any],
    ts: datetime,
    raw_ref: str | None,
    sensor: str | None,
) -> AlertEvent | None:
    alert = e.get("alert", {})
    signature = alert.get("signature") or alert.get("signature_id") or ""
    if not signature:
        signature = str(alert.get("signature_id", "unknown"))
    return AlertEvent(
        ts=ts,
        source=EventSource.SURICATA,
        sensor=sensor,
        raw_ref=raw_ref,
        src_ip=e.get("src_ip") or "",
        dst_ip=e.get("dest_ip") or "",
        signature=signature,
        category=alert.get("category") or None,
        severity=str(alert.get("severity") or 1),
        engine=alert.get("engine") or None,
        status=None,
        explanation=None,
    )
