"""Zeek log parsers: conn, dns, http, ssl."""

from datetime import datetime
from typing import Any

from unetdefence.models import FlowEvent, DnsEvent, HttpEvent, TlsEvent
from unetdefence.models.types import EventSource


def _ts(s: str) -> datetime | None:
    """Parse Zeek float timestamp to datetime."""
    try:
        return datetime.utcfromtimestamp(float(s))
    except (ValueError, TypeError):
        return None


def _int(v: Any) -> int:
    try:
        return int(v) if v != "-" and v is not None else 0
    except (ValueError, TypeError):
        return 0


def _float(v: Any) -> float | None:
    try:
        return float(v) if v != "-" and v is not None else None
    except (ValueError, TypeError):
        return None


def parse_zeek_conn(fields: dict[str, Any], raw_ref: str | None = None, sensor: str | None = None) -> FlowEvent | None:
    """Parse Zeek conn.log row into FlowEvent."""
    ts = _ts(fields.get("ts"))
    if ts is None:
        return None
    return FlowEvent(
        ts=ts,
        source=EventSource.ZEEK,
        sensor=sensor,
        raw_ref=raw_ref,
        src_ip=str(fields.get("id.orig_h", "")),
        src_port=_int(fields.get("id.orig_p", 0)),
        dst_ip=str(fields.get("id.resp_h", "")),
        dst_port=_int(fields.get("id.resp_p", 0)),
        proto=fields.get("proto") or None,
        transport=fields.get("conn_trans") or None,
        service=fields.get("service") or None,
        bytes_in=_int(fields.get("orig_bytes", fields.get("resp_bytes", 0))),
        bytes_out=_int(fields.get("resp_bytes", fields.get("orig_bytes", 0))),
        packets_in=_int(fields.get("orig_pkts", 0)),
        packets_out=_int(fields.get("resp_pkts", 0)),
        duration_ms=_float(fields.get("duration")),
    )


def parse_zeek_dns(fields: dict[str, Any], raw_ref: str | None = None, sensor: str | None = None) -> DnsEvent | None:
    """Parse Zeek dns.log row into DnsEvent."""
    ts = _ts(fields.get("ts"))
    if ts is None:
        return None
    answers = fields.get("answers") or []
    if isinstance(answers, str):
        answers = [answers]
    return DnsEvent(
        ts=ts,
        source=EventSource.ZEEK,
        sensor=sensor,
        raw_ref=raw_ref,
        src_ip=str(fields.get("id.orig_h", "")),
        query=str(fields.get("query", "")),
        qtype=fields.get("qtype_name") or None,
        answer_count=len(answers),
        rcode=_int(fields.get("rcode", 0)),
        resolved_ips=[str(a) for a in answers if a and str(a).replace(".", "").isdigit()],
    )


def parse_zeek_http(fields: dict[str, Any], raw_ref: str | None = None, sensor: str | None = None) -> HttpEvent | None:
    """Parse Zeek http.log row into HttpEvent."""
    ts = _ts(fields.get("ts"))
    if ts is None:
        return None
    host = fields.get("host") or ""
    return HttpEvent(
        ts=ts,
        source=EventSource.ZEEK,
        sensor=sensor,
        raw_ref=raw_ref,
        host=host,
        uri=fields.get("uri") or None,
        method=fields.get("method") or None,
        status_code=_int(fields.get("status_code", 0)) or None,
        user_agent=fields.get("user_agent") or None,
        dst_ip=fields.get("id.resp_h") or None,
    )


def parse_zeek_ssl(fields: dict[str, Any], raw_ref: str | None = None, sensor: str | None = None) -> TlsEvent | None:
    """Parse Zeek ssl.log / TLS row into TlsEvent."""
    ts = _ts(fields.get("ts"))
    if ts is None:
        return None
    return TlsEvent(
        ts=ts,
        source=EventSource.ZEEK,
        sensor=sensor,
        raw_ref=raw_ref,
        dst_ip=str(fields.get("id.resp_h", "")),
        sni=fields.get("server_name") or None,
        issuer=fields.get("issuer") or None,
        subject=fields.get("subject") or None,
        validation_status=fields.get("validation_status") or None,
    )
