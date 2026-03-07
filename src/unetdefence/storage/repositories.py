"""Repository layer: persist and query normalised events."""

import json
from uuid import UUID, uuid4

from psycopg import AsyncConnection
from psycopg.rows import dict_row

from unetdefence.models import (
    FlowEvent,
    DnsEvent,
    HttpEvent,
    TlsEvent,
    AlertEvent,
    RouterEvent,
)
from unetdefence.storage.connection import is_sqlite


def _ensure_uuid(val: UUID | str) -> UUID:
    return val if isinstance(val, UUID) else UUID(str(val))


async def insert_flow(conn: AsyncConnection, e: FlowEvent, device_id: UUID | None = None) -> UUID:
    """Insert a flow event; returns id."""
    did = device_id or e.device_id
    if is_sqlite():
        row_id = uuid4()
        sql = """
            INSERT INTO flows (
                id, ts, src_ip, src_port, dst_ip, dst_port, proto, transport, service,
                device_id, dst_country_code, dst_asn, bytes_in, bytes_out,
                packets_in, packets_out, duration_ms, dns_query, http_host, tls_sni,
                source, sensor, raw_ref
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING id
            """
        params = (str(row_id), e.ts, e.src_ip, e.src_port, e.dst_ip, e.dst_port, e.proto, e.transport, e.service, str(did) if did else None, e.dst_country_code, e.dst_asn, e.bytes_in, e.bytes_out, e.packets_in, e.packets_out, e.duration_ms, e.dns_query, e.http_host, e.tls_sni, e.source.value, e.sensor, e.raw_ref)
    else:
        sql = """
            INSERT INTO flows (
                ts, src_ip, src_port, dst_ip, dst_port, proto, transport, service,
                device_id, dst_country_code, dst_asn, bytes_in, bytes_out,
                packets_in, packets_out, duration_ms, dns_query, http_host, tls_sni,
                source, sensor, raw_ref
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING id
            """
        params = (e.ts, e.src_ip, e.src_port, e.dst_ip, e.dst_port, e.proto, e.transport, e.service, did, e.dst_country_code, e.dst_asn, e.bytes_in, e.bytes_out, e.packets_in, e.packets_out, e.duration_ms, e.dns_query, e.http_host, e.tls_sni, e.source.value, e.sensor, e.raw_ref)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        row = await cur.fetchone()
        return _ensure_uuid(row["id"])


async def insert_dns(conn: AsyncConnection, e: DnsEvent, device_id: UUID | None = None) -> UUID:
    resolved = e.resolved_ips or []
    if is_sqlite():
        resolved_param: str | list = json.dumps(resolved)
        sql = """
            INSERT INTO dns_events (ts, device_id, src_ip, query, qtype, answer_count, rcode, resolved_ips, source, sensor, raw_ref)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """
    else:
        resolved_param = resolved
        sql = """
            INSERT INTO dns_events (ts, device_id, src_ip, query, qtype, answer_count, rcode, resolved_ips, source, sensor, raw_ref)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s::inet[], %s, %s, %s)
            RETURNING id
        """
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            sql,
            (
                e.ts,
                device_id or e.device_id,
                e.src_ip,
                e.query,
                e.qtype,
                e.answer_count,
                e.rcode,
                resolved_param,
                e.source.value,
                e.sensor,
                e.raw_ref,
            ),
        )
        row = await cur.fetchone()
        return _ensure_uuid(row["id"])


async def insert_http(conn: AsyncConnection, e: HttpEvent, device_id: UUID | None = None) -> UUID:
    did = device_id or e.device_id
    if is_sqlite():
        row_id = uuid4()
        sql = "INSERT INTO http_events (id, ts, device_id, host, uri, method, status_code, user_agent, dst_ip, dst_country_code, source, sensor, raw_ref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id"
        params = (str(row_id), e.ts, str(did) if did else None, e.host, e.uri, e.method, e.status_code, e.user_agent, e.dst_ip, e.dst_country_code, e.source.value, e.sensor, e.raw_ref)
    else:
        sql = "INSERT INTO http_events (ts, device_id, host, uri, method, status_code, user_agent, dst_ip, dst_country_code, source, sensor, raw_ref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id"
        params = (e.ts, did, e.host, e.uri, e.method, e.status_code, e.user_agent, e.dst_ip, e.dst_country_code, e.source.value, e.sensor, e.raw_ref)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        row = await cur.fetchone()
        return _ensure_uuid(row["id"])


async def insert_tls(conn: AsyncConnection, e: TlsEvent, device_id: UUID | None = None) -> UUID:
    did = device_id or e.device_id
    if is_sqlite():
        row_id = uuid4()
        sql = "INSERT INTO tls_events (id, ts, device_id, dst_ip, sni, ja3, issuer, subject, validation_status, source, sensor, raw_ref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id"
        params = (str(row_id), e.ts, str(did) if did else None, e.dst_ip, e.sni, e.ja3, e.issuer, e.subject, e.validation_status, e.source.value, e.sensor, e.raw_ref)
    else:
        sql = "INSERT INTO tls_events (ts, device_id, dst_ip, sni, ja3, issuer, subject, validation_status, source, sensor, raw_ref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id"
        params = (e.ts, did, e.dst_ip, e.sni, e.ja3, e.issuer, e.subject, e.validation_status, e.source.value, e.sensor, e.raw_ref)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        row = await cur.fetchone()
        return _ensure_uuid(row["id"])


async def insert_alert(conn: AsyncConnection, e: AlertEvent, device_id: UUID | None = None) -> UUID:
    did = device_id or e.device_id
    if is_sqlite():
        row_id = uuid4()
        sql = "INSERT INTO alerts (id, ts, device_id, src_ip, dst_ip, signature, category, severity, engine, status, explanation, source, sensor, raw_ref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id"
        params = (str(row_id), e.ts, str(did) if did else None, e.src_ip, e.dst_ip, e.signature, e.category, e.severity, e.engine, e.status, e.explanation, e.source.value, e.sensor, e.raw_ref)
    else:
        sql = "INSERT INTO alerts (ts, device_id, src_ip, dst_ip, signature, category, severity, engine, status, explanation, source, sensor, raw_ref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id"
        params = (e.ts, did, e.src_ip, e.dst_ip, e.signature, e.category, e.severity, e.engine, e.status, e.explanation, e.source.value, e.sensor, e.raw_ref)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        row = await cur.fetchone()
        return _ensure_uuid(row["id"])


async def insert_router_event(conn: AsyncConnection, e: RouterEvent, device_id: UUID | None = None) -> UUID:
    did = device_id or e.device_id
    payload_json = json.dumps(e.raw_payload) if e.raw_payload else None
    if is_sqlite():
        row_id = uuid4()
        sql = "INSERT INTO router_events (id, ts, event_type, device_id, message, severity, raw_payload, source) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id"
        params = (str(row_id), e.ts, e.code, str(did) if did else None, e.message, e.severity, payload_json, e.source.value)
    else:
        sql = "INSERT INTO router_events (ts, event_type, device_id, message, severity, raw_payload, source) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id"
        params = (e.ts, e.code, did, e.message, e.severity, payload_json, e.source.value)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        row = await cur.fetchone()
        return _ensure_uuid(row["id"])


async def get_device_id_by_ip(conn: AsyncConnection, ip: str) -> UUID | None:
    """Resolve device_id for an internal IP (current assignment)."""
    sql = "SELECT id FROM devices WHERE current_ip = %s" if is_sqlite() else "SELECT id FROM devices WHERE current_ip = %s::inet"
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, (ip,))
        row = await cur.fetchone()
    return _ensure_uuid(row["id"]) if row else None


async def get_device_id_by_mac(conn: AsyncConnection, mac: str) -> UUID | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT id FROM devices WHERE mac_address = %s", (mac,))
        row = await cur.fetchone()
    return _ensure_uuid(row["id"]) if row else None


async def upsert_device(
    conn: AsyncConnection,
    *,
    mac_address: str | None = None,
    current_ip: str | None = None,
    hostname: str | None = None,
    friendly_name: str | None = None,
) -> UUID:
    """Insert or update device by MAC; update last_seen_at and optionally current_ip. Returns device id."""
    if not mac_address and not current_ip:
        raise ValueError("Need mac_address or current_ip")
    async with conn.cursor(row_factory=dict_row) as cur:
        if mac_address:
            if is_sqlite():
                dev_id = str(uuid4())
                await cur.execute(
                    """
                    INSERT INTO devices (id, mac_address, current_ip, hostname, friendly_name, last_seen_at)
                    VALUES (%s, %s, %s, %s, %s, datetime('now'))
                    ON CONFLICT (mac_address) DO UPDATE SET
                        current_ip = COALESCE(excluded.current_ip, current_ip),
                        hostname = COALESCE(excluded.hostname, hostname),
                        friendly_name = COALESCE(excluded.friendly_name, friendly_name),
                        last_seen_at = datetime('now'),
                        updated_at = datetime('now')
                    RETURNING id
                    """,
                    (dev_id, mac_address, current_ip, hostname, friendly_name),
                )
            else:
                await cur.execute(
                    """
                    INSERT INTO devices (mac_address, current_ip, hostname, friendly_name, last_seen_at)
                    VALUES (%s, %s::inet, %s, %s, now())
                    ON CONFLICT (mac_address) DO UPDATE SET
                        current_ip = COALESCE(EXCLUDED.current_ip::inet, devices.current_ip),
                        hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
                        friendly_name = COALESCE(EXCLUDED.friendly_name, devices.friendly_name),
                        last_seen_at = now(),
                        updated_at = now()
                    RETURNING id
                    """,
                    (mac_address, current_ip, hostname, friendly_name),
                )
            row = await cur.fetchone()
            if row:
                return _ensure_uuid(row["id"])
        if current_ip:
            sql = "SELECT id FROM devices WHERE current_ip = %s" if is_sqlite() else "SELECT id FROM devices WHERE current_ip = %s::inet"
            await cur.execute(sql, (current_ip,))
            row = await cur.fetchone()
            if row:
                upd = "UPDATE devices SET last_seen_at = datetime('now'), updated_at = datetime('now') WHERE id = %s" if is_sqlite() else "UPDATE devices SET last_seen_at = now(), updated_at = now() WHERE id = %s"
                await cur.execute(upd, (row["id"],))
                return _ensure_uuid(row["id"])
        if is_sqlite():
            dev_id = str(uuid4())
            await cur.execute(
                "INSERT INTO devices (id, current_ip, last_seen_at) VALUES (%s, %s, datetime('now')) RETURNING id",
                (dev_id, current_ip),
            )
        else:
            await cur.execute(
                "INSERT INTO devices (current_ip, last_seen_at) VALUES (%s::inet, now()) RETURNING id",
                (current_ip,),
            )
        row = await cur.fetchone()
        return _ensure_uuid(row["id"])
