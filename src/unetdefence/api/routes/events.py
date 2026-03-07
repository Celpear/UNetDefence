"""Events API: flows, DNS, HTTP, TLS, alerts, router events."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Query
from psycopg.rows import dict_row

from unetdefence.storage import get_pool, is_sqlite

router = APIRouter()


@router.get("/flows")
async def list_flows(
    limit: int = Query(100, ge=1, le=1000),
    since: datetime | None = Query(None),
    device_id: UUID | None = Query(None),
    country_code: str | None = Query(None),
) -> dict:
    """List flows with optional filters."""
    pool = get_pool()
    conditions = []
    params: list = []
    if since:
        conditions.append("f.ts >= %s")
        params.append(since)
    if device_id:
        conditions.append("f.device_id = %s")
        params.append(str(device_id) if is_sqlite() else device_id)
    if country_code:
        conditions.append("f.dst_country_code = %s")
        params.append(country_code)
    where = " AND ".join(conditions) if conditions else "TRUE"
    params.append(limit)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"""
                SELECT id, ts, src_ip, src_port, dst_ip, dst_port, proto, device_id,
                       dst_country_code, dst_asn, bytes_in, bytes_out, dns_query, http_host, tls_sni
                FROM flows f
                WHERE {where}
                ORDER BY f.ts DESC
                LIMIT %s
                """,
                params,
            )
            rows = await cur.fetchall()
    return {"flows": [dict(r) for r in rows]}


@router.get("/alerts")
async def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    since: datetime | None = Query(None),
    device_id: UUID | None = Query(None),
    severity: str | None = Query(None),
) -> dict:
    """List security alerts."""
    pool = get_pool()
    conditions = []
    params: list = []
    if since:
        conditions.append("ts >= %s")
        params.append(since)
    if device_id:
        conditions.append("device_id = %s")
        params.append(str(device_id) if is_sqlite() else device_id)
    if severity:
        conditions.append("severity = %s")
        params.append(severity)
    where = " AND ".join(conditions) if conditions else "TRUE"
    params.append(limit)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"""
                SELECT id, ts, device_id, src_ip, dst_ip, signature, category, severity, explanation
                FROM alerts
                WHERE {where}
                ORDER BY ts DESC
                LIMIT %s
                """,
                params,
            )
            rows = await cur.fetchall()
    return {"alerts": [dict(r) for r in rows]}


@router.get("/router")
async def list_router_events(
    limit: int = Query(100, ge=1, le=500),
    since: datetime | None = Query(None),
) -> dict:
    """List router/FRITZ!Box events."""
    pool = get_pool()
    params: list = []
    if since:
        params.append(since)
    params.append(limit)
    q = "WHERE ts >= %s" if since else "WHERE TRUE"
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT id, ts, event_type, device_id, message, severity FROM router_events {q} ORDER BY ts DESC LIMIT %s",
                params,
            )
            rows = await cur.fetchall()
    return {"events": [dict(r) for r in rows]}
