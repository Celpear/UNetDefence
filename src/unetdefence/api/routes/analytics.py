"""Analytics API: top countries, traffic, baselines, new destinations."""

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Query
from psycopg.rows import dict_row

from unetdefence.storage import get_pool, is_sqlite

router = APIRouter()


def _utc_now() -> datetime:
    return datetime.now(ZoneInfo("UTC"))


@router.get("/top-countries")
async def top_countries(
    limit: int = Query(20, ge=1, le=100),
    since_hours: int = Query(24, ge=1, le=720),
) -> dict:
    """Top destination countries by flow count (and optionally bytes)."""
    pool = get_pool()
    since = _utc_now() - timedelta(hours=since_hours)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT dst_country_code AS country_code, COUNT(*) AS flow_count, SUM(bytes_in + bytes_out) AS total_bytes
                FROM flows
                WHERE ts >= %s AND dst_country_code IS NOT NULL
                GROUP BY dst_country_code
                ORDER BY flow_count DESC
                LIMIT %s
                """,
                (since, limit),
            )
            rows = await cur.fetchall()
    return {"countries": [dict(r) for r in rows]}


@router.get("/devices-by-country")
async def devices_by_country(
    country_code: str = Query(..., min_length=2, max_length=2),
    since_hours: int = Query(24, ge=1, le=720),
) -> dict:
    """Devices that communicated with the given country."""
    pool = get_pool()
    since = _utc_now() - timedelta(hours=since_hours)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT f.device_id, d.friendly_name, d.hostname, d.current_ip,
                       COUNT(*) AS flow_count, SUM(f.bytes_in + f.bytes_out) AS total_bytes
                FROM flows f
                LEFT JOIN devices d ON d.id = f.device_id
                WHERE f.ts >= %s AND f.dst_country_code = %s
                GROUP BY f.device_id, d.friendly_name, d.hostname, d.current_ip
                ORDER BY flow_count DESC
                """,
                (since, country_code.upper()),
            )
            rows = await cur.fetchall()
    return {"country_code": country_code.upper(), "devices": [dict(r) for r in rows]}


@router.get("/anomalies")
async def list_anomalies(
    since_days: int = Query(7, ge=1, le=90),
) -> dict:
    """Devices with baseline anomalies (is_anomalous)."""
    pool = get_pool()
    if is_sqlite():
        sql = """
            SELECT b.baseline_date, b.device_id, d.friendly_name, d.hostname, b.metric_name, b.metric_value, b.mean_30d, b.stddev_30d
            FROM daily_baselines b
            LEFT JOIN devices d ON d.id = b.device_id
            WHERE b.is_anomalous AND b.baseline_date >= date('now', %s)
            ORDER BY b.baseline_date DESC
            LIMIT 100
            """
        params = (f"-{since_days} days",)
    else:
        sql = """
            SELECT b.baseline_date, b.device_id, d.friendly_name, d.hostname, b.metric_name, b.metric_value, b.mean_30d, b.stddev_30d
            FROM daily_baselines b
            LEFT JOIN devices d ON d.id = b.device_id
            WHERE b.is_anomalous AND b.baseline_date >= CURRENT_DATE - %s::integer
            ORDER BY b.baseline_date DESC
            LIMIT 100
            """
        params = (since_days,)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(sql, params)
            rows = await cur.fetchall()
    return {"anomalies": [dict(r) for r in rows]}


@router.get("/tls-sni")
async def tls_sni(
    since_hours: int = Query(24, ge=1, le=720),
    limit: int = Query(200, ge=1, le=2000),
) -> dict:
    """Distinct TLS SNI names observed (from tls_events)."""
    pool = get_pool()
    since = _utc_now() - timedelta(hours=since_hours)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT sni, COUNT(*) AS tls_count
                FROM tls_events
                WHERE ts >= %s AND sni IS NOT NULL AND sni != ''
                GROUP BY sni
                ORDER BY tls_count DESC, sni
                LIMIT %s
                """,
                (since, limit),
            )
            rows = await cur.fetchall()
    return {"since_hours": since_hours, "sni": [dict(r) for r in rows]}


@router.get("/domains")
async def domains(
    since_hours: int = Query(24, ge=1, le=720),
    limit: int = Query(500, ge=1, le=5000),
) -> dict:
    """Combined set of domains from DNS queries, HTTP hosts and TLS SNI."""
    pool = get_pool()
    since = _utc_now() - timedelta(hours=since_hours)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT domain, COUNT(*) AS cnt
                FROM (
                    SELECT query AS domain
                    FROM dns_events
                    WHERE ts >= %s AND query IS NOT NULL AND query != ''
                    UNION ALL
                    SELECT host AS domain
                    FROM http_events
                    WHERE ts >= %s AND host IS NOT NULL AND host != ''
                    UNION ALL
                    SELECT sni AS domain
                    FROM tls_events
                    WHERE ts >= %s AND sni IS NOT NULL AND sni != ''
                ) d
                GROUP BY domain
                ORDER BY cnt DESC, domain
                LIMIT %s
                """,
                (since, since, since, limit),
            )
            rows = await cur.fetchall()
    return {"since_hours": since_hours, "domains": [dict(r) for r in rows]}


@router.get("/dst-ips")
async def dst_ips(
    since_hours: int = Query(24, ge=1, le=720),
    limit: int = Query(500, ge=1, le=5000),
) -> dict:
    """Destination IPs from flows with counts."""
    pool = get_pool()
    since = _utc_now() - timedelta(hours=since_hours)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT dst_ip AS ip, COUNT(*) AS flow_count
                FROM flows
                WHERE ts >= %s
                GROUP BY dst_ip
                ORDER BY flow_count DESC, ip
                LIMIT %s
                """,
                (since, limit),
            )
            rows = await cur.fetchall()
    return {"since_hours": since_hours, "ips": [dict(r) for r in rows]}
