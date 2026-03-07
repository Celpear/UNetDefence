"""Devices API: list devices, device profile, communication patterns."""

from uuid import UUID

from fastapi import APIRouter, HTTPException
from psycopg.rows import dict_row

from unetdefence.storage import get_pool, is_sqlite

router = APIRouter()


@router.get("")
async def list_devices() -> dict:
    """List all known devices."""
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT id, mac_address, current_ip, hostname, friendly_name, vendor, device_type, trust_level, last_seen_at
                FROM devices
                ORDER BY last_seen_at DESC
                """
            )
            rows = await cur.fetchall()
    return {"devices": [dict(r) for r in rows]}


@router.get("/{device_id}")
async def get_device(device_id: UUID) -> dict:
    """Device detail and recent communication summary."""
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT id, mac_address, current_ip, hostname, friendly_name, vendor, device_type, trust_level, first_seen_at, last_seen_at FROM devices WHERE id = %s",
                (str(device_id) if is_sqlite() else device_id,),
            )
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT dst_country_code, COUNT(*) AS flow_count, SUM(bytes_in + bytes_out) AS total_bytes
                FROM flows
                WHERE device_id = %s
                GROUP BY dst_country_code
                ORDER BY flow_count DESC
                LIMIT 20
                """,
                (str(device_id) if is_sqlite() else device_id,),
            )
            countries = await cur.fetchall()
    return {
        "device": dict(row),
        "top_countries": [dict(r) for r in countries],
    }


@router.get("/{device_id}/alerts")
async def get_device_alerts(device_id: UUID, limit: int = 50) -> dict:
    """Alerts for a device."""
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT id, ts, src_ip, dst_ip, signature, severity, explanation FROM alerts WHERE device_id = %s ORDER BY ts DESC LIMIT %s",
                (str(device_id) if is_sqlite() else device_id, limit),
            )
            rows = await cur.fetchall()
    return {"alerts": [dict(r) for r in rows]}
