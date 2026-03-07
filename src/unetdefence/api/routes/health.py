"""Health check and status endpoints."""

from fastapi import APIRouter

from psycopg.rows import dict_row

from unetdefence.config import get_settings
from unetdefence.storage import get_pool

router = APIRouter()


@router.get("")
async def health() -> dict:
    """Basic liveness."""
    return {"status": "ok"}


@router.get("/ready")
async def ready() -> dict:
    """Readiness: DB connectivity."""
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            async with conn.cursor(row_factory=None) as cur:
                await cur.execute("SELECT 1")
                await cur.fetchone()
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        return {"status": "error", "database": str(e)}


@router.get("/stats")
async def stats() -> dict:
    """Simple stats: DB counts and whether ingest is configured. Use this to see if network analysis is feeding data."""
    settings = get_settings()
    ingest_configured = bool(settings.ingest.zeek_log_dir or settings.ingest.suricata_eve_path)
    out = {
        "ingest_configured": ingest_configured,
        "ingest_zeek_dir": settings.ingest.zeek_log_dir,
        "ingest_suricata_path": settings.ingest.suricata_eve_path,
        "flows_count": 0,
        "alerts_count": 0,
        "devices_count": 0,
    }
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute("SELECT COUNT(*) AS c FROM flows")
                out["flows_count"] = (await cur.fetchone())["c"]
                await cur.execute("SELECT COUNT(*) AS c FROM alerts")
                out["alerts_count"] = (await cur.fetchone())["c"]
                await cur.execute("SELECT COUNT(*) AS c FROM devices")
                out["devices_count"] = (await cur.fetchone())["c"]
    except Exception as e:
        out["database_error"] = str(e)
    return out
