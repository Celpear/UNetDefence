"""DB browse API: overview and table entries."""

from fastapi import APIRouter, Query
from psycopg.rows import dict_row

from unetdefence.storage import get_pool, get_sqlite_path, is_sqlite

router = APIRouter()

# Tables that have a ts or created_at column for ordering
TABLE_CONFIG = {
    "flows": ("ts", "ts DESC"),
    "alerts": ("ts", "ts DESC"),
    "devices": ("last_seen_at", "last_seen_at DESC"),
    "dns_events": ("ts", "ts DESC"),
    "http_events": ("ts", "ts DESC"),
    "tls_events": ("ts", "ts DESC"),
    "router_events": ("ts", "ts DESC"),
}


@router.get("/overview")
async def db_overview() -> dict:
    """Return row counts for all main tables. Use this to see what's in the DB."""
    pool = get_pool()
    tables = list(TABLE_CONFIG)
    counts: dict[str, int] = {}
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            for table in tables:
                try:
                    await cur.execute(f"SELECT COUNT(*) AS c FROM {table}")
                    row = await cur.fetchone()
                    counts[table] = row["c"] if row else 0
                except Exception:
                    counts[table] = -1
    out: dict = {"tables": counts}
    sqlite_path = get_sqlite_path()
    if sqlite_path:
        out["database_path"] = sqlite_path
    return out


@router.get("/entries")
async def db_entries(
    table: str = Query(..., description="Table name: flows, alerts, devices, dns_events, http_events, tls_events, router_events"),
    limit: int = Query(50, ge=1, le=500),
) -> dict:
    """Return recent rows from a table. Use ?table=flows&limit=50 to browse."""
    if table not in TABLE_CONFIG:
        return {"error": f"Unknown table. Choose one of: {', '.join(TABLE_CONFIG)}"}
    order_col, order_clause = TABLE_CONFIG[table]
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(f"SELECT * FROM {table} ORDER BY {order_clause} LIMIT %s", (limit,))
            rows = await cur.fetchall()
    return {"table": table, "count": len(rows), "entries": [dict(r) for r in rows]}
