"""Aggregation and baseline jobs (5-min and daily)."""

import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from unetdefence.storage import get_pool, is_sqlite

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(ZoneInfo("UTC"))


async def run_aggregation_5m() -> None:
    """Compute 5-minute aggregations for the previous 5-minute bucket (PostgreSQL only)."""
    if is_sqlite():
        logger.debug("Skipping 5m aggregation (SQLite)")
        return
    pool = get_pool()
    # Bucket: floor current time to 5 min, then subtract 5 min
    now = _utc_now()
    bucket_end = now.replace(minute=(now.minute // 5) * 5, second=0, microsecond=0)
    bucket_start = bucket_end - timedelta(minutes=5)
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO aggregation_5m (
                    bucket_start, device_id, country_code, asn,
                    flow_count, distinct_dst_ips, bytes_in, bytes_out, dns_count, alert_count
                )
                SELECT
                    %s::timestamptz,
                    f.device_id,
                    f.dst_country_code,
                    f.dst_asn,
                    COUNT(*),
                    COUNT(DISTINCT f.dst_ip),
                    COALESCE(SUM(f.bytes_in), 0),
                    COALESCE(SUM(f.bytes_out), 0),
                    0,
                    0
                FROM flows f
                WHERE f.ts >= %s AND f.ts < %s
                GROUP BY f.device_id, f.dst_country_code, f.dst_asn
                ON CONFLICT (bucket_start, device_id, country_code, asn) DO UPDATE SET
                    flow_count = EXCLUDED.flow_count,
                    distinct_dst_ips = EXCLUDED.distinct_dst_ips,
                    bytes_in = EXCLUDED.bytes_in,
                    bytes_out = EXCLUDED.bytes_out
                """,
                (bucket_start, bucket_start, bucket_end),
            )
    logger.info("Aggregation 5m done for bucket %s", bucket_start)


async def run_daily_baselines() -> None:
    """Compute daily baselines (mean_7d, mean_30d, stddev_30d) for yesterday (PostgreSQL only)."""
    if is_sqlite():
        logger.debug("Skipping daily baselines (SQLite)")
        return
    pool = get_pool()
    today = _utc_now().date()
    yesterday = today - timedelta(days=1)
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                WITH daily_totals AS (
                    SELECT device_id, SUM(flow_count)::double precision AS total_flows
                    FROM aggregation_5m
                    WHERE bucket_start >= %s::timestamptz AND bucket_start < %s::timestamptz
                    GROUP BY device_id
                ),
                stats_7 AS (
                    SELECT device_id, AVG(total_flows) AS mean_7d
                    FROM (
                        SELECT device_id, SUM(flow_count) AS total_flows
                        FROM aggregation_5m
                        WHERE bucket_start >= %s::timestamptz AND bucket_start < %s::timestamptz
                        GROUP BY device_id, date_trunc('day', bucket_start)
                    ) t
                    GROUP BY device_id
                ),
                stats_30 AS (
                    SELECT device_id, AVG(total_flows) AS mean_30d, STDDEV(total_flows) AS stddev_30d
                    FROM (
                        SELECT device_id, SUM(flow_count) AS total_flows
                        FROM aggregation_5m
                        WHERE bucket_start >= %s::timestamptz AND bucket_start < %s::timestamptz
                        GROUP BY device_id, date_trunc('day', bucket_start)
                    ) t
                    GROUP BY device_id
                )
                INSERT INTO daily_baselines (
                    baseline_date, device_id, metric_name, metric_value, mean_7d, mean_30d, stddev_30d, is_anomalous
                )
                SELECT
                    %s::date,
                    dt.device_id,
                    'flow_count',
                    dt.total_flows,
                    s7.mean_7d,
                    s30.mean_30d,
                    s30.stddev_30d,
                    (dt.total_flows > COALESCE(s30.mean_30d, 0) + 3 * COALESCE(s30.stddev_30d, 0))
                FROM daily_totals dt
                LEFT JOIN stats_7 s7 ON s7.device_id = dt.device_id
                LEFT JOIN stats_30 s30 ON s30.device_id = dt.device_id
                ON CONFLICT (baseline_date, device_id, metric_name) DO UPDATE SET
                    metric_value = EXCLUDED.metric_value,
                    mean_7d = EXCLUDED.mean_7d,
                    mean_30d = EXCLUDED.mean_30d,
                    stddev_30d = EXCLUDED.stddev_30d,
                    is_anomalous = EXCLUDED.is_anomalous
                """,
                (
                    yesterday,
                    yesterday + timedelta(days=1),
                    yesterday - timedelta(days=7),
                    yesterday,
                    yesterday - timedelta(days=30),
                    yesterday,
                    yesterday,
                ),
            )
    logger.info("Daily baselines done for %s", yesterday)
