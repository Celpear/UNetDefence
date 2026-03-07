"""Ingest worker: tail Zeek/Suricata logs, parse, enrich, persist."""

import asyncio
import json
import logging
import sys
from pathlib import Path

from unetdefence.config import get_settings
from unetdefence.ingest.parsers import (
    parse_zeek_conn,
    parse_zeek_dns,
    parse_zeek_http,
    parse_zeek_ssl,
    parse_suricata_event,
)
from unetdefence.models import FlowEvent, DnsEvent, HttpEvent, TlsEvent, AlertEvent, RouterEvent
from unetdefence.storage import get_pool, init_pool, close_pool
from unetdefence.storage.repositories import (
    insert_flow,
    insert_dns,
    insert_http,
    insert_tls,
    insert_alert,
    insert_router_event,
    get_device_id_by_ip,
)

logger = logging.getLogger(__name__)


def _parse_zeek_tsv_line(line: str, fields: list[str] | None) -> dict | None:
    """Parse a Zeek TSV line; first line is #fields. Returns dict or None."""
    if line.startswith("#"):
        return None
    if fields is None:
        return None
    parts = line.split("\t")
    if len(parts) != len(fields):
        return None
    return dict(zip(fields, parts))


async def _read_zeek_log(
    log_path: Path,
    log_type: str,
    sensor: str | None,
    batch: list,
) -> None:
    """Read Zeek log file and append parsed events to batch."""
    parser = {
        "conn": parse_zeek_conn,
        "dns": parse_zeek_dns,
        "http": parse_zeek_http,
        "ssl": parse_zeek_ssl,
    }.get(log_type)
    if not parser:
        return
    fields: list[str] | None = None
    try:
        with open(log_path, "r") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                row = _parse_zeek_tsv_line(line, fields)
                if not row:
                    continue
                ev = parser(row, raw_ref=str(log_path), sensor=sensor)
                if ev:
                    batch.append(ev)
    except FileNotFoundError:
        logger.debug("Zeek log not found: %s", log_path)
    except Exception as e:
        logger.warning("Error reading Zeek log %s: %s", log_path, e)


async def _read_suricata_events(
    eve_path: Path,
    sensor: str | None,
    batch: list,
    limit: int = 5000,
) -> None:
    """Read Suricata eve.json (file or directory) and append to batch."""
    if eve_path.is_file():
        files = [eve_path]
    elif eve_path.is_dir():
        files = sorted(eve_path.glob("eve*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:1]
    else:
        return
    for fp in files:
        try:
            with open(fp, "r") as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ev = parse_suricata_event(event, raw_ref=str(fp), sensor=sensor)
                    if ev:
                        batch.append(ev)
        except FileNotFoundError:
            logger.debug("Suricata eve not found: %s", fp)
        except Exception as e:
            logger.warning("Error reading Suricata eve %s: %s", fp, e)
        break  # one file per poll


async def _persist_batch(batch: list) -> int:
    """Persist a batch of normalised events; returns count inserted."""
    if not batch:
        return 0
    pool = get_pool()
    count = 0
    async with pool.connection() as conn:
        for ev in batch:
            try:
                device_id = await get_device_id_by_ip(conn, ev.src_ip) if hasattr(ev, "src_ip") else None
                if isinstance(ev, FlowEvent):
                    await insert_flow(conn, ev, device_id)
                    count += 1
                elif isinstance(ev, DnsEvent):
                    await insert_dns(conn, ev, device_id)
                    count += 1
                elif isinstance(ev, HttpEvent):
                    await insert_http(conn, ev, device_id)
                    count += 1
                elif isinstance(ev, TlsEvent):
                    await insert_tls(conn, ev, device_id)
                    count += 1
                elif isinstance(ev, AlertEvent):
                    await insert_alert(conn, ev, device_id)
                    count += 1
                elif isinstance(ev, RouterEvent):
                    await insert_router_event(conn, ev, device_id)
                    count += 1
            except Exception as e:
                logger.warning("Insert failed for event: %s", e)
    return count


async def run_ingest_loop() -> None:
    """Main loop: poll log dirs, parse, persist."""
    settings = get_settings()
    ingest = settings.ingest
    zeek_dir = ingest.zeek_log_dir
    suricata_path = ingest.suricata_eve_path
    batch_size = ingest.batch_size
    poll_interval = ingest.poll_interval_seconds

    await init_pool()
    if not zeek_dir and not suricata_path:
        logger.warning(
            "No ingest sources configured. Set UNETDEFENCE_INGEST_ZEEK_LOG_DIR and/or "
            "UNETDEFENCE_INGEST_SURICATA_EVE_PATH in .env to read Zeek/Suricata logs. "
            "Worker will keep running and check every %ds.",
            poll_interval,
        )
    else:
        logger.info(
            "Ingest started: zeek_dir=%s suricata_path=%s (poll every %ds)",
            zeek_dir or "(none)",
            suricata_path or "(none)",
            poll_interval,
        )
    try:
        while True:
            batch: list = []
            if zeek_dir:
                p = Path(zeek_dir)
                if p.is_dir():
                    for log_type in ("conn", "dns", "http", "ssl"):
                        await _read_zeek_log(p / f"{log_type}.log", log_type, None, batch)
            if suricata_path:
                p = Path(suricata_path)
                if p.exists():
                    await _read_suricata_events(p, None, batch, limit=batch_size)
            if batch:
                n = await _persist_batch(batch[:batch_size])
                logger.info("Persisted %d events (batch size %d)", n, len(batch))
            await asyncio.sleep(poll_interval)
    finally:
        await close_pool()


def main() -> None:
    """CLI entrypoint."""
    logging.basicConfig(
        level=get_settings().log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    asyncio.run(run_ingest_loop())


if __name__ == "__main__":
    main()
