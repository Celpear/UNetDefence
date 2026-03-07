"""Enrichment service: coordinate GeoIP, ASN, device resolution with caching."""

import asyncio
from uuid import UUID

from unetdefence.enrichment.geoip import lookup as geoip_lookup

# Simple in-memory cache for external IP enrichment (avoid resolving every event)
_ip_enrichment_cache: dict[str, dict] = {}
_cache_max = 50_000


def _cache_get(ip: str) -> dict | None:
    return _ip_enrichment_cache.get(ip)


def _cache_set(ip: str, data: dict) -> None:
    if len(_ip_enrichment_cache) >= _cache_max:
        # Evict some (simple: drop first 10%)
        keys = list(_ip_enrichment_cache.keys())[: _cache_max // 10]
        for k in keys:
            _ip_enrichment_cache.pop(k, None)
    _ip_enrichment_cache[ip] = data


def enrich_ip(ip: str) -> dict:
    """Return enrichment dict for an IP (country_code, asn, etc.). Cached."""
    cached = _cache_get(ip)
    if cached is not None:
        return cached
    geo = geoip_lookup(ip)
    data = {
        "country_code": geo.country_code if geo else None,
        "country_name": geo.country_name if geo else None,
        "region": geo.region if geo else None,
        "city": geo.city if geo else None,
        "asn": None,
        "asn_org": None,
        "rdns": None,
    }
    # ASN: could add maxmind GeoLite2-ASN or separate DB; leave None for now
    _cache_set(ip, data)
    return data


async def enrich_flow_for_db(device_id: UUID | None, dst_ip: str) -> dict:
    """Return enrichment fields for a flow destination IP (async for future DB/HTTP lookups)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, enrich_ip, dst_ip)


class EnrichmentService:
    """Orchestrates enrichment and optional DB upsert for ip_enrichment table."""

    async def enrich_and_upsert_ip(self, ip: str) -> dict:
        """Enrich IP and optionally upsert into ip_enrichment table."""
        data = await asyncio.get_event_loop().run_in_executor(None, enrich_ip, ip)
        # Optional: write to ip_enrichment via repository
        return data
