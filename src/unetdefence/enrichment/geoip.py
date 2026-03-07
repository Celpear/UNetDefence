"""GeoIP lookup (MaxMind)."""

from dataclasses import dataclass
from pathlib import Path

from unetdefence.config import get_settings


@dataclass
class GeoIPResult:
    """Result of a GeoIP lookup."""

    country_code: str | None
    country_name: str | None
    region: str | None
    city: str | None


_reader = None


def _get_reader():
    global _reader
    if _reader is not None:
        return _reader
    settings = get_settings()
    if not settings.geoip.enabled or not settings.geoip.db_path:
        return None
    path = Path(settings.geoip.db_path)
    if not path.exists():
        return None
    try:
        import maxminddb
        _reader = maxminddb.open_database(str(path))
        return _reader
    except Exception:
        return None


def lookup(ip: str) -> GeoIPResult | None:
    """Look up GeoIP data for an IP. Returns None if disabled or not found."""
    r = _get_reader()
    if r is None:
        return None
    try:
        rec = r.get(ip)
    except Exception:
        return None
    if not rec:
        return None
    return GeoIPResult(
        country_code=rec.get("country", {}).get("iso_code"),
        country_name=rec.get("country", {}).get("names", {}).get("en"),
        region=rec.get("subdivisions", [{}])[0].get("names", {}).get("en") if rec.get("subdivisions") else None,
        city=rec.get("city", {}).get("names", {}).get("en"),
    )


def close() -> None:
    global _reader
    if _reader is not None:
        try:
            _reader.close()
        except Exception:
            pass
        _reader = None
