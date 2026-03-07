"""Database connection: PostgreSQL (pool) or SQLite (default, no server)."""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator

from unetdefence.config import get_settings

# Project root (connection.py -> storage -> unetdefence -> src -> project)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _is_sqlite() -> bool:
    url = get_settings().database.url
    return url.startswith("sqlite") or not url.strip()


def is_sqlite() -> bool:
    """Whether the configured database is SQLite (for repository adapters)."""
    return _is_sqlite()


# --- PostgreSQL ---
_pg_pool: Any = None


async def _init_pg() -> None:
    global _pg_pool
    from psycopg_pool import AsyncConnectionPool
    settings = get_settings()
    _pg_pool = AsyncConnectionPool(
        conninfo=settings.database.url,
        min_size=1,
        max_size=settings.database.pool_size,
        max_wait=30,
        open=True,
    )


async def _close_pg() -> None:
    global _pg_pool
    if _pg_pool:
        await _pg_pool.close()
        _pg_pool = None


# --- SQLite wrapper (mimics psycopg cursor/connection API for repositories) ---
def _sqlite_convert_params(sql: str) -> str:
    """Convert %s placeholders to ? for SQLite."""
    return sql.replace("%s", "?")


class _SqliteCursorWrapper:
    """Cursor-like wrapper for aiosqlite so repositories can use same code."""

    def __init__(self, conn: Any):
        self._conn = conn
        self._cursor: Any = None

    async def __aenter__(self) -> "_SqliteCursorWrapper":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    async def execute(self, sql: str, params: tuple = ()) -> None:
        sql = _sqlite_convert_params(sql)
        self._cursor = await self._conn.execute(sql, params)

    async def fetchone(self) -> dict | None:
        if self._cursor is None:
            return None
        row = await self._cursor.fetchone()
        if row is None:
            return None
        if hasattr(row, "keys"):
            return dict(row)
        names = [d[0] for d in self._cursor.description]
        return dict(zip(names, row))

    async def fetchall(self) -> list[dict]:
        if self._cursor is None:
            return []
        rows = await self._cursor.fetchall()
        names = [d[0] for d in self._cursor.description]
        return [dict(zip(names, r)) for r in rows]


class _SqliteConnectionWrapper:
    """Connection wrapper that provides cursor(row_factory=dict_row) compatible with repos."""

    def __init__(self, conn: Any):
        self._conn = conn

    def cursor(self, row_factory: Any = None) -> "_SqliteCursorWrapper":
        return _SqliteCursorWrapper(self._conn)

    async def commit(self) -> None:
        """Commit the current transaction (required for aiosqlite; no auto-commit)."""
        await self._conn.commit()

    async def __aenter__(self) -> "_SqliteConnectionWrapper":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


class _SqlitePool:
    """Fake pool for SQLite: yields a new connection each time."""

    def __init__(self, path: str):
        self._path = path

    @asynccontextmanager
    async def connection(self) -> AsyncGenerator[_SqliteConnectionWrapper, None]:
        import aiosqlite
        import sqlite3
        conn = await aiosqlite.connect(self._path)
        conn.row_factory = sqlite3.Row  # so we can dict(row) in wrapper
        try:
            yield _SqliteConnectionWrapper(conn)
        finally:
            await conn.close()

    async def close(self) -> None:
        pass


_sqlite_pool: _SqlitePool | None = None


async def _init_sqlite() -> None:
    global _sqlite_pool
    url = get_settings().database.url
    # sqlite:///./unetdefence.db -> ./unetdefence.db
    path = url.replace("sqlite:///", "").strip()
    if not path:
        path = "./unetdefence.db"
    # Use absolute path so API and ingest use the same file regardless of cwd
    if not Path(path).is_absolute():
        path = str((_PROJECT_ROOT / path).resolve())
    _sqlite_pool = _SqlitePool(path)


async def _close_sqlite() -> None:
    global _sqlite_pool
    if _sqlite_pool:
        await _sqlite_pool.close()
        _sqlite_pool = None


# --- Public API ---

async def init_pool() -> None:
    """Create connection pool (PostgreSQL) or SQLite handler from settings."""
    if _is_sqlite():
        await _init_sqlite()
    else:
        await _init_pg()


async def close_pool() -> None:
    """Close pool."""
    if _is_sqlite():
        await _close_sqlite()
    else:
        await _close_pg()


def get_pool() -> Any:
    """Return the global pool (PostgreSQL AsyncConnectionPool or SQLite _SqlitePool)."""
    if _is_sqlite():
        if _sqlite_pool is None:
            raise RuntimeError("Connection pool not initialized; call init_pool() first")
        return _sqlite_pool
    if _pg_pool is None:
        raise RuntimeError("Connection pool not initialized; call init_pool() first")
    return _pg_pool


def get_sqlite_path() -> str | None:
    """Return the absolute path of the SQLite DB file when using SQLite; else None."""
    if not _is_sqlite() or _sqlite_pool is None:
        return None
    return getattr(_sqlite_pool, "_path", None)


@asynccontextmanager
async def get_connection() -> AsyncGenerator:
    """Context manager for a single connection from the pool."""
    pool = get_pool()
    async with pool.connection() as conn:
        yield conn
