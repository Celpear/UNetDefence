"""Run SQL migrations (sync). Detects SQLite vs PostgreSQL from config."""

import asyncio
import sys
from pathlib import Path

# Ensure we can import unetdefence
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from unetdefence.config import get_settings
from unetdefence.storage.connection import _is_sqlite


def run_migrations() -> None:
    """Apply migrations: SQLite or PostgreSQL depending on UNETDEFENCE_DATABASE_URL."""
    settings = get_settings()
    url = settings.database.url

    if _is_sqlite():
        _run_sqlite_migrations(url)
    else:
        _run_postgres_migrations(url)


def _run_sqlite_migrations(url: str) -> None:
    """Apply SQLite migration files."""
    try:
        import sqlite3
    except ImportError:
        print("SQLite is built-in; this should not happen.", file=sys.stderr)
        sys.exit(1)

    path = url.replace("sqlite:///", "").strip() or "./unetdefence.db"
    migrations_dir = Path(__file__).parent / "migrations"
    sql_file = migrations_dir / "001_initial_sqlite.sql"
    if not sql_file.exists():
        print("SQLite migration not found.", file=sys.stderr)
        return

    print(f"Applying SQLite migration to {path}...")
    conn = sqlite3.connect(path)
    conn.executescript(sql_file.read_text())
    conn.commit()
    conn.close()
    print("Migrations completed.")


def _run_postgres_migrations(url: str) -> None:
    """Apply PostgreSQL migration files (exclude *_sqlite.sql)."""
    try:
        import psycopg
    except ImportError:
        print("Install psycopg: pip install psycopg[binary]", file=sys.stderr)
        sys.exit(1)

    migrations_dir = Path(__file__).parent / "migrations"
    sql_files = sorted(p for p in migrations_dir.glob("*.sql") if "sqlite" not in p.name)
    if not sql_files:
        print("No PostgreSQL migration files found.", file=sys.stderr)
        return

    with psycopg.connect(url) as conn:
        conn.autocommit = True
        for path in sql_files:
            sql = path.read_text()
            name = path.name
            print(f"Applying {name}...")
            try:
                conn.execute(sql)
            except Exception as e:
                print(f"Error applying {name}: {e}", file=sys.stderr)
                raise
    print("Migrations completed.")


if __name__ == "__main__":
    run_migrations()
