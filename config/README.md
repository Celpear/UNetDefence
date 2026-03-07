# Configuration

Settings are loaded from environment variables and optionally from a `.env` file in the project root.

**Lite defaults (except DB):** Out of the box the app uses sensible local/lite options: SQLite for DB (unchanged), Ollama with a small LLM (`llama3.2:1b`), embedding disabled, GeoIP disabled. Run `unetdefence-ensure-ollama` once to pull the LLM model if needed.

## Prefix

All variables use the prefix `UNETDEFENCE_`. Nested settings use `__` (e.g. `UNETDEFENCE_DATABASE__URL`).

## Main variables (defaults = lite)

| Variable | Description | Default |
|----------|-------------|---------|
| `UNETDEFENCE_DATABASE_URL` | Database URL (SQLite or PostgreSQL) | `sqlite:///./unetdefence.db` |
| `UNETDEFENCE_DATABASE_POOL_SIZE` | Connection pool size | `5` |
| `UNETDEFENCE_GEOIP_ENABLED` | Enable GeoIP lookups (requires DB path) | `false` |
| `UNETDEFENCE_GEOIP_DB_PATH` | Path to MaxMind GeoLite2 DB | (none) |
| `UNETDEFENCE_EMBEDDING_PROVIDER` | `openai`, `ollama`, `sentence-transformers`, `disabled` | `disabled` |
| `UNETDEFENCE_EMBEDDING_MODEL` | Embedding model (when provider=ollama) | `nomic-embed-text` |
| `UNETDEFENCE_EMBEDDING_BASE_URL` | Ollama base URL | `http://localhost:11434` |
| `UNETDEFENCE_LLM_PROVIDER` | `openai`, `ollama`, `anthropic`, `disabled` | `ollama` |
| `UNETDEFENCE_LLM_MODEL` | LLM model (lite: small, e.g. 1b) | `llama3.2:1b` |
| `UNETDEFENCE_LLM_BASE_URL` | Ollama base URL | `http://localhost:11434` |
| `UNETDEFENCE_FRITZ_ENABLED` | Enable FRITZ!Box context | `false` |
| `UNETDEFENCE_INGEST_ZEEK_LOG_DIR` | Zeek log directory | (none) |
| `UNETDEFENCE_INGEST_SURICATA_EVE_PATH` | Suricata eve.json path | (none) |

To disable the LLM and run without Ollama: `UNETDEFENCE_LLM_PROVIDER=disabled`.

## Example `.env` (override lite defaults)

```env
# Keep SQLite
# UNETDEFENCE_DATABASE_URL=sqlite:///./unetdefence.db

# Optional: GeoIP (download MaxMind GeoLite2, then set path)
# UNETDEFENCE_GEOIP_ENABLED=true
# UNETDEFENCE_GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb

# Optional: enable embedding for semantic search (Ollama)
# UNETDEFENCE_EMBEDDING_PROVIDER=ollama
# UNETDEFENCE_EMBEDDING_MODEL=nomic-embed-text

# LLM (default is already ollama + llama3.2:1b)
# UNETDEFENCE_LLM_MODEL=llama3.2:3b

# Ingest (Zeek/Suricata)
# UNETDEFENCE_INGEST_ZEEK_LOG_DIR=/opt/zeek/logs/current
# UNETDEFENCE_INGEST_SURICATA_EVE_PATH=/var/log/suricata/eve.json
```
