# UNetDefence

**Local network security analysis** with IDS (Zeek, Suricata), enrichment, SQLite or PostgreSQL, optional pgvector, and a configurable LLM for natural-language analysis.

## Goals

- Monitor and analyse traffic from home or small business networks
- Structure, enrich, and store events in a relational database
- Detect anomalies and security events
- Answer questions like “Which devices communicate with China?” or “Why is this behaviour suspicious?”
- Combine router and IDS context in a single analysis layer

The system is **local-first**: data stays on your hardware by default. Database, embedding model, and LLM are configurable and swappable.

## Architecture Overview

```
Port Mirror / TAP
  → Zeek + Suricata
  → Ingest Worker
  → Enrichment (GeoIP, ASN, DNS/SNI, Device Mapping, FRITZ!Box)
  → SQLite (default) or PostgreSQL (+ pgvector for summaries/profiles/alerts)
  → Scheduler (5-min aggregations, daily baselines; Postgres only)
  → LLM Analyst (questions, explanations)
  → REST API
```

## Components

| Layer | Description |
|-------|-------------|
| **Sensor** | Zeek (conn, dns, http, ssl logs), Suricata (eve.json) |
| **Ingest** | Parsers, normalisation, idempotent write to DB |
| **Enrichment** | GeoIP, ASN, DNS/SNI/HTTP host, device mapping, FRITZ!Box context |
| **Storage** | SQLite (default) or PostgreSQL + pgvector for summaries/profiles/alerts |
| **Analysis** | 5-min aggregations, daily baselines (PostgreSQL); anomaly detection |
| **LLM Analyst** | Configurable LLM + embedding (e.g. Ollama), semantic search, Q&A |
| **API** | REST API: events, devices, analytics, LLM ask/explain-alert |

## Requirements

- Python 3.11+
- **Default:** no DB server – **SQLite** (`./unetdefence.db`) when `UNETDEFENCE_DATABASE_URL` is unset or `sqlite://...`
- **Production:** PostgreSQL 15+ with [pgvector](https://github.com/pgvector/pgvector) for full features (aggregations, baselines, vector search)
- Optional: [Ollama](https://ollama.com) for local LLM/embedding
- Optional: Zeek, Suricata (for live sensor data)
- Optional: MaxMind GeoLite2 (for GeoIP)

## Quick Start

**One-shot setup** (install Python package, **Zeek + Suricata** via Homebrew/apt, detect or set log paths in `.env`, run migrations, check/pull Ollama models):

```bash
./scripts/setup.sh
```

- **macOS:** installs Zeek and Suricata with `brew install zeek suricata` if not present; uses default log paths (`/opt/homebrew/var/log/zeek`, …).
- **Linux (Debian/Ubuntu):** adds the [Zeek APT repo](https://docs.zeek.org/install/ubuntu) for your Ubuntu version, then `apt-get install zeek suricata`; default log paths `/var/log/zeek`, `/var/log/suricata/eve.json`.
- **Linux (Fedora/RHEL):** `dnf install zeek suricata` (if packages exist); same default log paths.
- Options: `--no-install` (skip venv/pip), `--skip-ids` (do not install Zeek/Suricata), `--zeek-dir DIR`, `--suricata-path PATH`. At the end the script runs `unetdefence-ensure-ollama`; if Ollama is not running, run it later.

**Manual setup:**

```bash
# Virtualenv and install
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .

# Optional: PostgreSQL (default is SQLite)
# export UNETDEFENCE_DATABASE_URL=postgresql://user:pass@localhost/unetdefence

# Create DB schema (SQLite file or Postgres migrations)
python -m unetdefence.storage.migrate

# Optional: if using Ollama – ensure configured models are pulled (API only)
unetdefence-ensure-ollama

# Ingest: set in .env (or use setup.sh to auto-detect)
# UNETDEFENCE_INGEST_ZEEK_LOG_DIR=/var/log/zeek
# UNETDEFENCE_INGEST_SURICATA_EVE_PATH=/var/log/suricata/eve.json

# Start API (http://0.0.0.0:8000)
unetdefence-api

# Optional: ingest from Zeek/Suricata logs
# unetdefence-ingest

# Optional: scheduler (aggregations, baselines; requires Postgres)
# unetdefence-scheduler
```

## Commands

| Command | Description |
|---------|-------------|
| `./scripts/setup.sh` | Install (Python, Zeek, Suricata), detect paths, update `.env`, migrations, Ollama check. Options: `--no-install`, `--skip-ids` |
| `unetdefence-api` | Start REST API (default port 8000) |
| `unetdefence-ingest` | Ingest worker: read Zeek/Suricata logs, persist to DB |
| `unetdefence-scheduler` | Run 5-min aggregations and daily baselines (Postgres) |
| `unetdefence-ensure-ollama` | Check/pull Ollama models from config (HTTP API only) |

Migrations: `python -m unetdefence.storage.migrate`

## Starting the application

Follow these steps in order. Use **four terminals** if you run everything (Zeek, API, Ingest, optional Ollama); or fewer if you skip Zeek/Suricata or Ollama.

---

### Step 1: One-time setup

From the project directory:

```bash
cd /path/to/UNetDefence    # replace with your actual path
./scripts/setup.sh
```

Then edit **`.env`** in the project root. At least set:

- `UNETDEFENCE_LLM_MODEL=smollm2` (or your Ollama model) if you use the LLM.
- **Ingest paths:** Setup already sets `UNETDEFENCE_INGEST_ZEEK_LOG_DIR` and `UNETDEFENCE_INGEST_SURICATA_EVE_PATH` to the project **`logs/zeek`** and **`logs/suricata`** dirs (created by setup, ignored by git). Only change them if you use system log paths instead.

---

### Step 2: Zeek & Suricata (optional – for network data)

**Setup** creates **`logs/zeek`** and **`logs/suricata`** in the project and writes their paths into **`.env`**. These folders are in **`.gitignore`**, so logs stay out of the repo. The ingest worker reads from the paths in `.env`.

No need to edit `.env` for log paths if you use the project log dirs (setup sets them):

- `UNETDEFENCE_INGEST_ZEEK_LOG_DIR=<project>/logs/zeek`
- `UNETDEFENCE_INGEST_SURICATA_EVE_PATH=<project>/logs/suricata/eve.json`

**Start Zeek** (dedicated terminal). Zeek writes to the **current directory**, so run it from **`logs/zeek`**:

```bash
cd /path/to/UNetDefence/logs/zeek
# One-time on macOS: allow packet capture (or use: sudo zeek -i en0)
sudo chgrp admin /dev/bpf* && sudo chmod g+r /dev/bpf*
zeek -i en0
```

Replace `en0` with your interface (`ifconfig` or `networksetup -listallhardwareports`). Logs (`conn.log`, `dns.log`, …) appear in `logs/zeek`.

**Suricata** (optional): write logs into the project with **`-l logs/suricata`**:

```bash
cd /path/to/UNetDefence
suricata -c /opt/homebrew/etc/suricata/suricata.yaml -i en0 -l logs/suricata
# If config path fails: find $(brew --prefix) -name 'suricata.yaml' 2>/dev/null
```

**Linux:** use `sudo systemctl start zeek` and `sudo systemctl start suricata`; then set `.env` to `/var/log/zeek` and `/var/log/suricata/eve.json` (or run Zeek/Suricata so they write into `logs/zeek` and `logs/suricata` and keep the .env from setup).

---

### Step 3: Start API and Ingest

**Terminal A – API**

```bash
cd /path/to/UNetDefence
source .venv/bin/activate
unetdefence-api
```

**Terminal B – Ingest** (reads Zeek/Suricata logs and fills the DB)

```bash
cd /path/to/UNetDefence
source .venv/bin/activate
unetdefence-ingest
```

---

### Step 4: Optional – Ollama (for LLM questions)

If you use the LLM, in another terminal:

```bash
ollama serve
ollama run smollm2
```

---

### Step 5: Check

- **API docs:** open **http://localhost:8000/docs**
- **Health:** `curl http://localhost:8000/health`
- **Stats (ingest + DB):** `curl http://localhost:8000/health/stats`

---

### Overview

| You want…              | Do this |
|------------------------|--------|
| API only               | Step 1 → Step 3 Terminal A |
| API + network analysis | Step 1 → Step 2 (Zeek + .env) → Step 3 (API + Ingest) |
| Full (API + data + LLM)| All steps; keep Zeek, API, Ingest (and optionally Ollama) running |

## Running on a server

Use this to run the API (and optionally ingest/scheduler) on a dedicated machine so it keeps running.

1. **Clone and setup**
   ```bash
   git clone https://github.com/Celpear/UNetDefence.git
   cd UNetDefence
   ./scripts/setup.sh
   ```
   On a server without Zeek/Suricata (e.g. API-only): `./scripts/setup.sh --skip-ids`.

2. **Configure**
   - Copy or create `.env` in the repo root (do not commit it). Set at least:
     - `UNETDEFENCE_DATABASE_URL` (e.g. `postgresql://user:pass@localhost/unetdefence` for production)
     - `UNETDEFENCE_LLM_MODEL` and `UNETDEFENCE_LLM_BASE_URL` if using Ollama
     - `UNETDEFENCE_INGEST_ZEEK_LOG_DIR` / `UNETDEFENCE_INGEST_SURICATA_EVE_PATH` if this host runs ingest
   - Run migrations if not done by setup: `python -m unetdefence.storage.migrate`

3. **Start services** (choose one of the following)

   **Option A – systemd (recommended)**  
   Create unit files (e.g. in `/etc/systemd/system/`):

   - `unetdefence-api.service`:
     ```ini
     [Unit]
     Description=UNetDefence API
     After=network.target

     [Service]
     Type=simple
     User=unetdefence
     WorkingDirectory=/opt/UNetDefence
     EnvironmentFile=/opt/UNetDefence/.env
     ExecStart=/opt/UNetDefence/.venv/bin/unetdefence-api
     Restart=on-failure

     [Install]
     WantedBy=multi-user.target
     ```
   - For the ingest worker: same pattern with `ExecStart=.../unetdefence-ingest`.  
   Then: `sudo systemctl daemon-reload`, `sudo systemctl enable --now unetdefence-api` (and `unetdefence-ingest` if used).

   **Option B – background processes**
   ```bash
   cd /path/to/UNetDefence
   source .venv/bin/activate
   nohup unetdefence-api &
   nohup unetdefence-ingest &   # optional
   ```

4. **Check**
   - API: `curl http://localhost:8000/health` and `curl http://localhost:8000/health/stats`
   - To expose the API, put a reverse proxy (e.g. nginx) in front and bind the app to `0.0.0.0` (default) or set `HOST=0.0.0.0` if your CLI supports it.

## Configuration

- **Database**: `UNETDEFENCE_DATABASE_URL` (default `sqlite:///./unetdefence.db`; use Postgres URL for production). For SQLite, use an absolute path so API and ingest share the same file: `sqlite:////absolute/path/unetdefence.db`.
- **LLM**: `UNETDEFENCE_LLM_PROVIDER` (e.g. `ollama`), `UNETDEFENCE_LLM_MODEL`, `UNETDEFENCE_LLM_BASE_URL` (default `http://localhost:11434`). If the API runs **in Docker** but Ollama is on the host, set `UNETDEFENCE_LLM_BASE_URL=http://host.docker.internal:11434`.
- **Embedding**: `UNETDEFENCE_EMBEDDING_PROVIDER` (e.g. `ollama`), `UNETDEFENCE_EMBEDDING_MODEL`, `UNETDEFENCE_EMBEDDING_BASE_URL`
- **GeoIP**: `UNETDEFENCE_GEOIP_DB_PATH` (MaxMind DB path)
- **FRITZ!Box**: `UNETDEFENCE_FRITZ_ENABLED`, `UNETDEFENCE_FRITZ_BASE_URL`, etc.
- **Ingest**: `UNETDEFENCE_INGEST_ZEEK_LOG_DIR`, `UNETDEFENCE_INGEST_SURICATA_EVE_PATH`

See `config/README.md` and `docs/ARCHITECTURE.md` for details.

## API

- `GET /health`, `GET /health/ready` – liveness, DB readiness
- `GET /health/stats` – ingest configured (Zeek/Suricata paths), DB row counts (flows, alerts, devices); use this to see if network analysis is feeding data
- `GET /api/events/flows`, `GET /api/events/alerts`, `GET /api/events/router`
- `GET /api/devices`, `GET /api/devices/{id}`, `GET /api/devices/{id}/alerts`
- `GET /api/analytics/top-countries`, `GET /api/analytics/devices-by-country`, `GET /api/analytics/anomalies`
- `GET /api/analytics/tls-sni`, `GET /api/analytics/domains`, `GET /api/analytics/dst-ips`
- `GET /api/db/overview` – row counts per table and `database_path` (which SQLite file is used); `GET /api/db/entries?table=flows&limit=50` – browse table rows
- `POST /api/llm/ask`, `POST /api/llm/explain-alert`

`POST /api/llm/ask` request body (simplified):

```json
{
  "question": "Welche Daten hast du?",
  "since_hours": 2,
  "include_domains": true,
  "include_tls_sni": true,
  "include_dst_ips": false,
  "language": "German"
}
```

Response includes `answer`, `full_prompt` (full system+user prompt sent to the LLM) and `llm_model` (e.g. `smollm2`).

OpenAPI docs: `http://localhost:8000/docs` when the API is running.

## Testing endpoints

With the API running (`unetdefence-api`), run:

```bash
./scripts/test_endpoints.sh          # default: http://127.0.0.1:8000
./scripts/test_endpoints.sh http://localhost:8000
```

Health, events, devices, analytics and LLM (ask/explain) are checked. LLM returns 503 if Ollama is not running or the model is unavailable.

### Is network analysis running?

- Call **`GET /health/stats`**. It returns `ingest_configured` (whether Zeek/Suricata paths are set), and `flows_count`, `alerts_count`, `devices_count`.
- Data comes from the **ingest worker** (`unetdefence-ingest`). If you never run it, or don’t set `UNETDEFENCE_INGEST_ZEEK_LOG_DIR` / `UNETDEFENCE_INGEST_SURICATA_EVE_PATH`, the DB stays empty and the LLM will only see “No recent data” as context.
- After changing `.env` (e.g. `UNETDEFENCE_LLM_MODEL=smollm2`), **restart the API** so it picks up the new config.

### API and Ingest: same database?

API and ingest must use the **same SQLite file**, otherwise the API shows empty tables even though the ingest logs “Persisted N events”.

- **Check which file is used:**  
  - **API:** `GET /api/db/overview` returns `database_path` (absolute path to the SQLite file).  
  - **Ingest:** At startup it logs `Database: <path>`.  
  Both must show the **same path**.
- By default the SQLite path is resolved to the **project root** (`<repo>/unetdefence.db`), so starting both from the project directory is enough.
- To fix it explicitly, set in **`.env`** an absolute path (four slashes: `sqlite:///` + path):
  ```env
  UNETDEFENCE_DATABASE_URL=sqlite:////Users/you/Documents/github/UNetDefence/unetdefence.db
  ```
  Then restart **API and Ingest**.

## License

MIT
