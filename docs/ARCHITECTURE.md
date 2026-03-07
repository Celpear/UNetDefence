# Architecture

## Overview

UNetDefence is built as loosely coupled modules connected by a normalised event schema and clear APIs.

## Layers

### 1. Sensor Layer

- **Zeek**: Produces structured logs (conn, dns, http, ssl, optionally ssh, files, notice).
- **Suricata**: Produces alerts, flow events, DNS/HTTP/TLS metadata, anomaly events; single output format `eve.json`.
- **Data source**: Traffic from port mirror, TAP, or transparent bridge.

### 2. Ingest Worker

- Reads Zeek logs, Suricata eve.json, and router/FRITZ!Box events.
- Parses, validates, normalises into internal schema.
- Deduplication, persistence to Postgres, forwarding to enrichment/summary pipeline.
- Implemented as a containerised service (Python); idempotent, retry-capable, horizontally scalable.

### 3. Enrichment Layer

- **GeoIP**: Country, region, optional city.
- **ASN**: AS number, AS name, provider.
- **DNS/SNI/HTTP**: Query, HTTP host, TLS SNI, optional reverse DNS.
- **Device mapping**: Internal IP/MAC → device (hostname, friendly name, type, trust).
- **FRITZ!Box**: New devices, connection events, port forwards, admin events, WAN changes.

Enrichment is cacheable; external IPs are not resolved on every event. Device–IP mapping is historised.

### 4. Storage Layer

- **Primary**: PostgreSQL.
- **Extension**: pgvector for semantic search on summaries, profiles, alerts.
- Relational tables for raw events, flows, alerts, devices, enrichments, aggregations.

### 5. Analysis Layer

- **Every 5 minutes**: Aggregations per device, country, ASN; new destinations/domains/SNIs; alert counts; optional summaries and embeddings.
- **Daily**: Baseline computation, profile updates, trend analysis, top countries/ASNs, new behaviour patterns, risk scores.
- **Optional (hourly)**: Alert correlation, similar-incident search, incident candidates.

### 6. LLM Analyst Layer

- Configurable LLM and embedding provider.
- Semantic search over summaries, profiles, alerts.
- Natural-language questions and explanations; orchestration of DB queries and vector search; answers with references to internal data.

### 7. API / UI Layer

- REST API (or GraphQL): events, devices, analytics, search, LLM analyst, admin.
- Web UI: dashboard, search, drill-down, alerts, device view, analyst chat, configuration.

## Key Interfaces

- **Event schema**: Normalised internal representation for flows, DNS, HTTP, TLS, alerts, router events.
- **Embedding adapter**: Configurable provider, model, batch, retry, timeout; local and remote backends.
- **LLM adapter**: `generate_answer`, `summarize_events`, `explain_alert`, `create_profile`, `compare_with_baseline`; configurable provider and system prompts.

## Deployment

- **Small**: Docker Compose (Postgres, ingest, API, scheduler, optional Zeek/Suricata).
- **Larger**: Kubernetes-ready services; scale ingest workers and API independently.
