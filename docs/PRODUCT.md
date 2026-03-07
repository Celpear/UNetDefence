# Product: Local Network Security Analysis

## Purpose

A locally deployable system that monitors network traffic (home or small business), structures it, enriches it with context, stores it in a relational database, runs periodic analysis, and makes it queryable in natural language via a configurable LLM.

Goals:

- Make network traffic transparent
- Detect anomalies and security events
- Compare device behaviour over time
- Answer questions like “Which devices communicate with China?” or “Why is this behaviour suspicious?”
- Unify router and IDS context in one analysis layer

The system is **local-first**. Data remains in your network by default. Database, embedding model, and LLM are configurable and swappable.

---

## Data Flow

```
Port Mirror / TAP
  → Zeek + Suricata
  → Ingest Worker
  → Enrichment (GeoIP, ASN, DNS/SNI, Device Mapping, FRITZ!Box)
  → PostgreSQL (relational events + pgvector for summaries/profiles/alerts)
  → Scheduler (5-min aggregations, daily baselines)
  → LLM Analyst (answers questions, explains anomalies)
```

---

## Scope

### Core Modules

1. **Sensor Layer** – Zeek (structured logs), Suricata (eve.json, alerts), optional PCAP retention
2. **Ingest Layer** – Zeek/Suricata/FRITZ!Box parsers, normalisation into internal event schema
3. **Enrichment Layer** – GeoIP, ASN, DNS/SNI/HTTP host, device mapping, FRITZ!Box context
4. **Storage Layer** – PostgreSQL as primary store; pgvector only for summaries, profiles, alerts
5. **Analysis Layer** – 5-min aggregations, daily baselines, deviation/trend detection
6. **LLM Analyst Layer** – Configurable LLM and embedding provider; semantic search; natural-language Q&A and explanations
7. **API / UI Layer** – REST (or GraphQL) API; web UI with dashboard, search, drill-down, alerts, devices, analyst chat

---

## Functional Requirements

### Primary Use Cases

The system must at least support:

- Which devices communicate with which countries?
- Traffic volume per device and destination country
- Which devices communicate to China, Russia, or other defined countries?
- Which devices show new or unusual behaviour?
- Which new external destinations were contacted in the last 24 hours?
- Which devices generate unusually many DNS requests?
- Which Suricata alerts are critical and which devices are involved?
- Is a given behaviour unusual compared to last week or last month?
- Which devices were active at the time of a router event?
- Which internal devices talk to the same ASN, domain, or SNI as a suspicious host?
- Explain why an event is suspicious.

### Secondary Use Cases

- New device detection
- Visibility of IoT cloud communication
- Correlating router logs with network events
- Free-text search over security-relevant events
- Find similar incidents via vector search

---

## Architecture Principles

1. **Local-first** – All components deployable locally; external services optional.
2. **Swappability** – Database, embedding model, and LLM configurable and replaceable.
3. **Event-normalised** – Zeek, Suricata, and router logs mapped to a common internal event schema.
4. **Relational-first** – Queries by country, device, time, port, ASN, volume primarily via SQL.
5. **Vector search where it fits** – Embeddings only for summaries, profiles, aggregated behaviour, alerts, incident summaries; not for raw packets or every flow.
6. **Explainability** – Results should be interpretable with clear context.

---

## Data Model (Summary)

- **devices** – Internal device master data (MAC, IP, hostname, friendly name, trust level, etc.)
- **device_ip_history** – IP assignment history per device
- **ip_enrichment** – External IP context (country, ASN, RDNS, etc.)
- **flows** – Normalised network flows (with device_id, dst_country_code, dst_asn, bytes, DNS/HTTP/TLS context)
- **dns_events**, **http_events**, **tls_events** – Protocol-specific events
- **alerts** – Normalised security alerts (Suricata, etc.)
- **router_events** – FRITZ!Box / router context
- **aggregation_5m** – 5-minute aggregations per device/country/ASN
- **daily_baselines** – Daily baselines and anomaly flags
- **summaries** – LLM/analyst summaries with optional embedding
- **profiles** – Behaviour profiles (per device/entity) with optional embedding
- **cases** – Optional incident/case table

---

## Non-Functional Requirements

- **Security** – Encrypted storage of secrets; role-based access; audit log for admin actions
- **Performance** – Handle thousands of flows per minute; resilient ingest under backpressure; efficient aggregations
- **Deployment** – Containerised; Docker Compose for small setups; Kubernetes-ready for larger ones
- **Observability** – Health checks, metrics, structured logs

See repository for full schema, API, and UI requirements.
