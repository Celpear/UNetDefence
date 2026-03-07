-- UNetDefence initial schema: SQLite (default when no Postgres URL)
-- Run with: python -m unetdefence.storage.migrate (auto-detects SQLite)

-- 1. devices
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    mac_address TEXT UNIQUE,
    current_ip TEXT,
    hostname TEXT,
    friendly_name TEXT,
    vendor TEXT,
    device_type TEXT,
    trust_level TEXT DEFAULT 'unknown',
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_devices_current_ip ON devices(current_ip);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);

-- 2. device_ip_history
CREATE TABLE IF NOT EXISTS device_ip_history (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    valid_from TEXT NOT NULL DEFAULT (datetime('now')),
    valid_to TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_device_ip_history_device ON device_ip_history(device_id);

-- 3. ip_enrichment
CREATE TABLE IF NOT EXISTS ip_enrichment (
    ip TEXT PRIMARY KEY,
    country_code TEXT,
    country_name TEXT,
    region TEXT,
    city TEXT,
    asn INTEGER,
    asn_org TEXT,
    rdns TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 4. flows
CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    proto TEXT,
    transport TEXT,
    service TEXT,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    dst_country_code TEXT,
    dst_asn INTEGER,
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    packets_in INTEGER DEFAULT 0,
    packets_out INTEGER DEFAULT 0,
    duration_ms REAL,
    dns_query TEXT,
    http_host TEXT,
    tls_sni TEXT,
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_device ON flows(device_id);
CREATE INDEX IF NOT EXISTS idx_flows_dst_country ON flows(dst_country_code);

-- 5. dns_events (resolved_ips as JSON text)
CREATE TABLE IF NOT EXISTS dns_events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    src_ip TEXT NOT NULL,
    query TEXT NOT NULL,
    qtype TEXT,
    answer_count INTEGER DEFAULT 0,
    rcode INTEGER DEFAULT 0,
    resolved_ips TEXT,
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_dns_events_ts ON dns_events(ts);
CREATE INDEX IF NOT EXISTS idx_dns_events_device ON dns_events(device_id);

-- 6. http_events
CREATE TABLE IF NOT EXISTS http_events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    host TEXT NOT NULL,
    uri TEXT,
    method TEXT,
    status_code INTEGER,
    user_agent TEXT,
    dst_ip TEXT,
    dst_country_code TEXT,
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_http_events_ts ON http_events(ts);
CREATE INDEX IF NOT EXISTS idx_http_events_device ON http_events(device_id);

-- 7. tls_events
CREATE TABLE IF NOT EXISTS tls_events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    dst_ip TEXT NOT NULL,
    sni TEXT,
    ja3 TEXT,
    issuer TEXT,
    subject TEXT,
    validation_status TEXT,
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tls_events_ts ON tls_events(ts);
CREATE INDEX IF NOT EXISTS idx_tls_events_device ON tls_events(device_id);

-- 8. alerts
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    signature TEXT NOT NULL,
    category TEXT,
    severity TEXT NOT NULL,
    engine TEXT,
    status TEXT,
    explanation TEXT,
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);

-- 9. router_events
CREATE TABLE IF NOT EXISTS router_events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    message TEXT,
    severity TEXT,
    raw_payload TEXT,
    source TEXT NOT NULL DEFAULT 'fritz',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_router_events_ts ON router_events(ts);

-- 10. aggregation_5m (unique on bucket_start, device_id, country_code, asn)
CREATE TABLE IF NOT EXISTS aggregation_5m (
    id TEXT PRIMARY KEY,
    bucket_start TEXT NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    country_code TEXT,
    asn INTEGER,
    flow_count INTEGER DEFAULT 0,
    distinct_dst_ips INTEGER DEFAULT 0,
    distinct_domains INTEGER DEFAULT 0,
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    dns_count INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    new_destination_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(bucket_start, device_id, country_code, asn)
);
CREATE INDEX IF NOT EXISTS idx_aggregation_5m_bucket ON aggregation_5m(bucket_start);

-- 11. daily_baselines
CREATE TABLE IF NOT EXISTS daily_baselines (
    id TEXT PRIMARY KEY,
    baseline_date TEXT NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    mean_7d REAL,
    mean_30d REAL,
    stddev_30d REAL,
    is_anomalous INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(baseline_date, device_id, metric_name)
);
CREATE INDEX IF NOT EXISTS idx_daily_baselines_date ON daily_baselines(baseline_date);

-- 12. summaries (no vector column in SQLite)
CREATE TABLE IF NOT EXISTS summaries (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT,
    summary_text TEXT NOT NULL,
    summary_kind TEXT NOT NULL,
    risk_score REAL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_summaries_ts ON summaries(ts);

-- 13. profiles (no vector column in SQLite)
CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    profile_text TEXT NOT NULL,
    metadata TEXT,
    valid_from TEXT NOT NULL DEFAULT (datetime('now')),
    valid_to TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_profiles_entity ON profiles(entity_type, entity_id);

-- 14. cases
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    opened_at TEXT NOT NULL DEFAULT (datetime('now')),
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT,
    summary TEXT,
    owner TEXT,
    metadata TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
