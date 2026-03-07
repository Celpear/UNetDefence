-- UNetDefence initial schema: PostgreSQL + pgvector
-- Run with: python -m unetdefence.storage.migrate

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";

-- 1. devices: internal device master data
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mac_address TEXT,
    current_ip INET,
    hostname TEXT,
    friendly_name TEXT,
    vendor TEXT,
    device_type TEXT,
    trust_level TEXT DEFAULT 'unknown',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(mac_address)
);

CREATE INDEX IF NOT EXISTS idx_devices_current_ip ON devices(current_ip);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);

-- 2. device_ip_history: IP assignment history
CREATE TABLE IF NOT EXISTS device_ip_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_ip_history_device ON device_ip_history(device_id);
CREATE INDEX IF NOT EXISTS idx_device_ip_history_valid ON device_ip_history(valid_from, valid_to);

-- 3. ip_enrichment: external IP context (GeoIP, ASN, RDNS)
CREATE TABLE IF NOT EXISTS ip_enrichment (
    ip INET PRIMARY KEY,
    country_code CHAR(2),
    country_name TEXT,
    region TEXT,
    city TEXT,
    asn BIGINT,
    asn_org TEXT,
    rdns TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. flows: normalised network flows
CREATE TABLE IF NOT EXISTS flows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ts TIMESTAMPTZ NOT NULL,
    src_ip INET NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip INET NOT NULL,
    dst_port INTEGER NOT NULL,
    proto TEXT,
    transport TEXT,
    service TEXT,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    dst_country_code CHAR(2),
    dst_asn BIGINT,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    packets_in INTEGER DEFAULT 0,
    packets_out INTEGER DEFAULT 0,
    duration_ms DOUBLE PRECISION,
    dns_query TEXT,
    http_host TEXT,
    tls_sni TEXT,
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_device ON flows(device_id);
CREATE INDEX IF NOT EXISTS idx_flows_dst_country ON flows(dst_country_code);
CREATE INDEX IF NOT EXISTS idx_flows_src_dst ON flows(src_ip, dst_ip, ts);

-- 5. dns_events
CREATE TABLE IF NOT EXISTS dns_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ts TIMESTAMPTZ NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    src_ip INET NOT NULL,
    query TEXT NOT NULL,
    qtype TEXT,
    answer_count INTEGER DEFAULT 0,
    rcode INTEGER DEFAULT 0,
    resolved_ips INET[],
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dns_events_ts ON dns_events(ts);
CREATE INDEX IF NOT EXISTS idx_dns_events_device ON dns_events(device_id);
CREATE INDEX IF NOT EXISTS idx_dns_events_query ON dns_events(query);

-- 6. http_events
CREATE TABLE IF NOT EXISTS http_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ts TIMESTAMPTZ NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    host TEXT NOT NULL,
    uri TEXT,
    method TEXT,
    status_code INTEGER,
    user_agent TEXT,
    dst_ip INET,
    dst_country_code CHAR(2),
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_http_events_ts ON http_events(ts);
CREATE INDEX IF NOT EXISTS idx_http_events_device ON http_events(device_id);
CREATE INDEX IF NOT EXISTS idx_http_events_host ON http_events(host);

-- 7. tls_events
CREATE TABLE IF NOT EXISTS tls_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ts TIMESTAMPTZ NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    dst_ip INET NOT NULL,
    sni TEXT,
    ja3 TEXT,
    issuer TEXT,
    subject TEXT,
    validation_status TEXT,
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tls_events_ts ON tls_events(ts);
CREATE INDEX IF NOT EXISTS idx_tls_events_device ON tls_events(device_id);
CREATE INDEX IF NOT EXISTS idx_tls_events_sni ON tls_events(sni);

-- 8. alerts: normalised security alerts
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ts TIMESTAMPTZ NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    signature TEXT NOT NULL,
    category TEXT,
    severity TEXT NOT NULL,
    engine TEXT,
    status TEXT,
    explanation TEXT,
    source TEXT NOT NULL,
    sensor TEXT,
    raw_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

-- 9. router_events: FRITZ!Box / router context
CREATE TABLE IF NOT EXISTS router_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ts TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    message TEXT,
    severity TEXT,
    raw_payload JSONB,
    source TEXT NOT NULL DEFAULT 'fritz',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_router_events_ts ON router_events(ts);
CREATE INDEX IF NOT EXISTS idx_router_events_type ON router_events(event_type);

-- 10. aggregation_5m: 5-minute aggregations
CREATE TABLE IF NOT EXISTS aggregation_5m (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    bucket_start TIMESTAMPTZ NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    country_code CHAR(2),
    asn BIGINT,
    flow_count INTEGER DEFAULT 0,
    distinct_dst_ips INTEGER DEFAULT 0,
    distinct_domains INTEGER DEFAULT 0,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    dns_count INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    new_destination_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(bucket_start, device_id, country_code, asn)
);

CREATE INDEX IF NOT EXISTS idx_aggregation_5m_bucket ON aggregation_5m(bucket_start);
CREATE INDEX IF NOT EXISTS idx_aggregation_5m_device ON aggregation_5m(device_id);

-- 11. daily_baselines
CREATE TABLE IF NOT EXISTS daily_baselines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    baseline_date DATE NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    metric_name TEXT NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    mean_7d DOUBLE PRECISION,
    mean_30d DOUBLE PRECISION,
    stddev_30d DOUBLE PRECISION,
    is_anomalous BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(baseline_date, device_id, metric_name)
);

CREATE INDEX IF NOT EXISTS idx_daily_baselines_date ON daily_baselines(baseline_date);
CREATE INDEX IF NOT EXISTS idx_daily_baselines_device ON daily_baselines(device_id);
CREATE INDEX IF NOT EXISTS idx_daily_baselines_anomalous ON daily_baselines(is_anomalous) WHERE is_anomalous;

-- 12. summaries: LLM/analyst summaries with optional embedding
CREATE TABLE IF NOT EXISTS summaries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ts TIMESTAMPTZ NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id UUID,
    summary_text TEXT NOT NULL,
    summary_kind TEXT NOT NULL,
    risk_score DOUBLE PRECISION,
    embedding vector(384),
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_summaries_ts ON summaries(ts);
CREATE INDEX IF NOT EXISTS idx_summaries_scope ON summaries(scope_type, scope_id);
-- pgvector similarity search (cosine by default)
CREATE INDEX IF NOT EXISTS idx_summaries_embedding ON summaries USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- 13. profiles: behaviour profiles per device/entity
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type TEXT NOT NULL,
    entity_id UUID NOT NULL,
    profile_text TEXT NOT NULL,
    embedding vector(384),
    metadata JSONB,
    valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_profiles_entity ON profiles(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_profiles_valid ON profiles(valid_from, valid_to);
CREATE INDEX IF NOT EXISTS idx_profiles_embedding ON profiles USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- 14. cases: optional incident/case table
CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT,
    summary TEXT,
    owner TEXT,
    metadata JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_opened ON cases(opened_at);
