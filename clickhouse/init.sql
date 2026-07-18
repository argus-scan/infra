CREATE DATABASE IF NOT EXISTS argus;

CREATE TABLE IF NOT EXISTS argus.port_history (
    scan_time   DateTime,
    tenant_id   UUID,
    asset_id    UUID,
    ip          String,
    port        UInt16,
    protocol    LowCardinality(String),
    service     String,
    state       LowCardinality(String),
    scan_job_id UUID
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(scan_time)
ORDER BY (tenant_id, ip, port, scan_time)
TTL scan_time + INTERVAL 2 YEAR;

CREATE TABLE IF NOT EXISTS argus.finding_history (
    scan_time       DateTime,
    tenant_id       UUID,
    asset_id        UUID,
    ip              String,
    cve_id          String,
    severity        LowCardinality(String),
    epss_score      Float32,
    is_kev          UInt8,
    ai_score        Float32,
    scan_job_id     UUID
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(scan_time)
ORDER BY (tenant_id, ip, cve_id, scan_time)
TTL scan_time + INTERVAL 2 YEAR;

CREATE TABLE IF NOT EXISTS argus.asset_history (
    scan_time       DateTime,
    tenant_id       UUID,
    org_id          UUID,
    ip              String,
    hostname        String,
    os              String,
    open_ports      UInt16,
    total_findings  UInt16,
    critical_count  UInt16,
    high_count      UInt16,
    scan_job_id     UUID
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(scan_time)
ORDER BY (tenant_id, org_id, ip, scan_time)
TTL scan_time + INTERVAL 2 YEAR;

CREATE MATERIALIZED VIEW IF NOT EXISTS argus.daily_finding_trend
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, org_id, day, severity)
AS SELECT
    toDate(scan_time)   AS day,
    tenant_id,
    org_id,
    severity,
    countIf(is_kev = 1) AS kev_count,
    count()             AS total_count
FROM argus.finding_history
GROUP BY day, tenant_id, org_id, severity;

CREATE MATERIALIZED VIEW IF NOT EXISTS argus.daily_port_trend
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, org_id, day, port)
AS SELECT
    toDate(scan_time)   AS day,
    tenant_id,
    org_id,
    port,
    count()             AS total_count
FROM argus.port_history
GROUP BY day, tenant_id, org_id, port;
