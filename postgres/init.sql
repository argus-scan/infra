CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE plan_type AS ENUM ('free', 'pro', 'business', 'enterprise');
CREATE TYPE user_role AS ENUM ('owner', 'admin', 'analyst', 'viewer');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE scan_type AS ENUM ('full', 'discovery', 'ports', 'vulns', 'recon');
CREATE TYPE finding_status AS ENUM ('open', 'confirmed', 'mitigated', 'accepted', 'false_positive');
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE asset_type AS ENUM ('ip', 'domain', 'cidr');
CREATE TYPE port_state AS ENUM ('open', 'closed', 'filtered');
CREATE TYPE registry_type AS ENUM ('ARIN', 'RIPE', 'APNIC', 'LACNIC', 'AFRINIC');

CREATE TABLE tenants (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    plan        plan_type NOT NULL DEFAULT 'free',
    api_key     TEXT NOT NULL DEFAULT encode(gen_random_bytes(32), 'hex'),
    max_orgs    INT NOT NULL DEFAULT 1,
    max_scans   INT NOT NULL DEFAULT 10,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            user_role NOT NULL DEFAULT 'viewer',
    mfa_secret      TEXT,
    mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    description TEXT,
    domains     TEXT[],
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, slug)
);

CREATE TABLE asns (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asn         INT NOT NULL,
    name        TEXT,
    registry    registry_type,
    country     CHAR(2),
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, asn)
);

CREATE TABLE ip_ranges (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asn_id      UUID NOT NULL REFERENCES asns(id) ON DELETE CASCADE,
    cidr        CIDR NOT NULL,
    total_ips   INT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asn_id, cidr)
);

CREATE TABLE assets (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip          INET NOT NULL,
    hostname    TEXT,
    reverse_dns TEXT,
    os          TEXT,
    os_version  TEXT,
    asset_type  asset_type NOT NULL DEFAULT 'ip',
    tags        TEXT[],
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, ip)
);

CREATE TABLE ports (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port        INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    service     TEXT,
    product     TEXT,
    version     TEXT,
    banner      TEXT,
    state       port_state NOT NULL DEFAULT 'open',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, port, protocol)
);

CREATE TABLE cves (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id          TEXT NOT NULL UNIQUE,
    description     TEXT,
    cvss_score      NUMERIC(4,1),
    cvss_vector     TEXT,
    cvss_version    TEXT,
    severity        severity_level,
    epss_score      NUMERIC(7,6),
    epss_percentile NUMERIC(7,6),
    is_kev          BOOLEAN NOT NULL DEFAULT FALSE,
    kev_date_added  DATE,
    cwe             TEXT[],
    references      JSONB,
    published_at    TIMESTAMPTZ,
    modified_at     TIMESTAMPTZ,
    enriched_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    status          scan_status NOT NULL DEFAULT 'pending',
    type            scan_type NOT NULL DEFAULT 'full',
    config          JSONB NOT NULL DEFAULT '{}',
    progress        INT NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    assets_found    INT NOT NULL DEFAULT 0,
    ports_found     INT NOT NULL DEFAULT 0,
    findings_found  INT NOT NULL DEFAULT 0,
    error_msg       TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port_id         UUID REFERENCES ports(id) ON DELETE SET NULL,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    cve_id          UUID REFERENCES cves(id) ON DELETE SET NULL,
    template_id     TEXT,
    name            TEXT NOT NULL,
    severity        severity_level NOT NULL,
    status          finding_status NOT NULL DEFAULT 'open',
    matcher_name    TEXT,
    extracted_data  JSONB,
    ai_verdict      TEXT,
    ai_score        NUMERIC(4,2),
    ai_remediation  TEXT,
    ai_triaged_at   TIMESTAMPTZ,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_organizations_tenant ON organizations(tenant_id);
CREATE INDEX idx_asns_org ON asns(org_id);
CREATE INDEX idx_ip_ranges_asn ON ip_ranges(asn_id);
CREATE INDEX idx_assets_tenant ON assets(tenant_id);
CREATE INDEX idx_assets_org ON assets(org_id);
CREATE INDEX idx_assets_ip ON assets(ip);
CREATE INDEX idx_ports_asset ON ports(asset_id);
CREATE INDEX idx_ports_port ON ports(port);
CREATE INDEX idx_findings_tenant ON findings(tenant_id);
CREATE INDEX idx_findings_asset ON findings(asset_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_cve ON findings(cve_id);
CREATE INDEX idx_scan_jobs_tenant ON scan_jobs(tenant_id);
CREATE INDEX idx_scan_jobs_org ON scan_jobs(org_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_cves_cve_id ON cves(cve_id);
CREATE INDEX idx_cves_is_kev ON cves(is_kev);
CREATE INDEX idx_cves_epss ON cves(epss_score DESC);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE asns ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated_at BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_assets_updated_at BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION update_updated_at();
