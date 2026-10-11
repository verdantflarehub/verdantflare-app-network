CREATE SCHEMA IF NOT EXISTS network;
CREATE TABLE network.configuration (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    station_id uuid NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version = 1)
);
CREATE TABLE network.egress_proxies (
    proxy_id uuid PRIMARY KEY,
    station_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    protocol text NOT NULL CHECK (protocol IN ('http','https','socks5','socks5h')),
    host text NOT NULL,
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    credentials bytea NOT NULL,
    endpoint_key text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','off')),
    tag text NOT NULL DEFAULT '',
    note text NOT NULL DEFAULT '',
    expires_at timestamptz,
    assigned_apps text[] NOT NULL DEFAULT '{}',
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    probe jsonb,
    probe_token uuid,
    probe_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(station_id, organization_id, endpoint_key)
);
CREATE INDEX egress_proxies_owner ON network.egress_proxies(station_id, organization_id, created_at);
CREATE TABLE network.audit_events (
    event_id uuid PRIMARY KEY,
    request_id text NOT NULL,
    user_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    session_id uuid,
    action text NOT NULL,
    outcome text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX network_audit_org_time ON network.audit_events(organization_id, created_at);
