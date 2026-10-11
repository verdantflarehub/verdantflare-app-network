CREATE TABLE network.writer_gate (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    state text NOT NULL CHECK (state IN ('closed','importing','staged','active')),
    migration_owner name NOT NULL DEFAULT CURRENT_USER
);
INSERT INTO network.writer_gate(singleton,state) VALUES(true,'closed');
CREATE TABLE network.handoffs (
    handoff_id uuid PRIMARY KEY,
    station_id uuid NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    proxy_count bigint NOT NULL,
    audit_count bigint NOT NULL,
    frozen_at timestamptz NOT NULL,
    imported_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE network.legacy_audit_events (
    event_id uuid PRIMARY KEY,
    handoff_id uuid NOT NULL REFERENCES network.handoffs(handoff_id),
    request_id text NOT NULL,
    user_id uuid,
    organization_id uuid,
    session_id uuid,
    action text NOT NULL CHECK (action LIKE 'egress.%'),
    outcome text NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE FUNCTION network.check_writer_gate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE gate network.writer_gate;
BEGIN
    SELECT * INTO STRICT gate FROM network.writer_gate WHERE singleton FOR SHARE;
    IF gate.state='active' OR (gate.state='importing' AND session_user=gate.migration_owner) THEN RETURN NULL; END IF;
    RAISE EXCEPTION 'network writer is closed' USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER network_writer_gate BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON network.egress_proxies FOR EACH STATEMENT EXECUTE FUNCTION network.check_writer_gate();
ALTER TABLE network.egress_proxies ENABLE ALWAYS TRIGGER network_writer_gate;
CREATE TRIGGER network_audit_gate BEFORE INSERT ON network.audit_events FOR EACH STATEMENT EXECUTE FUNCTION network.check_writer_gate();
ALTER TABLE network.audit_events ENABLE ALWAYS TRIGGER network_audit_gate;
CREATE FUNCTION network.reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'network audit is append-only'; END;
$$;
CREATE TRIGGER network_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON network.audit_events FOR EACH STATEMENT EXECUTE FUNCTION network.reject_audit_mutation();
CREATE TRIGGER network_legacy_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON network.legacy_audit_events FOR EACH STATEMENT EXECUTE FUNCTION network.reject_audit_mutation();
ALTER TABLE network.audit_events ENABLE ALWAYS TRIGGER network_audit_immutable;
ALTER TABLE network.legacy_audit_events ENABLE ALWAYS TRIGGER network_legacy_audit_immutable;
CREATE FUNCTION network.runtime_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
SELECT state='active'
AND NOT pg_has_role(session_user,migration_owner,'MEMBER')
AND NOT pg_has_role(session_user,(SELECT relowner FROM pg_class WHERE oid='network.egress_proxies'::regclass),'MEMBER')
AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname=session_user)
AND NOT has_table_privilege(session_user,'network.writer_gate','INSERT,UPDATE,DELETE,TRUNCATE')
AND NOT has_table_privilege(session_user,'network.handoffs','INSERT,UPDATE,DELETE,TRUNCATE')
AND NOT has_table_privilege(session_user,'network.legacy_audit_events','INSERT,UPDATE,DELETE,TRUNCATE')
FROM network.writer_gate WHERE singleton;
$$;
