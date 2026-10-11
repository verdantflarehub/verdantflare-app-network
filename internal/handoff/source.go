package handoff

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const rejectWrite = `BEGIN RAISE EXCEPTION 'egress source frozen for handoff' USING ERRCODE='55000'; END;`
const rejectAudit = `BEGIN IF NEW.action LIKE 'egress.%' THEN RAISE EXCEPTION 'egress source frozen for handoff' USING ERRCODE='55000'; END IF; RETURN NEW; END;`

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// FreezeSource is a separate, explicit administration command. Export and all
// target commands use read-only source transactions and never install this gate.
func FreezeSource(ctx context.Context, pool *pgxpool.Pool, station, id string) error {
	if !validID(station) || !validID(id) {
		return ErrInvalid
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(2026101105)`); e != nil {
		return e
	}
	var configured string
	if e = tx.QueryRow(ctx, `SELECT station_id::text FROM station.configuration WHERE singleton`).Scan(&configured); e != nil {
		return e
	}
	if configured != station {
		return ErrConflict
	}
	// Locks wait for prior writes. Once committed, ALWAYS triggers prevent every
	// legacy insert/update/delete/truncate, including late probe completions.
	if _, e = tx.Exec(ctx, `LOCK TABLE station.egress_proxies,station.audit_events IN ACCESS EXCLUSIVE MODE`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS network_handoff; CREATE TABLE IF NOT EXISTS network_handoff.control(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),handoff_id uuid NOT NULL,station_id uuid NOT NULL,frozen_at timestamptz NOT NULL DEFAULT now())`); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM network_handoff.control`).Scan(&count); e != nil {
		return e
	}
	if count == 0 {
		if _, e = tx.Exec(ctx, `CREATE FUNCTION network_handoff.reject_write() RETURNS trigger LANGUAGE plpgsql AS $body$`+rejectWrite+`$body$; CREATE FUNCTION network_handoff.reject_egress_audit() RETURNS trigger LANGUAGE plpgsql AS $body$`+rejectAudit+`$body$;
CREATE TRIGGER network_handoff_proxy BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON station.egress_proxies FOR EACH STATEMENT EXECUTE FUNCTION network_handoff.reject_write();
CREATE TRIGGER network_handoff_audit_insert BEFORE INSERT ON station.audit_events FOR EACH ROW EXECUTE FUNCTION network_handoff.reject_egress_audit();
CREATE TRIGGER network_handoff_audit_history BEFORE UPDATE OR DELETE OR TRUNCATE ON station.audit_events FOR EACH STATEMENT EXECUTE FUNCTION network_handoff.reject_write();
CREATE TRIGGER network_handoff_control_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON network_handoff.control FOR EACH STATEMENT EXECUTE FUNCTION network_handoff.reject_write();
ALTER TABLE station.egress_proxies ENABLE ALWAYS TRIGGER network_handoff_proxy;
ALTER TABLE station.audit_events ENABLE ALWAYS TRIGGER network_handoff_audit_insert;
ALTER TABLE station.audit_events ENABLE ALWAYS TRIGGER network_handoff_audit_history;
ALTER TABLE network_handoff.control ENABLE ALWAYS TRIGGER network_handoff_control_immutable;`); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO network_handoff.control(handoff_id,station_id) VALUES($1,$2)`, id, station); e != nil {
			return e
		}
	}
	if _, e = sourceFrozen(ctx, tx, station, id); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func trigger(ctx context.Context, q queryer, table, name, function, body string, eventType int) error {
	var valid bool
	e := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE t.tgrelid=$1::regclass AND t.tgname=$2 AND NOT t.tgisinternal AND t.tgenabled='A' AND t.tgtype=$3 AND t.tgnargs=0 AND t.tgqual IS NULL AND n.nspname='network_handoff' AND p.proname=$4 AND p.prosrc=$5 AND NOT p.prosecdef AND l.lanname='plpgsql')`, table, name, eventType, function, body).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return ErrNotFrozen
	}
	return nil
}
func sourceFrozen(ctx context.Context, q queryer, station, id string) (time.Time, error) {
	var configured, storedID, storedStation string
	var frozen time.Time
	if e := q.QueryRow(ctx, `SELECT station_id::text FROM station.configuration WHERE singleton`).Scan(&configured); e != nil {
		return frozen, e
	}
	if e := q.QueryRow(ctx, `SELECT handoff_id::text,station_id::text,frozen_at FROM network_handoff.control WHERE singleton`).Scan(&storedID, &storedStation, &frozen); e != nil {
		return frozen, ErrNotFrozen
	}
	if configured != station || storedStation != station || storedID != id || frozen.IsZero() {
		return frozen, ErrConflict
	}
	for _, t := range []struct {
		table, name, function, body string
		event                       int
	}{
		{"station.egress_proxies", "network_handoff_proxy", "reject_write", rejectWrite, 62},
		{"station.audit_events", "network_handoff_audit_insert", "reject_egress_audit", rejectAudit, 7},
		{"station.audit_events", "network_handoff_audit_history", "reject_write", rejectWrite, 58},
		{"network_handoff.control", "network_handoff_control_immutable", "reject_write", rejectWrite, 58},
	} {
		if e := trigger(ctx, q, t.table, t.name, t.function, t.body, t.event); e != nil {
			return frozen, e
		}
	}
	return frozen.UTC(), nil
}
func readRows(ctx context.Context, q queryer, source bool) ([]Proxy, []Audit, error) {
	proxyTable, auditTable, auditSelect, auditWhere := "network.egress_proxies", "network.legacy_audit_events", "to_jsonb(a)-'handoff_id'", ""
	if source {
		proxyTable, auditTable, auditSelect, auditWhere = "station.egress_proxies", "station.audit_events", "to_jsonb(a)", " WHERE action LIKE 'egress.%'"
	}
	var count int
	if e := q.QueryRow(ctx, `SELECT count(*) FROM `+proxyTable).Scan(&count); e != nil {
		return nil, nil, e
	}
	if count > 10000 {
		return nil, nil, ErrInvalid
	}
	if e := q.QueryRow(ctx, `SELECT count(*) FROM `+auditTable+auditWhere).Scan(&count); e != nil {
		return nil, nil, e
	}
	if count > 100000 {
		return nil, nil, ErrInvalid
	}
	// Bound expanded JSON before aggregating; TOAST/compressed tuple size does
	// not bound the client allocation needed for a complete audit snapshot.
	var proxyBytes, auditBytes int64
	if e := q.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(to_jsonb(p)::text)),0)::bigint FROM `+proxyTable+` p`).Scan(&proxyBytes); e != nil {
		return nil, nil, e
	}
	if e := q.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(to_jsonb(a)::text)),0)::bigint FROM `+auditTable+` a`+auditWhere).Scan(&auditBytes); e != nil {
		return nil, nil, e
	}
	if proxyBytes+auditBytes > MaxBytes/2 {
		return nil, nil, ErrInvalid
	}
	var proxies, audits []byte
	if e := q.QueryRow(ctx, `SELECT COALESCE(jsonb_agg((to_jsonb(p)-'credentials') || jsonb_build_object('credentials',encode(p.credentials,'base64')) ORDER BY proxy_id),'[]'::jsonb) FROM `+proxyTable+` p`).Scan(&proxies); e != nil {
		return nil, nil, e
	}
	if e := q.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(`+auditSelect+` ORDER BY event_id),'[]'::jsonb) FROM `+auditTable+` a`+auditWhere).Scan(&audits); e != nil {
		return nil, nil, e
	}
	var p []Proxy
	var a []Audit
	if e := decode(bytes.NewReader(proxies), MaxBytes, &p); e != nil {
		return nil, nil, e
	}
	if e := decode(bytes.NewReader(audits), MaxBytes, &a); e != nil {
		return nil, nil, e
	}
	return p, a, nil
}

// sourceSnapshot keeps ACCESS SHARE locks until its caller rolls back/commits.
// Source barrier removal requires conflicting DDL locks and cannot race import.
func sourceSnapshot(ctx context.Context, pool *pgxpool.Pool, station, id string, key []byte) (pgx.Tx, Archive, error) {
	var a Archive
	tx, e := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return nil, a, e
	}
	fail := func(e error) (pgx.Tx, Archive, error) { _ = tx.Rollback(context.Background()); return nil, a, e }
	if _, e = tx.Exec(ctx, `SET LOCAL TIME ZONE 'UTC'; LOCK TABLE station.egress_proxies,station.audit_events,network_handoff.control IN ACCESS SHARE MODE`); e != nil {
		return fail(e)
	}
	frozen, e := sourceFrozen(ctx, tx, station, id)
	if e != nil {
		return fail(e)
	}
	p, events, e := readRows(ctx, tx, true)
	if e != nil {
		return fail(e)
	}
	a, e = (Snapshot{Format: 1, ID: id, Station: station, FrozenAt: frozen, Proxies: p, Audits: events}).Archive()
	if e != nil {
		return fail(e)
	}
	var now time.Time
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return fail(e)
	}
	if e = a.Validate(key, station, id, now); e != nil {
		return fail(e)
	}
	return tx, a, nil
}
func Export(ctx context.Context, pool *pgxpool.Pool, station, id string, key []byte) (Archive, error) {
	tx, a, e := sourceSnapshot(ctx, pool, station, id, key)
	if e != nil {
		return a, e
	}
	defer tx.Rollback(context.Background())
	return a, tx.Commit(ctx)
}
func Summary(a Archive, state string) string {
	return fmt.Sprintf("handoff=%s state=%s proxies=%d audit=%d sha256=%s", a.Snapshot.ID, state, len(a.Snapshot.Proxies), len(a.Snapshot.Audits), a.Digest)
}
