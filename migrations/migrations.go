// Package migrations owns the application's schema. Data adoption is explicit.
package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
)

//go:embed 0001_network.sql
var initial string

//go:embed 0002_handoff.sql
var handoff string
var scripts = []string{initial, handoff}

func digest(sql string) string { h := sha256.Sum256([]byte(sql)); return hex.EncodeToString(h[:]) }
func validStation(station string) bool {
	id, e := uuid.Parse(station)
	return e == nil && id != uuid.Nil && id.String() == station
}

// Apply is never called by serve. Existing immutable SQL is checksum verified.
func Apply(ctx context.Context, pool *pgxpool.Pool, station string) error {
	if !validStation(station) {
		return errors.New("invalid Station identity")
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(2026101104)`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS network; CREATE TABLE IF NOT EXISTS network.migration_history(version integer PRIMARY KEY, digest text NOT NULL)`); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM network.migration_history`).Scan(&count); e != nil {
		return e
	}
	if count > len(scripts) {
		return errors.New("unsupported migration history")
	}
	for i, sql := range scripts {
		if i < count {
			var stored string
			if e = tx.QueryRow(ctx, `SELECT digest FROM network.migration_history WHERE version=$1`, i+1).Scan(&stored); e != nil {
				return e
			}
			if stored != digest(sql) {
				return errors.New("migration digest mismatch")
			}
			continue
		}
		if _, e = tx.Exec(ctx, sql); e != nil {
			return e
		}
		if i == 0 {
			if _, e = tx.Exec(ctx, `INSERT INTO network.configuration(station_id,schema_version) VALUES($1,1)`, station); e != nil {
				return e
			}
		}
		if _, e = tx.Exec(ctx, `INSERT INTO network.migration_history(version,digest) VALUES($1,$2)`, i+1, digest(sql)); e != nil {
			return e
		}
	}
	if e = verify(ctx, tx, station); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func verify(ctx context.Context, q queryer, station string) error {
	var existing string
	var count int
	if e := q.QueryRow(ctx, `SELECT station_id::text FROM network.configuration WHERE singleton AND schema_version=1`).Scan(&existing); e != nil {
		return e
	}
	if e := q.QueryRow(ctx, `SELECT count(*) FROM network.migration_history`).Scan(&count); e != nil {
		return e
	}
	if existing != station || count != len(scripts) {
		return errors.New("network schema or Station mismatch")
	}
	for i, sql := range scripts {
		var stored string
		if e := q.QueryRow(ctx, `SELECT digest FROM network.migration_history WHERE version=$1`, i+1).Scan(&stored); e != nil {
			return e
		}
		if stored != digest(sql) {
			return errors.New("migration digest mismatch")
		}
	}
	return nil
}
func Verify(ctx context.Context, pool *pgxpool.Pool, station string) error {
	if err := verify(ctx, pool, station); err != nil {
		return err
	}
	return VerifyGuards(ctx, pool)
}
func VerifyRuntime(ctx context.Context, pool *pgxpool.Pool) error {
	if err := VerifyGuards(ctx, pool); err != nil {
		return err
	}
	var ready bool
	if e := pool.QueryRow(ctx, `SELECT COALESCE(network.runtime_ready(),false)`).Scan(&ready); e != nil {
		return e
	}
	if !ready {
		return errors.New("writer gate closed or runtime role privileged")
	}
	return nil
}

// VerifyGuards checks live database objects as well as immutable migration
// history. A disabled/replaced trigger cannot masquerade as a closed writer.
func VerifyGuards(ctx context.Context, q queryer) error {
	_, body, ok := strings.Cut(handoff, "CREATE FUNCTION network.check_writer_gate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$")
	if !ok {
		return errors.New("invalid writer gate migration")
	}
	body, _, ok = strings.Cut(body, "$$;")
	if !ok {
		return errors.New("invalid writer gate migration")
	}
	var valid bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='network.check_writer_gate()'::regprocedure AND p.prosrc=$1 AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog']) AND (SELECT count(*) FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgenabled='A' AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgfoid='network.check_writer_gate()'::regprocedure AND ((t.tgrelid='network.egress_proxies'::regclass AND t.tgname='network_writer_gate' AND t.tgtype=62) OR (t.tgrelid='network.audit_events'::regclass AND t.tgname='network_audit_gate' AND t.tgtype=6)))=2`, body).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("network writer gate does not match migration")
	}
	return nil
}

// ActivateFresh is restricted to explicitly new, empty environments.
func ActivateFresh(ctx context.Context, pool *pgxpool.Pool) error {
	tx, e := pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = VerifyGuards(ctx, tx); e != nil {
		return e
	}
	var state string
	var owner bool
	if e = tx.QueryRow(ctx, `SELECT state,session_user=migration_owner FROM network.writer_gate WHERE singleton FOR UPDATE`).Scan(&state, &owner); e != nil {
		return e
	}
	if !owner || (state != "closed" && state != "active") {
		return errors.New("fresh activation unavailable")
	}
	var empty bool
	if e = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM network.handoffs) AND NOT EXISTS(SELECT 1 FROM network.egress_proxies) AND NOT EXISTS(SELECT 1 FROM network.audit_events) AND NOT EXISTS(SELECT 1 FROM network.legacy_audit_events)`).Scan(&empty); e != nil {
		return e
	}
	if !empty {
		return errors.New("fresh activation requires an empty target")
	}
	if _, e = tx.Exec(ctx, `UPDATE network.writer_gate SET state='active' WHERE singleton`); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
