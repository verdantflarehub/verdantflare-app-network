package handoff

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verdantflarehub/verdantflare-app-network/migrations"
)

type targetState struct {
	mode            string
	owner, imported bool
}

func target(ctx context.Context, tx pgx.Tx, a Archive, lock bool) (targetState, error) {
	var s targetState
	if err := migrations.VerifyGuards(ctx, tx); err != nil {
		return s, err
	}
	sql := `SELECT state,session_user=migration_owner FROM network.writer_gate WHERE singleton`
	if lock {
		sql += ` FOR UPDATE`
	}
	if e := tx.QueryRow(ctx, sql).Scan(&s.mode, &s.owner); e != nil {
		return s, e
	}
	var count, live int
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM network.audit_events`).Scan(&live); e != nil {
		return s, e
	}
	if live != 0 {
		return s, ErrConflict
	}
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM network.handoffs`).Scan(&count); e != nil {
		return s, e
	}
	if count > 1 {
		return s, ErrConflict
	}
	p, events, e := readRows(ctx, tx, false)
	if e != nil {
		return s, e
	}
	if count == 0 {
		if len(p) > 0 || len(events) > 0 || s.mode != "closed" {
			return s, ErrConflict
		}
		return s, nil
	}
	s.imported = true
	var id, station, digest string
	var proxies, audits int
	var frozen time.Time
	if e = tx.QueryRow(ctx, `SELECT handoff_id::text,station_id::text,digest,proxy_count,audit_count,frozen_at FROM network.handoffs`).Scan(&id, &station, &digest, &proxies, &audits, &frozen); e != nil {
		return s, e
	}
	if id != a.Snapshot.ID || station != a.Snapshot.Station || digest != a.Digest || proxies != len(a.Snapshot.Proxies) || audits != len(a.Snapshot.Audits) || !frozen.Equal(a.Snapshot.FrozenAt) {
		return s, ErrConflict
	}
	snapshot := a.Snapshot
	snapshot.Proxies = p
	snapshot.Audits = events
	current, e := fingerprint(snapshot)
	if e != nil || current != a.Digest {
		return s, ErrConflict
	}
	if s.mode != "staged" && s.mode != "closed" && s.mode != "active" {
		return s, ErrConflict
	}
	return s, nil
}

// Execute verifies a fresh frozen source while holding its read locks through
// the target commit. check is read-only; import and activate are explicit modes.
func Execute(ctx context.Context, source, destination *pgxpool.Pool, a Archive, key []byte, mode string) (string, error) {
	if mode != "check" && mode != "import" && mode != "activate" {
		return "", ErrInvalid
	}
	if e := a.Validate(key, a.Snapshot.Station, a.Snapshot.ID, time.Now()); e != nil {
		return "", e
	}
	sourceTx, current, e := sourceSnapshot(ctx, source, a.Snapshot.Station, a.Snapshot.ID, key)
	if e != nil {
		return "", e
	}
	defer sourceTx.Rollback(context.Background())
	if current.Digest != a.Digest {
		return "", ErrConflict
	}
	options := pgx.TxOptions{}
	if mode == "check" {
		options = pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
	}
	tx, e := destination.BeginTx(ctx, options)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SET LOCAL TIME ZONE 'UTC'`); e != nil {
		return "", e
	}
	s, e := target(ctx, tx, a, mode != "check")
	if e != nil {
		return "", e
	}
	if mode == "check" {
		if !s.imported {
			return "empty", tx.Commit(ctx)
		}
		return s.mode, tx.Commit(ctx)
	}
	if !s.owner {
		return "", ErrConflict
	}
	if mode == "activate" {
		if !s.imported || (s.mode != "staged" && s.mode != "active") {
			return "", ErrConflict
		}
		if _, e = tx.Exec(ctx, `UPDATE network.writer_gate SET state='active' WHERE singleton`); e != nil {
			return "", e
		}
		return "active", tx.Commit(ctx)
	}
	if s.imported {
		return s.mode, tx.Commit(ctx)
	}
	if _, e = tx.Exec(ctx, `UPDATE network.writer_gate SET state='importing' WHERE singleton`); e != nil {
		return "", e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO network.handoffs(handoff_id,station_id,digest,proxy_count,audit_count,frozen_at) VALUES($1,$2,$3,$4,$5,$6)`, a.Snapshot.ID, a.Snapshot.Station, a.Digest, len(a.Snapshot.Proxies), len(a.Snapshot.Audits), a.Snapshot.FrozenAt); e != nil {
		return "", e
	}
	for _, p := range a.Snapshot.Proxies {
		var probe any
		if string(p.Probe) != "null" {
			probe = []byte(p.Probe)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO network.egress_proxies(proxy_id,station_id,organization_id,name,protocol,host,port,credentials,endpoint_key,status,tag,note,expires_at,assigned_apps,revision,probe,probe_token,probe_until,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, p.ID, p.Station, p.Organization, p.Name, p.Protocol, p.Host, p.Port, p.Credentials, p.EndpointKey, p.Status, p.Tag, p.Note, p.ExpiresAt, p.Assigned, p.Revision, probe, p.ProbeToken, p.ProbeUntil, p.CreatedAt, p.UpdatedAt); e != nil {
			return "", e
		}
	}
	for _, aEvent := range a.Snapshot.Audits {
		if _, e = tx.Exec(ctx, `INSERT INTO network.legacy_audit_events(event_id,handoff_id,request_id,user_id,organization_id,session_id,action,outcome,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, aEvent.ID, a.Snapshot.ID, aEvent.Request, aEvent.User, aEvent.Organization, aEvent.Session, aEvent.Action, aEvent.Outcome, aEvent.CreatedAt); e != nil {
			return "", e
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE network.writer_gate SET state='staged' WHERE singleton`); e != nil {
		return "", e
	}
	if _, e = target(ctx, tx, a, false); e != nil {
		return "", e
	}
	return "staged", tx.Commit(ctx)
}
func Close(ctx context.Context, pool *pgxpool.Pool) error {
	tx, e := pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	var owner bool
	if e = migrations.VerifyGuards(ctx, tx); e != nil {
		return e
	}
	if e = tx.QueryRow(ctx, `SELECT session_user=migration_owner FROM network.writer_gate WHERE singleton FOR UPDATE`).Scan(&owner); e != nil {
		return e
	}
	if !owner {
		return errors.New("handoff requires migration owner")
	}
	if _, e = tx.Exec(ctx, `UPDATE network.writer_gate SET state='closed' WHERE singleton`); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
