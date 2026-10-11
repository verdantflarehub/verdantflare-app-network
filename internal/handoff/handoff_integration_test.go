//go:build integration

package handoff

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verdantflarehub/verdantflare-app-network/internal/testdb"
	"github.com/verdantflarehub/verdantflare-app-network/migrations"
)

// This uses two disposable PostgreSQL databases in the explicitly configured
// 5090 environment. Local development only compiles this tagged test.
func TestSeparateDatabaseHandoffBarrierAtomicImportAndCutover(t *testing.T) {
	ctx := context.Background()
	source, targetDB := testdb.New(t), testdb.New(t)
	template, key, _ := fixture()
	station, id := template.Snapshot.Station, template.Snapshot.ID
	if e := migrations.Apply(ctx, source, station); e != nil {
		t.Fatal(e)
	}
	if e := migrations.Apply(ctx, targetDB, station); e != nil {
		t.Fatal(e)
	}
	// Same H1 column shapes, with the source's nullable audit principals. These
	// fixtures do not claim to exercise all unrelated Core identity migrations.
	_, e := source.Exec(ctx, `CREATE SCHEMA station; CREATE TABLE station.configuration(singleton boolean PRIMARY KEY DEFAULT true,station_id uuid NOT NULL);
CREATE TABLE station.egress_proxies(LIKE network.egress_proxies INCLUDING ALL);
CREATE TABLE station.audit_events(LIKE network.audit_events INCLUDING ALL);
ALTER TABLE station.audit_events ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE station.audit_events ALTER COLUMN organization_id DROP NOT NULL;`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = source.Exec(ctx, `INSERT INTO station.configuration(station_id) VALUES($1)`, station); e != nil {
		t.Fatal(e)
	}
	p := template.Snapshot.Proxies[0]
	expired := time.Now().UTC().Add(-time.Minute)
	p.ProbeUntil = &expired
	if _, e = source.Exec(ctx, `INSERT INTO station.egress_proxies(proxy_id,station_id,organization_id,name,protocol,host,port,credentials,endpoint_key,status,tag,note,expires_at,assigned_apps,revision,probe,probe_token,probe_until,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, p.ID, p.Station, p.Organization, p.Name, p.Protocol, p.Host, p.Port, p.Credentials, p.EndpointKey, p.Status, p.Tag, p.Note, p.ExpiresAt, p.Assigned, p.Revision, []byte(p.Probe), p.ProbeToken, p.ProbeUntil, p.CreatedAt, p.UpdatedAt); e != nil {
		t.Fatal(e)
	}
	audit := template.Snapshot.Audits[0]
	if _, e = source.Exec(ctx, `INSERT INTO station.audit_events(event_id,request_id,user_id,organization_id,session_id,action,outcome,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, audit.ID, audit.Request, audit.User, audit.Organization, audit.Session, audit.Action, audit.Outcome, audit.CreatedAt); e != nil {
		t.Fatal(e)
	}
	if _, e = Export(ctx, source, station, id, key); e == nil {
		t.Fatal("unfrozen source exported")
	}
	if e = FreezeSource(ctx, source, station, id); e != nil {
		t.Fatal(e)
	}
	if e = FreezeSource(ctx, source, station, id); e != nil {
		t.Fatal("freeze retry", e)
	}
	if e = FreezeSource(ctx, source, station, "0199b501-0000-7000-8000-000000000099"); !errors.Is(e, ErrConflict) {
		t.Fatal("changed handoff identity accepted", e)
	}
	if _, e = source.Exec(ctx, `UPDATE station.egress_proxies SET probe_token=NULL,probe_until=NULL WHERE proxy_id=$1`, p.ID); e == nil {
		t.Fatal("late old probe mutated frozen source")
	}
	a, e := Export(ctx, source, station, id, key)
	if e != nil {
		t.Fatal(e)
	}
	if a.Snapshot.Proxies[0].Revision != p.Revision || *a.Snapshot.Proxies[0].ProbeToken != *p.ProbeToken || a.Snapshot.Audits[0].User != nil {
		t.Fatal("source snapshot lost original fields")
	}
	if state, e := Execute(ctx, source, targetDB, a, key, "check"); e != nil || state != "empty" {
		t.Fatal("preflight", state, e)
	}
	changed := a
	changed.Snapshot.Proxies = append([]Proxy(nil), a.Snapshot.Proxies...)
	changed.Snapshot.Proxies[0].Note = "archive mutation"
	changed, _ = changed.Snapshot.Archive()
	if _, e = Execute(ctx, source, targetDB, changed, key, "import"); !errors.Is(e, ErrConflict) {
		t.Fatal("archive differed from frozen source", e)
	}
	// Force a failure after proxy insertion to verify the whole batch, handoff
	// record and importing state roll back together.
	if _, e = targetDB.Exec(ctx, `CREATE FUNCTION network.test_reject_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejection'; END; $$; CREATE TRIGGER test_reject_import BEFORE INSERT ON network.legacy_audit_events FOR EACH ROW EXECUTE FUNCTION network.test_reject_import();`); e != nil {
		t.Fatal(e)
	}
	if _, e = Execute(ctx, source, targetDB, a, key, "import"); e == nil {
		t.Fatal("forced import error was ignored")
	}
	if state, e := Execute(ctx, source, targetDB, a, key, "check"); e != nil || state != "empty" {
		t.Fatal("failed import left partial records", state, e)
	}
	if _, e = targetDB.Exec(ctx, `DROP TRIGGER test_reject_import ON network.legacy_audit_events; DROP FUNCTION network.test_reject_import();`); e != nil {
		t.Fatal(e)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if state, e := Execute(ctx, source, targetDB, a, key, "import"); e != nil || state != "staged" {
			t.Fatal("import/retry", state, e)
		}
	}
	if _, e = targetDB.Exec(ctx, `UPDATE network.egress_proxies SET note='too early'`); e == nil {
		t.Fatal("staged writer accepted mutation")
	}
	if state, e := Execute(ctx, source, targetDB, a, key, "activate"); e != nil || state != "active" {
		t.Fatal("activate", state, e)
	}
	if _, e = targetDB.Exec(ctx, `UPDATE network.egress_proxies SET note='new writer',revision=revision+1`); e != nil {
		t.Fatal(e)
	}
	if _, e = Execute(ctx, source, targetDB, a, key, "check"); !errors.Is(e, ErrConflict) {
		t.Fatal("new writes falsely declared rollback-safe", e)
	}
	if e = Close(ctx, targetDB); e != nil {
		t.Fatal(e)
	}
	if _, e = targetDB.Exec(ctx, `UPDATE network.egress_proxies SET note='after close'`); e == nil {
		t.Fatal("closed writer accepted mutation")
	}
	if _, e = source.Exec(ctx, `DELETE FROM station.egress_proxies`); e == nil {
		t.Fatal("target close silently reopened legacy source")
	}
}
