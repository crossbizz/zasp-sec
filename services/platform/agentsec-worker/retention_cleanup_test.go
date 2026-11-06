package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	runtimeopensearch "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
)

type cleanupTestRow struct {
	ready bool
	body  []byte
}

func (r cleanupTestRow) Scan(dest ...any) error {
	switch v := dest[0].(type) {
	case *bool:
		*v = r.ready
	case *[]byte:
		*v = r.body
	default:
		return errors.New("wrong destination")
	}
	return nil
}

type cleanupTestDB struct {
	mu                 sync.Mutex
	mode               string
	steps              []string
	claim              map[string]any
	providers, settles int
}

func (d *cleanupTestDB) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return nil, errors.New("cleanup must use confirmed transaction")
}
func (d *cleanupTestDB) BeginRetentionCleanup(context.Context) (pgx.Tx, error) {
	d.mu.Lock()
	d.steps = append(d.steps, "begin")
	d.mu.Unlock()
	return &cleanupTestTx{db: d}, nil
}

type cleanupTestTx struct {
	pgx.Tx
	db    *cleanupTestDB
	phase string
}

func (tx *cleanupTestTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	d := tx.db
	d.mu.Lock()
	defer d.mu.Unlock()
	if strings.Contains(sql, "caller_ready") {
		ready := !(d.mode == "forward revoked" && d.providers == 0 && len(d.steps) > 4)
		d.steps = append(d.steps, "purpose")
		return cleanupTestRow{ready: ready}
	}
	var body []byte
	switch sql {
	case retentionCleanupClaimSQL:
		tx.phase = "claim"
		d.steps = append(d.steps, "claim")
		found := d.mode != "no pending intent"
		var claim any = d.claim
		if !found {
			claim = nil
		}
		body, _ = json.Marshal(map[string]any{"found": found, "claim": claim})
		if d.mode == "missing claim envelope" {
			body = []byte(`{"found":false}`)
		}
		if d.mode == "missing pending flag" {
			body = []byte(`{"claim":null}`)
		}
	case retentionCleanupAuthorizeSQL:
		tx.phase = "authorize"
		d.steps = append(d.steps, "authorize")
		var got map[string]any
		_ = json.Unmarshal(args[0].([]byte), &got)
		if len(got) != 10 || got["lease_token"] != d.claim["lease_token"] {
			panic("original claim binding lost")
		}
		body = []byte(`{"authorized":true}`)
		if d.mode == "writer not drained before admission" {
			body = []byte(`{"authorized":false}`)
		}
	case retentionCleanupSettleSQL:
		tx.phase = "settle"
		d.steps = append(d.steps, "settle")
		d.settles++
		var got map[string]any
		_ = json.Unmarshal(args[0].([]byte), &got)
		if len(got) != 13 || got["lease_token"] != d.claim["lease_token"] {
			panic("captured settlement binding lost")
		}
		drained := d.mode != "settlement epoch changed" && d.mode != "writer not drained before admission"
		complete := drained && got["index_observed_empty"] == true
		if d.mode == "false physical completion" {
			complete = true
			drained = false
		}
		body, _ = json.Marshal(map[string]any{"recorded": true, "drained": drained, "complete": complete})
	default:
		panic("unlisted cleanup SQL")
	}
	return cleanupTestRow{body: body}
}
func (tx *cleanupTestTx) Commit(context.Context) error {
	d := tx.db
	d.mu.Lock()
	defer d.mu.Unlock()
	d.steps = append(d.steps, "commit:"+tx.phase)
	if d.mode == tx.phase+" commit unknown" {
		return errors.New("private database details")
	}
	return nil
}
func (tx *cleanupTestTx) Rollback(context.Context) error { return nil }

type cleanupTestPurge struct {
	db        *cleanupTestDB
	kind      string
	authority runtimeopensearch.RetentionPurgeAuthority
}

func (p cleanupTestPurge) FixedKind() string { return p.kind }
func (p cleanupTestPurge) PurgeEvent(ctx context.Context, scope domain.Scope, event string) (runtimeopensearch.RetentionPurgeObservation, error) {
	if err := p.authority.AuthorizeRetentionPurge(ctx, scope, event); err != nil {
		return runtimeopensearch.RetentionPurgeObservation{}, err
	}
	p.db.mu.Lock()
	p.db.providers++
	p.db.steps = append(p.db.steps, "provider")
	p.db.mu.Unlock()
	if p.db.mode == "provider uncertain" {
		return runtimeopensearch.RetentionPurgeObservation{}, errors.New("private provider error")
	}
	return runtimeopensearch.RetentionPurgeObservation{DocumentsChecked: 1, DocumentsAbsent: 1, IndexObservedEmpty: true}, nil
}

func cleanupClaimFixture() map[string]any {
	return map[string]any{"claim_id": strings.Repeat("a", 64), "organization_id": "pid_99000001-0000-4000-8000-000000000001", "workspace_id": "pid_99000002-0000-4000-8000-000000000002", "environment_id": "pid_99000003-0000-4000-8000-000000000003", "event_id": "pid_99000004-0000-4000-8000-000000000004", "source_digest": strings.Repeat("b", 64), "kind": "raw-index", "worker_id": "cleanup-worker", "lease_token": strings.Repeat("c", 64), "lease_until": time.Now().UTC().Add(30 * time.Second).Format(retentionCleanupLeaseLayout)}
}

func TestRetentionCleanupOriginalClaimCommitAndDrainBoundaries(t *testing.T) {
	for _, mode := range []string{"confirmed", "no pending intent", "claim commit unknown", "authorize commit unknown", "settle commit unknown", "forward revoked", "provider uncertain", "settlement epoch changed", "false physical completion", "foreign worker", "unknown kind", "expired claim", "swapped fixed target", "missing claim envelope", "missing pending flag", "session v1", "session v2", "writer not drained before admission"} {
		t.Run(mode, func(t *testing.T) {
			db := &cleanupTestDB{mode: mode, claim: cleanupClaimFixture()}
			if mode == "session v1" {
				db.claim["kind"] = "session-index-v1"
			}
			if mode == "session v2" {
				db.claim["kind"] = "session-index-v2"
			}
			if mode == "foreign worker" {
				db.claim["worker_id"] = "other-worker"
			}
			if mode == "unknown kind" {
				db.claim["kind"] = "arbitrary-index"
			}
			if mode == "expired claim" {
				db.claim["lease_until"] = time.Now().UTC().Add(-time.Second).Format(retentionCleanupLeaseLayout)
			}
			factories := map[string]retentionCleanupPurgeFactory{}
			for _, kind := range []string{"raw-index", "session-index-v1", "session-index-v2"} {
				kind := kind
				factories[kind] = func(a runtimeopensearch.RetentionPurgeAuthority) (retentionCleanupPurge, error) {
					if mode == "swapped fixed target" && kind == "raw-index" {
						return cleanupTestPurge{db: db, kind: "session-index-v2", authority: a}, nil
					}
					return cleanupTestPurge{db: db, kind: kind, authority: a}, nil
				}
			}
			runtime, err := newRetentionCleanupWithFactories(db, migrations.RetentionAuditProfileChecksum(), "cleanup-worker", factories, time.Second, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			err = runtime.RunOnce(context.Background())
			success := mode == "confirmed" || mode == "no pending intent" || mode == "settlement epoch changed" || mode == "session v1" || mode == "session v2"
			if success && err != nil {
				t.Fatal(err)
			}
			if !success && err == nil {
				t.Fatal("unconfirmed or unsafe cleanup accepted")
			}
			shouldProvider := mode == "confirmed" || mode == "settle commit unknown" || mode == "provider uncertain" || mode == "settlement epoch changed" || mode == "false physical completion" || mode == "session v1" || mode == "session v2"
			if shouldProvider != (db.providers == 1) {
				t.Fatalf("provider crossed unconfirmed boundary: providers=%d steps=%v", db.providers, db.steps)
			}
			if (mode == "forward revoked" || mode == "writer not drained before admission") && db.settles != 1 {
				t.Fatal("captured observation was lost after forward revocation")
			}
			if mode == "confirmed" {
				joined := strings.Join(db.steps, "|")
				if !strings.Contains(joined, "commit:claim|begin|purpose|authorize|commit:authorize|provider|begin|settle|commit:settle") {
					t.Fatalf("SQL/effect order changed: %s", joined)
				}
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
			if runtime.RunOnce(context.Background()) == nil {
				t.Fatal("closed cleanup admitted borrower")
			}
		})
	}
}

func TestRetentionCleanupClaimCannotLeakOrSwitchFixedTarget(t *testing.T) {
	claim := retentionCleanupClaim{LeaseToken: strings.Repeat("d", 64)}
	if strings.Contains(fmt.Sprintf("%+v", claim), claim.LeaseToken) {
		t.Fatal("private claim token exposed")
	}
}

type cleanupBlockingPurge struct {
	cleanupTestPurge
	entered chan struct{}
	release <-chan struct{}
}

func (p cleanupBlockingPurge) PurgeEvent(ctx context.Context, scope domain.Scope, event string) (runtimeopensearch.RetentionPurgeObservation, error) {
	result, err := p.cleanupTestPurge.PurgeEvent(ctx, scope, event)
	close(p.entered)
	<-p.release
	return result, err
}

func TestRetentionCleanupCloseJoinsActualEffectAndCapturedSettlement(t *testing.T) {
	db := &cleanupTestDB{mode: "confirmed", claim: cleanupClaimFixture()}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	factories := map[string]retentionCleanupPurgeFactory{}
	for _, kind := range []string{"raw-index", "session-index-v1", "session-index-v2"} {
		kind := kind
		factories[kind] = func(a runtimeopensearch.RetentionPurgeAuthority) (retentionCleanupPurge, error) {
			return cleanupBlockingPurge{cleanupTestPurge: cleanupTestPurge{db: db, kind: kind, authority: a}, entered: entered, release: release}, nil
		}
	}
	runtime, err := newRetentionCleanupWithFactories(db, migrations.RetentionAuditProfileChecksum(), "cleanup-worker", factories, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.RunOnce(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("provider never entered")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close abandoned active borrower: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if runtime.Ready(context.Background()) == nil {
		t.Fatal("closing cleanup admitted new SQL borrower")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish captured settlement")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join actual borrower")
	}
	db.mu.Lock()
	settles := db.settles
	db.mu.Unlock()
	if settles != 1 {
		t.Fatal("Close lost captured settlement")
	}
}
