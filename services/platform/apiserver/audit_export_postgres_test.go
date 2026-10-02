package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type auditExportOutboxSQLLease struct {
	OrganizationID string    `json:"organization_id"`
	WorkspaceID    string    `json:"workspace_id"`
	EnvironmentID  string    `json:"environment_id"`
	OutboxID       string    `json:"outbox_id"`
	ExportID       string    `json:"export_id"`
	PolicyID       string    `json:"policy_id"`
	Generation     int64     `json:"generation"`
	Attempt        int       `json:"attempt"`
	ExpiresAt      time.Time `json:"lease_expires_at"`
}

func TestAuditExportPostgresOutboxRetryAndConfirmedPublish(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, outbox := auditExportWorkerConnections(t, ctx, f)
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	claim := `SELECT zasp_audit_export_claim_outbox($1,$2,$3,$4,$5,$6)`
	claimArgs := []any{"audit-export-publisher", strings.Repeat("d", 64), 180, 10, request[11], request[12]}
	if err := outbox.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil {
		t.Fatal("registered durable audit outbox unavailable", err)
	}
	original := append([]byte(nil), body...)
	var leases []auditExportOutboxSQLLease
	var fields []map[string]json.RawMessage
	if json.Unmarshal(body, &leases) != nil || json.Unmarshal(body, &fields) != nil || len(leases) != 1 || len(fields[0]) != 9 {
		t.Fatal("outbox claim is not a closed bounded lease array")
	}
	lease := leases[0]
	if lease.OrganizationID != request[0] || lease.WorkspaceID != request[1] || lease.EnvironmentID != request[2] || lease.OutboxID != request[9] || lease.ExportID != request[7] || lease.PolicyID != auditExportTestPolicy().PolicyID || lease.Generation != 1 || lease.Attempt != 1 || !lease.ExpiresAt.After(time.Now()) {
		t.Fatal("outbox lease lost persisted scope/policy or attempt")
	}
	if err := outbox.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil || !bytes.Equal(body, original) {
		t.Fatal("lost claim response replay changed lease", err)
	}
	other := append([]any(nil), claimArgs...)
	other[0], other[1] = "other-export-publisher", strings.Repeat("e", 64)
	if err := outbox.QueryRow(ctx, claim, other...).Scan(&body); err != nil || string(body) != "[]" {
		t.Fatal("another publisher stole confirmed lease", err)
	}
	if _, err := worker.Exec(ctx, claim, claimArgs...); auditExportSQLState(err) != "42501" {
		t.Fatal("executor claimed publish authority", err)
	}
	for _, bad := range []struct {
		index int
		value any
	}{{1, strings.Repeat("d", 32)}, {2, 59}, {2, 301}, {3, 0}, {3, 11}} {
		args := append([]any(nil), claimArgs...)
		args[bad.index] = bad.value
		if err := outbox.QueryRow(ctx, claim, args...).Scan(&body); auditExportSQLState(err) != "22023" {
			t.Fatal("invalid bounded publish claim accepted", err)
		}
	}
	base := []any{request[0], request[1], request[2], request[9], claimArgs[0], claimArgs[1], int64(1), 1}
	retry := `SELECT zasp_audit_export_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	retryArgs := append(append([]any(nil), base...), 60, request[11], request[12])
	if err := outbox.QueryRow(ctx, retry, retryArgs...).Scan(&body); err != nil || string(body) != `{"retried": true}` {
		t.Fatal("uncertain publication could not durably retry", err)
	}
	if err := outbox.QueryRow(ctx, retry, retryArgs...).Scan(&body); err != nil {
		t.Fatal("outbox retry replay unavailable", err)
	}
	if err := outbox.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil || string(body) != "[]" {
		t.Fatal("outbox skipped fixed retry backoff", err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[9]); err != nil {
		t.Fatal(err)
	}
	if err := outbox.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil || json.Unmarshal(body, &leases) != nil || len(leases) != 1 || leases[0].Generation != 2 || leases[0].Attempt != 2 {
		t.Fatal("durable outbox retry did not advance fence", err)
	}
	finish := `SELECT zasp_audit_export_finish_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	ack := "sha256:" + strings.Repeat("a", 64)
	if err := outbox.QueryRow(ctx, finish, append(append([]any(nil), base...), ack, request[11], request[12])...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("old publish lease completed new generation", err)
	}
	base[6], base[7] = int64(2), 2
	finishArgs := append(append([]any(nil), base...), ack, request[11], request[12])
	badAck := append([]any(nil), finishArgs...)
	badAck[8] = "raw-provider-message"
	if err := outbox.QueryRow(ctx, finish, badAck...).Scan(&body); auditExportSQLState(err) != "22023" {
		t.Fatal("raw provider acknowledgement accepted", err)
	}
	if err := outbox.QueryRow(ctx, finish, finishArgs...).Scan(&body); err != nil || string(body) != `{"finished": true}` {
		t.Fatal("confirmed publication unavailable", err)
	}
	if err := outbox.QueryRow(ctx, finish, finishArgs...).Scan(&body); err != nil {
		t.Fatal("lost publish checkpoint replay unavailable", err)
	}
	badAck[8] = "sha256:" + strings.Repeat("b", 64)
	if err := outbox.QueryRow(ctx, finish, badAck...).Scan(&body); auditExportSQLState(err) != "23505" {
		t.Fatal("changed confirmed acknowledgement accepted", err)
	}
	if err := outbox.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil || string(body) != "[]" {
		t.Fatal("confirmed publication was leased again", err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT o.state='published' AND o.generation=2 AND o.attempt=2 AND j.status='queued' AND j.attempt=0 AND j.completion_audit_id IS NULL FROM zasp_audit_export_outbox o JOIN zasp_audit_export_jobs j ON j.organization_id=o.organization_id AND j.id=o.export_id WHERE o.organization_id=$1 AND o.id=$2`, request[0], request[9]).Scan(&exact); err != nil || !exact {
		t.Fatal("publication pretended executor completion", err)
	}
	var before, after string
	snapshot := `SELECT jsonb_build_object('outbox',to_jsonb(o),'job',(SELECT to_jsonb(j) FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$3))::text FROM zasp_audit_export_outbox o WHERE organization_id=$1 AND id=$2`
	if err := f.admin.QueryRow(ctx, snapshot, request[0], request[9], request[7]).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		index int
		value any
	}{{4, "different-publisher"}, {5, strings.Repeat("f", 64)}, {6, int64(1)}, {7, 1}} {
		bad := append([]any(nil), finishArgs...)
		bad[change.index] = change.value
		if err := outbox.QueryRow(ctx, finish, bad...).Scan(&body); auditExportSQLState(err) != "42501" {
			t.Fatal("changed published replay authority accepted", err)
		}
	}
	if _, err := outbox.Exec(ctx, `SELECT * FROM zasp_audit_export_outbox`); auditExportSQLState(err) != "42501" {
		t.Fatal("publisher can read raw outbox tokens", err)
	}
	for _, statement := range []string{`UPDATE zasp_audit_export_outbox SET provider_message_id='sha256:'||repeat('b',64)`, `DELETE FROM zasp_audit_export_outbox`} {
		if _, err := f.admin.Exec(ctx, statement); auditExportSQLState(err) != "42501" {
			t.Fatal("published outbox was mutable", err)
		}
	}
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err == nil {
		t.Fatal("Down discarded published authority")
	}
	if err := f.admin.QueryRow(ctx, snapshot, request[0], request[9], request[7]).Scan(&after); err != nil || before != after {
		t.Fatal("refused published mutation/Down changed evidence", err)
	}
}

func TestAuditExportPostgresOutboxConcurrentBoundedPolicyClaims(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	_, outbox := auditExportWorkerConnections(t, ctx, f)
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	policy := auditExportTestPolicy()
	oldPolicy := policy.PolicyID
	policy.ExpectedCurrentPolicyID = oldPolicy
	policy.PolicyID = "pid_52000081-0000-4000-8000-000000000081"
	policy.MaximumInflight = 4
	auditExportConfigureSQL(t, ctx, f.admin, policy)
	for index := 0; index < 2; index++ {
		args := f.createArgs()
		args[6] = fmt.Sprintf("audit-export-publish-batch-%d", index)
		for field := 7; field <= 9; field++ {
			args[field] = fmt.Sprintf("pid_52000082-0000-4000-8000-%012d", index*3+field)
		}
		if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); err != nil {
			t.Fatal(err)
		}
	}
	second, err := pgx.ConnectConfig(ctx, outbox.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = second.Close(cleanup)
	})
	transaction, err := outbox.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = transaction.Rollback(cleanup)
	})
	claim := `SELECT zasp_audit_export_claim_outbox($1,$2,$3,$4,$5,$6)`
	if err := transaction.QueryRow(ctx, claim, "first-publisher", strings.Repeat("d", 64), 180, 2, request[11], request[12]).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var first, other []auditExportOutboxSQLLease
	if json.Unmarshal(body, &first) != nil || len(first) != 2 {
		t.Fatal("first batch exceeded or missed its requested bound")
	}
	bounded, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := second.QueryRow(bounded, claim, "second-publisher", strings.Repeat("e", 64), 180, 2, request[11], request[12]).Scan(&body); err != nil {
		t.Fatal("second publisher waited on leased rows instead of skipping", err)
	}
	if json.Unmarshal(body, &other) != nil || len(other) != 1 {
		t.Fatal("second claim duplicated locked leases or missed pending work")
	}
	seen := map[string]bool{}
	for _, lease := range append(first, other...) {
		if seen[lease.OutboxID] || lease.Attempt != 1 || lease.Generation != 1 {
			t.Fatal("concurrent publishers duplicated or consumed attempts")
		}
		seen[lease.OutboxID] = true
		want := policy.PolicyID
		if lease.ExportID == request[7] {
			want = oldPolicy
		}
		if lease.PolicyID != want {
			t.Fatal("outbox hint rebound retained job policy")
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT count(*)=3 AND bool_and(status='queued' AND attempt=0 AND completion_audit_id IS NULL) FROM zasp_audit_export_jobs`).Scan(&exact); err != nil || !exact {
		t.Fatal("publish claims changed executor jobs", err)
	}
}

func TestAuditExportPostgresOutboxPostWaitLossIsAtomic(t *testing.T) {
	for _, mode := range []string{"claim-drift", "finish-drift", "finish-expiry", "retry-drift", "retry-expiry", "published-replay-drift", "retry-replay-drift"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			_, outbox := auditExportWorkerConnections(t, ctx, f)
			request := f.createArgs()
			var body []byte
			if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			claim := `SELECT zasp_audit_export_claim_outbox($1,$2,$3,$4,$5,$6)`
			claimArgs := []any{"audit-export-publisher", strings.Repeat("d", 64), 180, 1, request[11], request[12]}
			statement, args := claim, claimArgs
			if mode != "claim-drift" {
				if err := outbox.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil {
					t.Fatal(err)
				}
				statement = `SELECT zasp_audit_export_finish_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
				args = []any{request[0], request[1], request[2], request[9], claimArgs[0], claimArgs[1], int64(1), 1, "sha256:" + strings.Repeat("a", 64), request[11], request[12]}
				if strings.HasPrefix(mode, "retry-") {
					statement = `SELECT zasp_audit_export_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
					args[8] = 60
				}
				if mode == "published-replay-drift" || mode == "retry-replay-drift" {
					if err := outbox.QueryRow(ctx, statement, args...).Scan(&body); err != nil {
						t.Fatal(err)
					}
				}
			}
			if strings.HasSuffix(mode, "expiry") {
				if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_outbox SET lease_expires_at=clock_timestamp()+interval '10 seconds' WHERE organization_id=$1 AND id=$2`, request[0], request[9]); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				var value string
				if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('outbox',to_jsonb(o),'job',(SELECT to_jsonb(j) FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$3),'completion',(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'))::text FROM zasp_audit_export_outbox o WHERE organization_id=$1 AND id=$2`, request[0], request[9], request[7]).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			f.api = outbox
			lock := "LOCK TABLE zasp_audit_export_outbox IN SHARE MODE"
			var lockArgs []any
			if mode == "published-replay-drift" || mode == "retry-replay-drift" {
				lock = `SELECT 1 FROM zasp_audit_export_outbox WHERE organization_id=$1 AND id=$2 FOR UPDATE`
				lockArgs = []any{request[0], request[9]}
			}
			err := auditExportBlockedCall(t, ctx, f, statement, args, lock, lockArgs, func(tx pgx.Tx) error {
				if strings.HasSuffix(mode, "expiry") {
					_, err := tx.Exec(ctx, `SELECT pg_sleep(11)`)
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
				return err
			})
			want := "55000"
			if strings.HasSuffix(mode, "expiry") {
				want = "42501"
			}
			if auditExportSQLState(err) != want || snapshot() != before {
				t.Fatal("outbox postwait operation accepted lost authority or changed evidence", err)
			}
		})
	}
}

func TestAuditExportPostgresOutboxNeverLifetimeExhausts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	_, outbox := auditExportWorkerConnections(t, ctx, f)
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	claim := `SELECT zasp_audit_export_claim_outbox($1,$2,$3,$4,$5,$6)`
	claimArgs := []any{"audit-export-publisher", strings.Repeat("d", 64), 180, 1, request[11], request[12]}
	for generation := int64(1); generation <= 103; generation++ {
		if err := outbox.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil {
			t.Fatal("durable outbox claim unavailable", err)
		}
		var leases []auditExportOutboxSQLLease
		attempt := int(generation)
		if attempt > 100 {
			attempt = 100
		}
		if json.Unmarshal(body, &leases) != nil || len(leases) != 1 || leases[0].Generation != generation || leases[0].Attempt != attempt {
			t.Fatal("publish retry exhausted or lost saturation fence", generation)
		}
		if generation%2 == 0 {
			if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_outbox SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[9]); err != nil {
				t.Fatal(err)
			}
		} else {
			args := []any{request[0], request[1], request[2], request[9], claimArgs[0], claimArgs[1], generation, attempt, 1, request[11], request[12]}
			if err := outbox.QueryRow(ctx, `SELECT zasp_audit_export_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, args...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[9]); err != nil {
				t.Fatal(err)
			}
		}
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT o.state='pending' AND o.generation=103 AND o.attempt=100 AND j.status='queued' AND j.attempt=0 AND j.completion_audit_id IS NULL FROM zasp_audit_export_outbox o JOIN zasp_audit_export_jobs j ON j.organization_id=o.organization_id AND j.id=o.export_id WHERE o.organization_id=$1 AND o.id=$2`, request[0], request[9]).Scan(&exact); err != nil || !exact {
		t.Fatal("uncertain publish stranded or terminal-failed export", err)
	}
}

func TestAuditExportPostgresRetryPreservesFrozenIssuedAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, outbox := auditExportWorkerConnections(t, ctx, f)
	request, common, manifest, canonical := auditExportCompletedChunks(t, ctx, f, worker, false)
	var body []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	retry := `SELECT zasp_audit_export_retry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	args := append(append([]any(nil), common...), 60, "execution_failed")
	if err := worker.QueryRow(ctx, retry, args...).Scan(&body); err != nil {
		t.Fatal("registered durable retry unavailable", err)
	}
	original := append([]byte(nil), body...)
	var response struct {
		State     string  `json:"state"`
		Failure   *string `json:"failure_code"`
		Available *string `json:"available_at"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &response) != nil || json.Unmarshal(body, &fields) != nil || len(fields) != 3 || response.State != "retry" || response.Failure != nil || response.Available == nil {
		t.Fatal("retry did not return bounded nonterminal availability")
	}
	available, err := time.Parse("2006-01-02T15:04:05.000000Z", *response.Available)
	if err != nil || time.Until(available) < 50*time.Second || time.Until(available) > 61*time.Second {
		t.Fatal("retry availability was not a fixed bounded deadline", err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT status='processing' AND captured AND generation=1 AND attempt=1 AND lease_worker IS NULL AND available_at=$3 AND reserved_bytes=$4 AND (SELECT count(*)=2 FROM zasp_audit_export_intents) AND (SELECT count(*)=1 FROM zasp_audit_export_receipts) AND (SELECT count(*)=0 FROM zasp_admin_audit WHERE action='audit_export.complete') FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7], available, manifest.ChunkBytes+int64(len(canonical))).Scan(&exact); err != nil || !exact {
		t.Fatal("retry lost frozen authority, reservation or execution budget", err)
	}
	if err := worker.QueryRow(ctx, retry, args...).Scan(&body); err != nil || !bytes.Equal(body, original) {
		t.Fatal("retry replay changed availability", err)
	}
	for _, bad := range []struct {
		index int
		value any
		state string
	}{{13, 61, "23505"}, {13, -1, "22023"}, {13, 301, "22023"}, {14, "invalid_source", "22023"}, {8, strings.Repeat("c", 64), "42501"}, {7, "another-export-worker", "42501"}} {
		changed := append([]any(nil), args...)
		changed[bad.index] = bad.value
		if err := worker.QueryRow(ctx, retry, changed...).Scan(&body); auditExportSQLState(err) != bad.state {
			t.Fatal("changed retry accepted", err)
		}
	}
	if _, err := outbox.Exec(ctx, retry, args...); auditExportSQLState(err) != "42501" {
		t.Fatal("outbox retried executor work", err)
	}
	claim := `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	claimArgs := []any{request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("c", 64), 180, common[9], common[10], common[11], common[12]}
	if err := worker.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil || string(body) != "null" {
		t.Fatal("retry backoff granted early lease", err)
	}
	if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1`, request[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil || string(body) == "null" {
		t.Fatal("scheduled retry could not reclaim", err)
	}
	next := append([]any(nil), common...)
	next[5], next[6], next[8] = int64(2), 2, strings.Repeat("c", 64)
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, next...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var progress map[string]any
	if json.Unmarshal(body, &progress) != nil || progress["event_count"] != float64(1) || progress["next_chunk"] != float64(2) || progress["chain_root"] != manifest.ChainRoot {
		t.Fatal("retry resnapshotted mutated live source")
	}
	if err := worker.QueryRow(ctx, retry, args...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("old attempt replay accepted after reclaim", err)
	}
	permanent := append(append([]any(nil), next...), 0, "execution_failed")
	if err := worker.QueryRow(ctx, retry, permanent...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	original = append([]byte(nil), body...)
	response.State = ""
	response.Available = nil
	if json.Unmarshal(body, &response) != nil || response.State != "failed" || response.Failure == nil || *response.Failure != "execution_failed" || response.Available != nil {
		t.Fatal("permanent retry did not return durable failed proof")
	}
	if err := worker.QueryRow(ctx, retry, permanent...).Scan(&body); err != nil || !bytes.Equal(body, original) {
		t.Fatal("permanent retry replay duplicated failure", err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT status='failed' AND failure_code='execution_failed' AND attempt=2 AND reserved_bytes=$3 AND (SELECT count(*)=1 FROM zasp_admin_audit WHERE action='audit_export.complete') AND (SELECT count(*)=1 FROM zasp_audit_export_receipts) FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7], manifest.ChunkBytes+int64(len(canonical))).Scan(&exact); err != nil || !exact {
		t.Fatal("permanent retry released ambiguous issued bytes or duplicated audit", err)
	}
	var before, after string
	snapshot := `SELECT jsonb_build_object('job',to_jsonb(j),'retries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY generation) FROM zasp_audit_export_retries r),'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY kind,ordinal) FROM zasp_audit_export_intents i))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`
	if err := f.admin.QueryRow(ctx, snapshot, request[0], request[7]).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Exec(ctx, `SELECT * FROM zasp_audit_export_retries`); auditExportSQLState(err) != "42501" {
		t.Fatal("executor can read raw retry tokens", err)
	}
	for _, statement := range []string{`UPDATE zasp_audit_export_retries SET retry_seconds=1`, `DELETE FROM zasp_audit_export_retries`} {
		if _, err := f.admin.Exec(ctx, statement); auditExportSQLState(err) != "42501" {
			t.Fatal("retry receipt mutation accepted", err)
		}
	}
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err == nil {
		t.Fatal("Down discarded retry evidence")
	}
	if err := f.admin.QueryRow(ctx, snapshot, request[0], request[7]).Scan(&after); err != nil || before != after {
		t.Fatal("refused mutation/Down changed retry evidence", err)
	}
}

func TestAuditExportPostgresRetrySerializesIssuedIntent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	_, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
	second, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = second.Close(closeContext)
	})
	child, stop := context.WithTimeout(ctx, 20*time.Second)
	transaction, err := worker.Begin(child)
	if err != nil {
		stop()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	started, settled := false, false
	t.Cleanup(func() {
		stop()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = transaction.Rollback(cleanup)
		if started && !settled {
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("retry contender did not join before connection cleanup")
			}
		}
	})
	prepare := `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	var body []byte
	if err := transaction.QueryRow(child, prepare, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	started = true
	go func() {
		var result []byte
		done <- second.QueryRow(child, `SELECT zasp_audit_export_retry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, append(append([]any(nil), common...), 0, "execution_failed")...).Scan(&result)
	}()
	for {
		var waiting bool
		if err := f.admin.QueryRow(child, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, second.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			settled = true
			t.Fatal("retry did not wait for issued intent transaction", err)
		case <-child.Done():
			t.Fatal(child.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := transaction.Commit(child); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		settled = true
		if err != nil {
			t.Fatal(err)
		}
	case <-child.Done():
		t.Fatal(child.Err())
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT status='failed' AND reserved_bytes=$3 AND (SELECT count(*)=1 FROM zasp_audit_export_intents) AND (SELECT count(*)=1 FROM zasp_audit_export_retries) AND (SELECT count(*)=1 FROM zasp_admin_audit WHERE action='audit_export.complete') FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7], len(canonical)).Scan(&exact); err != nil || !exact {
		t.Fatal("racing retry released committed issued bytes", err)
	}
	if err := worker.QueryRow(ctx, prepare, append(append([]any(nil), common...), canonical)...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("stale prepare escaped permanent retry fence", err)
	}
}

func TestAuditExportPostgresRetryPostWaitLossIsAtomic(t *testing.T) {
	for _, test := range []struct {
		name, table string
		seconds     int
	}{{"scheduled-job", "zasp_audit_export_jobs", 60}, {"scheduled-receipt", "zasp_audit_export_retries", 60}, {"failed-receipt", "zasp_audit_export_retries", 0}, {"failed-audit", "zasp_admin_audit", 0}} {
		for _, mode := range []string{"drift", "expiry"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				f := auditExportPGFixture(t, ctx)
				f.register(t, ctx)
				worker, _ := auditExportWorkerConnections(t, ctx, f)
				request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
				if mode == "expiry" {
					if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()+interval '10 seconds' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
						t.Fatal(err)
					}
				}
				snapshot := func() string {
					var value string
					if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'retries',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_audit_export_retries r),'completion',(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				before := snapshot()
				f.api = worker
				err := auditExportBlockedCall(t, ctx, f, `SELECT zasp_audit_export_retry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, append(append([]any(nil), common...), test.seconds, "execution_failed"), `LOCK TABLE `+test.table+` IN SHARE MODE`, nil, func(tx pgx.Tx) error {
					if mode == "drift" {
						_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
						return err
					}
					_, err := tx.Exec(ctx, `SELECT pg_sleep(11)`)
					return err
				})
				want := "55000"
				if mode == "expiry" {
					want = "42501"
				}
				if auditExportSQLState(err) != want || snapshot() != before {
					t.Fatal("retry wait persisted failure/backoff without current authority", err)
				}
			})
		}
	}
}

func TestAuditExportPostgresRetryExhaustsOnlyExecutionBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	var body []byte
	for attempt := 1; attempt <= 5; attempt++ {
		common[5], common[6] = int64(attempt), attempt
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_retry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, append(append([]any(nil), common...), 60, "execution_failed")...).Scan(&body); err != nil {
			t.Fatal("retry authority unavailable", err)
		}
		var result map[string]any
		if json.Unmarshal(body, &result) != nil || attempt < 5 && result["state"] != "retry" || attempt == 5 && result["state"] != "failed" {
			t.Fatal("retry execution budget changed")
		}
		if attempt < 5 {
			if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
				t.Fatal(err)
			}
		}
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, common[9], common[10], common[11], common[12]).Scan(&body); err != nil || attempt < 5 && string(body) == "null" || attempt == 5 && string(body) != "null" {
			t.Fatal("execution retry failed to reclaim or granted sixth attempt", err)
		}
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT status='failed' AND attempt=5 AND generation=5 AND NOT captured AND reserved_bytes=0 AND (SELECT count(*)=1 FROM zasp_admin_audit WHERE action='audit_export.complete') FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&exact); err != nil || !exact {
		t.Fatal("final retry stranded job or consumed unissued bytes", err)
	}
}

func auditExportCompletedChunks(t *testing.T, ctx context.Context, f auditExportPG, worker *pgx.Conn, empty bool) ([]any, []any, audit.ExportManifest, []byte) {
	t.Helper()
	request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	binding := audit.ExportBinding{OrganizationID: request[0].(string), WorkspaceID: request[1].(string), EnvironmentID: request[2].(string), ExportID: request[7].(string), CaptureID: common[4].(string)}
	manifest := audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, ChainRoot: audit.ExportZeroDigest}
	var body []byte
	if empty {
		if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1`, request[0]); err != nil {
			t.Fatal(err)
		}
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body); err != nil {
			t.Fatal(err)
		}
	} else {
		_, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
		sum := sha256.Sum256(canonical)
		manifest.EventCount, manifest.ChunkCount, manifest.ChunkBytes, manifest.ChainRoot = 1, 1, int64(len(canonical)), hex.EncodeToString(sum[:])
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_record_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, append(append([]any(nil), common...), int64(1), "owned-chunk-version", sum[:], int64(len(canonical)))...).Scan(&body); err != nil {
			t.Fatal(err)
		}
	}
	canonical, err := audit.EncodeExportManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return request, common, manifest, canonical
}

func TestAuditExportPostgresFinishesExactManifestAndReadsReady(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%t", empty), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, outbox := auditExportWorkerConnections(t, ctx, f)
			request, common, manifest, canonical := auditExportCompletedChunks(t, ctx, f, worker, empty)
			sum := sha256.Sum256(canonical)
			completionID := "pid_52000091-0000-4000-8000-000000000091"
			finish := `SELECT zasp_audit_export_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
			args := append(append([]any(nil), common...), "owned-manifest-version", sum[:], int64(len(canonical)), completionID)
			var body []byte
			if err := worker.QueryRow(ctx, finish, args...).Scan(&body); auditExportSQLState(err) != "42501" {
				t.Fatal("finish must refuse a missing expected manifest intent", err)
			}
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			for _, change := range []struct {
				index int
				value any
			}{{13, "null"}, {13, ""}, {13, strings.Repeat("x", 1025)}, {13, "version-é"}, {13, "version\n"}, {14, bytes.Repeat([]byte{1}, 32)}, {15, int64(len(canonical) + 1)}, {16, request[8]}} {
				bad := append([]any(nil), args...)
				bad[change.index] = change.value
				if err := worker.QueryRow(ctx, finish, bad...).Scan(&body); auditExportSQLState(err) != "22023" {
					t.Fatal("changed manifest receipt or aliased completion accepted", err)
				}
			}
			if err := worker.QueryRow(ctx, finish, args...).Scan(&body); err != nil {
				t.Fatal("registered manifest completion unavailable", err)
			}
			original := append([]byte(nil), body...)
			descriptor, err := audit.DecodeExportDescriptor(body)
			if err != nil || descriptor.Status != "ready" || descriptor.ID != manifest.Binding.ExportID || descriptor.AuditCorrelationID != request[8] || descriptor.ManifestSHA256 != hex.EncodeToString(sum[:]) || descriptor.EventCount == nil || *descriptor.EventCount != manifest.EventCount || descriptor.ChunkCount == nil || *descriptor.ChunkCount != manifest.ChunkCount || descriptor.ChunkBytes == nil || *descriptor.ChunkBytes != manifest.ChunkBytes {
				t.Fatal("ready descriptor lost canonical frozen totals", err)
			}
			snapshot := func() string {
				var value string
				if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY kind,ordinal) FROM zasp_audit_export_intents i),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY kind,ordinal) FROM zasp_audit_export_receipts r),'completion',(SELECT jsonb_agg(to_jsonb(a)) FROM zasp_admin_audit a WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			if err := worker.QueryRow(ctx, finish, args...).Scan(&body); err != nil || !bytes.Equal(body, original) {
				t.Fatal("lost finish response replay changed descriptor", err)
			}
			for _, change := range []struct {
				index int
				value any
				state string
			}{{13, "changed-version", "23505"}, {16, "pid_52000092-0000-4000-8000-000000000092", "23505"}, {8, strings.Repeat("c", 64), "42501"}, {5, int64(2), "42501"}, {7, "different-export-worker", "42501"}, {4, "pid_52000093-0000-4000-8000-000000000093", "42501"}, {6, 2, "42501"}} {
				bad := append([]any(nil), args...)
				bad[change.index] = change.value
				if err := worker.QueryRow(ctx, finish, bad...).Scan(&body); auditExportSQLState(err) != change.state {
					t.Fatal("changed or stale ready replay accepted", err)
				}
			}
			if _, err := outbox.Exec(ctx, finish, args...); auditExportSQLState(err) != "42501" {
				t.Fatal("outbox completed executor work", err)
			}
			if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil || !bytes.Equal(body, original) {
				t.Fatal("original create replay did not return durable ready state", err)
			}
			database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
			if err != nil {
				t.Fatal(err)
			}
			repository, err := NewAuditExportRepository(database)
			if err != nil {
				t.Fatal(err)
			}
			identity := f.identity
			identity.Permissions = []string{"view", "view_audit"}
			read, err := repository.Get(ctx, identity, AuditExportRead{ExportID: descriptor.ID, SessionDigest: f.digest[:], ChunkOrdinal: 1})
			if err != nil || read.authority == nil || read.authority.Binding != manifest.Binding || read.authority.Manifest.VersionID != "owned-manifest-version" || read.authority.Manifest.SHA256 != descriptor.ManifestSHA256 || read.authority.Manifest.SizeBytes != int64(len(canonical)) || (read.authority.Chunk == nil) != empty {
				t.Fatal("actual Go ready Get lost exact immutable receipt authority", err)
			}
			if !empty && (read.authority.Chunk.VersionID != "owned-chunk-version" || read.authority.Chunk.Ordinal != 1 || read.authority.Chunk.SHA256 != manifest.ChainRoot) {
				t.Fatal("ready chunk receipt changed")
			}
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`, request[0], request[1], request[2], request[7], common[9], common[10], common[11], common[12]).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var terminal struct {
				State  string          `json:"state"`
				Export json.RawMessage `json:"export"`
			}
			if json.Unmarshal(body, &terminal) != nil || terminal.State != "ready" || !bytes.Equal(terminal.Export, original) {
				t.Fatal("terminal duplicate wakeup lost ready proof")
			}
			var exact bool
			if err := f.admin.QueryRow(ctx, `SELECT status='ready' AND completion_audit_id=$3 AND lease_worker IS NULL AND reserved_bytes=chunk_bytes+octet_length(manifest_bytes) AND (SELECT count(*)=1 AND bool_and(version_id='owned-manifest-version' AND sha256=$4 AND size_bytes=$5) FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2 AND kind='manifest') AND (SELECT count(*)=1 AND bool_and(id=$3 AND actor_id=j.principal_id AND workspace_id=j.workspace_id AND environment_id=j.environment_id AND outcome='succeeded' AND occurred_at=j.completed_at AND metadata=jsonb_build_object('event_count',j.event_count,'chunk_count',j.chunk_count,'chunk_bytes',j.chunk_bytes,'manifest_sha256',encode($4::bytea,'hex'))) FROM zasp_admin_audit WHERE organization_id=$1 AND target_id=$2 AND action='audit_export.complete') FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7], completionID, sum[:], len(canonical)).Scan(&exact); err != nil || !exact {
				t.Fatal("ready transaction lost receipt/quota/completion audit", err)
			}
			if snapshot() != before {
				t.Fatal("ready replay/read changed persisted evidence")
			}
			if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET metadata='{}' WHERE organization_id=$1 AND id=$2`, request[0], completionID); auditExportSQLState(err) != "42501" {
				t.Fatal("completion audit mutation accepted", err)
			}
			if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1 AND action<>'audit_export.complete'`, request[0]); err != nil {
				t.Fatal(err)
			}
			afterSource, err := repository.Get(ctx, identity, AuditExportRead{ExportID: descriptor.ID, SessionDigest: f.digest[:], ChunkOrdinal: 1})
			if err != nil || afterSource.authority == nil || afterSource.authority.Manifest != read.authority.Manifest || afterSource.authority.Binding != manifest.Binding {
				t.Fatal("ready read depended on mutable live audit source", err)
			}
			workspace, environment := "pid_52000021-0000-4000-8000-000000000021", "pid_52000022-0000-4000-8000-000000000022"
			if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(organization_id,principal_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$3,$4,'Another current scope','["view_audit"]')`, request[0], request[3], workspace, environment); err != nil {
				t.Fatal(err)
			}
			if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET workspace_id=$2,environment_id=$3,authenticated_at=clock_timestamp()-interval '1 hour' WHERE token_digest=$1`, f.digest[:], workspace, environment); err != nil {
				t.Fatal(err)
			}
			readArgs := []any{request[0], workspace, environment, request[3], request[4], request[5], request[7], int64(1), nil, request[11], request[12]}
			if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, readArgs...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var scoped struct {
				Export    AuditExportDescriptor    `json:"export"`
				Authority auditExportReadAuthority `json:"authority"`
			}
			if json.Unmarshal(body, &scoped) != nil || scoped.Authority.Binding != manifest.Binding || scoped.Authority.Manifest != read.authority.Manifest || scoped.Export.WorkspaceID != request[1] || scoped.Export.EnvironmentID != request[2] {
				t.Fatal("current selected scope rebound retained ready artifact")
			}
			if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:]); err != nil {
				t.Fatal(err)
			}
			if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, readArgs...).Scan(&body); auditExportSQLState(err) != "28000" {
				t.Fatal("revoked session read retained ready contents", err)
			}
			if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err == nil || snapshot() != before {
				t.Fatal("Down erased or changed ready authority", err)
			}
		})
	}
}

func TestAuditExportPostgresReadyReplayRechecksPostWaitAuthority(t *testing.T) {
	for _, mode := range []string{"get-drift", "get-scope-revoked", "finish-replay-drift", "terminal-drift"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			request, common, _, canonical := auditExportCompletedChunks(t, ctx, f, worker, false)
			var body []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(canonical)
			finish := `SELECT zasp_audit_export_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
			finishArgs := append(append([]any(nil), common...), "owned-manifest-version", sum[:], int64(len(canonical)), "pid_52000091-0000-4000-8000-000000000091")
			if err := worker.QueryRow(ctx, finish, finishArgs...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var before, after string
			snapshot := `SELECT jsonb_build_object('job',to_jsonb(j),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY kind,ordinal) FROM zasp_audit_export_receipts r),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM zasp_admin_audit a WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`
			if err := f.admin.QueryRow(ctx, snapshot, request[0], request[7]).Scan(&before); err != nil {
				t.Fatal(err)
			}
			statement := postgresAuditExportGetSQL
			args := []any{request[0], request[1], request[2], request[3], request[4], request[5], request[7], int64(1), nil, request[11], request[12]}
			if mode == "finish-replay-drift" {
				statement, args, f.api = finish, finishArgs, worker
			}
			if mode == "terminal-drift" {
				statement, f.api = `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`, worker
				args = []any{request[0], request[1], request[2], request[7], common[9], common[10], common[11], common[12]}
			}
			err := auditExportBlockedCall(t, ctx, f, statement, args, `SELECT 1 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2 FOR UPDATE`, []any{request[0], request[7]}, func(tx pgx.Tx) error {
				if mode == "get-scope-revoked" {
					_, err := tx.Exec(ctx, `DELETE FROM zasp_authorized_scopes WHERE organization_id=$1 AND principal_id=$2`, request[0], request[3])
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
				return err
			})
			want := "55000"
			if mode == "get-scope-revoked" {
				want = "42501"
			}
			if auditExportSQLState(err) != want {
				t.Fatal("ready replay/read accepted changed authority after wait", err)
			}
			if err := f.admin.QueryRow(ctx, snapshot, request[0], request[7]).Scan(&after); err != nil || after != before {
				t.Fatal("refused ready operation changed immutable evidence", err)
			}
		})
	}
}

func TestAuditExportPostgresFinishPostWaitLossIsAtomic(t *testing.T) {
	for _, table := range []string{"zasp_audit_export_receipts", "zasp_audit_export_jobs", "zasp_admin_audit"} {
		for _, mode := range []string{"drift", "expiry"} {
			t.Run(table+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				f := auditExportPGFixture(t, ctx)
				f.register(t, ctx)
				worker, _ := auditExportWorkerConnections(t, ctx, f)
				request, common, _, canonical := auditExportCompletedChunks(t, ctx, f, worker, false)
				var body []byte
				if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
					t.Fatal(err)
				}
				if mode == "expiry" {
					if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()+interval '10 seconds' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
						t.Fatal(err)
					}
				}
				snapshot := func() string {
					var value string
					if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY kind,ordinal) FROM zasp_audit_export_intents i),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY kind,ordinal) FROM zasp_audit_export_receipts r),'completion',(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				before := snapshot()
				sum := sha256.Sum256(canonical)
				args := append(append([]any(nil), common...), "owned-manifest-version", sum[:], int64(len(canonical)), "pid_52000091-0000-4000-8000-000000000091")
				f.api = worker
				err := auditExportBlockedCall(t, ctx, f, `SELECT zasp_audit_export_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, args, `LOCK TABLE `+table+` IN SHARE MODE`, nil, func(tx pgx.Tx) error {
					if mode == "drift" {
						_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
						return err
					}
					_, err := tx.Exec(ctx, `SELECT pg_sleep(11)`)
					return err
				})
				want := "55000"
				if mode == "expiry" {
					want = "42501"
				}
				if auditExportSQLState(err) != want || snapshot() != before {
					t.Fatal("finish wait committed partial ready/receipt/audit after authority loss", err)
				}
			})
		}
	}
}

func TestAuditExportPostgresPreparesManifestAfterExactCoverage(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%t", empty), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, outbox := auditExportWorkerConnections(t, ctx, f)
			policy := auditExportTestPolicy()
			request, common := auditExportClaimForCapture(t, ctx, f, worker, policy)
			binding := audit.ExportBinding{OrganizationID: request[0].(string), WorkspaceID: request[1].(string), EnvironmentID: request[2].(string), ExportID: request[7].(string), CaptureID: common[4].(string)}
			manifest := audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, ChainRoot: audit.ExportZeroDigest}
			var body, chunkBytes []byte
			if empty {
				// Owned source setup only: Capture itself must establish the empty
				// snapshot, header and quota; none of those successful rows are seeded.
				if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1`, request[0]); err != nil {
					t.Fatal(err)
				}
				if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body); err != nil {
					t.Fatal(err)
				}
			} else {
				_, chunkBytes = auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
				sum := sha256.Sum256(chunkBytes)
				manifest.EventCount, manifest.ChunkCount, manifest.ChunkBytes, manifest.ChainRoot = 1, 1, int64(len(chunkBytes)), hex.EncodeToString(sum[:])
			}
			canonical, err := audit.EncodeExportManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			prepare := `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
			args := append(append([]any(nil), common...), canonical)
			if !empty {
				if err := worker.QueryRow(ctx, prepare, args...).Scan(&body); auditExportSQLState(err) != "42501" {
					t.Fatal("manifest must refuse incomplete recorded coverage", err)
				}
				if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), chunkBytes)...).Scan(&body); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(chunkBytes)
				if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_record_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, append(append([]any(nil), common...), int64(1), "owned-chunk-version", sum[:], int64(len(chunkBytes)))...).Scan(&body); err != nil {
					t.Fatal(err)
				}
			}
			if err := worker.QueryRow(ctx, prepare, args...).Scan(&body); err != nil {
				t.Fatal("registered canonical manifest intent unavailable", err)
			}
			original := append([]byte(nil), body...)
			var intent struct {
				Binding         audit.ExportBinding `json:"binding"`
				Policy          map[string]any      `json:"storage_policy"`
				Kind            string              `json:"kind"`
				ArtifactID      string              `json:"artifact_id"`
				ObjectReference string              `json:"object_reference"`
				SHA256          string              `json:"sha256"`
				SizeBytes       int64               `json:"size_bytes"`
			}
			var fields map[string]json.RawMessage
			sum := sha256.Sum256(canonical)
			digest, _ := migrations.AuditExportPolicyDigest(policy)
			if err := json.Unmarshal(body, &intent); err != nil || json.Unmarshal(body, &fields) != nil || len(fields) != 7 || intent.Binding != binding || intent.Kind != "manifest" || intent.SHA256 != hex.EncodeToString(sum[:]) || intent.SizeBytes != int64(len(canonical)) || intent.Policy["policy_digest"] != digest {
				t.Fatal("manifest intent differs from independent codec totals", err)
			}
			if _, err := domain.ParseProductID(intent.ArtifactID); err != nil || intent.ArtifactID == binding.ExportID || intent.ArtifactID == binding.CaptureID || intent.ObjectReference != "s3://"+policy.Bucket+"/organizations/"+binding.OrganizationID+"/workspaces/"+binding.WorkspaceID+"/environments/"+binding.EnvironmentID+"/exports/"+intent.ArtifactID {
				t.Fatal("manifest locator did not use immutable policy and scope", err)
			}
			if err := worker.QueryRow(ctx, prepare, args...).Scan(&body); err != nil || !bytes.Equal(body, original) {
				t.Fatal("manifest replay changed intent", err)
			}
			for _, bad := range [][]byte{nil, append(append([]byte(nil), canonical...), '\n'), bytes.Replace(canonical, []byte(`"event_count":`), []byte(`"unknown_count":`), 1), bytes.Repeat([]byte("x"), 2049)} {
				if err := worker.QueryRow(ctx, prepare, append(append([]any(nil), common...), bad)...).Scan(&body); auditExportSQLState(err) != "22023" {
					t.Fatal("changed or oversized manifest accepted", err)
				}
			}
			if _, err := outbox.Exec(ctx, prepare, args...); auditExportSQLState(err) != "42501" {
				t.Fatal("outbox prepared final artifact", err)
			}
			var exact bool
			if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*)=1 AND bool_and(ordinal=0 AND sha256=$3 AND size_bytes=$4) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2 AND kind='manifest') AND (SELECT count(*)=0 FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2 AND kind='manifest') AND status='processing' AND reserved_bytes=$5 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, binding.OrganizationID, binding.ExportID, sum[:], len(canonical), len(canonical)+len(chunkBytes)).Scan(&exact); err != nil || !exact {
				t.Fatal("prepare changed completion or exact reserved authority", err)
			}
			if empty {
				for attempt := 1; attempt <= 5; attempt++ {
					if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
						t.Fatal(err)
					}
					if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, policy.PolicyID, common[10], request[11], request[12]).Scan(&body); err != nil {
						t.Fatal(err)
					}
				}
				if string(body) != "null" {
					t.Fatal("final attempt granted a sixth manifest lease")
				}
				if err := f.admin.QueryRow(ctx, `SELECT status='failed' AND reserved_bytes=$3 AND chunk_bytes=0 AND (SELECT count(*)=0 FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2) AND (SELECT count(*)=1 FROM zasp_admin_audit WHERE organization_id=$1 AND target_id=$2 AND action='audit_export.complete') FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7], len(canonical)).Scan(&exact); err != nil || !exact {
					t.Fatal("failure released an issued manifest without a receipt", err)
				}
				if err := worker.QueryRow(ctx, prepare, args...).Scan(&body); auditExportSQLState(err) != "42501" {
					t.Fatal("stale manifest prepare revived failed work", err)
				}
			}
		})
	}
}

func TestAuditExportPostgresPreparesOnlyFrozenChunkIntent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, outbox := auditExportWorkerConnections(t, ctx, f)
	policy := auditExportTestPolicy()
	request, common := auditExportClaimForCapture(t, ctx, f, worker, policy)
	chunk, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
	binding := chunk.Binding
	var body []byte
	prepare := `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	args := append(append([]any(nil), common...), canonical)
	if err := worker.QueryRow(ctx, prepare, args...).Scan(&body); err != nil {
		t.Fatal("registered pre-Put frozen intent unavailable", err)
	}
	original := append([]byte(nil), body...)
	var intent struct {
		Binding         audit.ExportBinding `json:"binding"`
		Policy          map[string]any      `json:"storage_policy"`
		Kind            string              `json:"kind"`
		Ordinal         int64               `json:"ordinal"`
		FirstEvent      int64               `json:"first_event"`
		EventCount      int64               `json:"event_count"`
		PreviousDigest  string              `json:"previous_digest"`
		ArtifactID      string              `json:"artifact_id"`
		ObjectReference string              `json:"object_reference"`
		SHA256          string              `json:"sha256"`
		SizeBytes       int64               `json:"size_bytes"`
	}
	var fields map[string]json.RawMessage
	sum := sha256.Sum256(canonical)
	digest, _ := migrations.AuditExportPolicyDigest(policy)
	if err := json.Unmarshal(body, &intent); err != nil || json.Unmarshal(body, &fields) != nil || len(fields) != 11 || intent.Binding != binding || intent.Kind != "chunk" || intent.Ordinal != 1 || intent.FirstEvent != 1 || intent.EventCount != 1 || intent.PreviousDigest != audit.ExportZeroDigest || intent.SHA256 != hex.EncodeToString(sum[:]) || intent.SizeBytes != int64(len(canonical)) || intent.Policy["policy_id"] != policy.PolicyID || intent.Policy["policy_digest"] != digest || intent.Policy["bucket"] != policy.Bucket {
		t.Fatal("prepared intent differs from independently encoded frozen source", err)
	}
	if _, err := domain.ParseProductID(intent.ArtifactID); err != nil || intent.ArtifactID == binding.ExportID || intent.ArtifactID == binding.CaptureID {
		t.Fatal("intent artifact identity is not independent", err)
	}
	wantReference := "s3://" + policy.Bucket + "/organizations/" + binding.OrganizationID + "/workspaces/" + binding.WorkspaceID + "/environments/" + binding.EnvironmentID + "/exports/" + intent.ArtifactID
	if intent.ObjectReference != wantReference {
		t.Fatal("intent did not use trusted immutable export profile")
	}
	if err := worker.QueryRow(ctx, prepare, args...).Scan(&body); err != nil || !bytes.Equal(body, original) {
		t.Fatal("exact intent replay changed expected object", err)
	}
	before := func() string {
		t.Helper()
		var value string
		if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY ordinal) FROM zasp_audit_export_intents i WHERE organization_id=$1 AND export_id=$2))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, binding.OrganizationID, binding.ExportID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	snapshot := before()
	for _, bad := range [][]byte{append(append([]byte(nil), canonical...), '\n'), bytes.Replace(canonical, []byte(`"ordinal":1`), []byte(`"ordinal":2`), 1), bytes.Replace(canonical, []byte(`"outcome":"succeeded"`), []byte(`"outcome":"denied"`), 1), bytes.Repeat([]byte("x"), 1048577)} {
		changed := append(append([]any(nil), common...), bad)
		if err := worker.QueryRow(ctx, prepare, changed...).Scan(&body); auditExportSQLState(err) != "22023" {
			t.Fatal("noncanonical or non-frozen intent accepted", err)
		}
	}
	if _, err := outbox.Exec(ctx, prepare, args...); auditExportSQLState(err) != "42501" {
		t.Fatal("outbox prepared an executor artifact", err)
	}
	if before() != snapshot {
		t.Fatal("refused intent changed durable authority")
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(kind='chunk' AND ordinal=1 AND artifact_id=$3 AND object_reference=$4 AND sha256=$5 AND size_bytes=$6) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2`, binding.OrganizationID, binding.ExportID, intent.ArtifactID, wantReference, sum[:], len(canonical)).Scan(&exact); err != nil || !exact {
		t.Fatal("pre-Put expected authority was not durably exact", err)
	}
	t.Run("issued-without-receipt-remains-retained-after-failure", func(t *testing.T) {
		// An issued intent may already have saved provider bytes even when no
		// receipt exists. Exhaustion can release the never-issued manifest only.
		for attempt := 1; attempt <= 5; attempt++ {
			if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, binding.OrganizationID, binding.ExportID); err != nil {
				t.Fatal(err)
			}
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, policy.PolicyID, common[10], request[11], request[12]).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if attempt < 5 && string(body) == "null" || attempt == 5 && string(body) != "null" {
				t.Fatal("execution attempt budget changed")
			}
		}
		if err := f.admin.QueryRow(ctx, `SELECT status='failed' AND failure_code='execution_failed' AND captured AND reserved_bytes=$3 AND reserved_bytes<chunk_bytes+octet_length(manifest_bytes) AND (SELECT count(*) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2)=1 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, binding.OrganizationID, binding.ExportID, len(canonical)).Scan(&exact); err != nil || !exact {
			t.Fatal("failure released issued ambiguous bytes or retained unissued manifest", err)
		}
		afterFailure := before()
		if err := worker.QueryRow(ctx, prepare, args...).Scan(&body); auditExportSQLState(err) != "42501" {
			t.Fatal("stale prepare after failure accepted", err)
		}
		if before() != afterFailure {
			t.Fatal("stale prepare changed retained failed authority")
		}
		rotated := policy
		rotated.ExpectedCurrentPolicyID = policy.PolicyID
		rotated.PolicyID = "pid_52000080-0000-4000-8000-000000000080"
		rotated.MaximumRetainedBytes = int64(len(canonical))
		rotated.MaximumInflight = 1
		auditExportConfigureSQL(t, ctx, f.admin, rotated)
		later := f.createArgs()
		later[6] = "audit-export-retained-old-intent"
		later[7] = "pid_52000081-0000-4000-8000-000000000081"
		later[8] = "pid_52000082-0000-4000-8000-000000000082"
		later[9] = "pid_52000083-0000-4000-8000-000000000083"
		if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, later...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		var descriptor map[string]any
		if err := json.Unmarshal(body, &descriptor); err != nil || descriptor["status"] != "failed" || descriptor["failure_code"] != "capacity_exceeded" {
			t.Fatal("new policy forgot retained old failed intent", err)
		}
		rotated.ExpectedCurrentPolicyID = rotated.PolicyID
		rotated.PolicyID = "pid_52000084-0000-4000-8000-000000000084"
		rotated.MaximumRetainedBytes++
		auditExportConfigureSQL(t, ctx, f.admin, rotated)
		later[6] = "audit-export-failed-not-inflight"
		later[7] = "pid_52000085-0000-4000-8000-000000000085"
		later[8] = "pid_52000086-0000-4000-8000-000000000086"
		later[9] = "pid_52000087-0000-4000-8000-000000000087"
		if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, later...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &descriptor); err != nil || descriptor["status"] != "queued" {
			t.Fatal("failed historical jobs consumed inflight admission", err)
		}
		if err := f.admin.QueryRow(ctx, `SELECT status='failed' AND reserved_bytes=$3 AND policy_id=$4 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, binding.OrganizationID, binding.ExportID, len(canonical), policy.PolicyID).Scan(&exact); err != nil || !exact {
			t.Fatal("rotation changed retained failed job policy or bytes", err)
		}
	})
}

func TestAuditExportPostgresManifestPostWaitLossIsAtomic(t *testing.T) {
	for _, mode := range []string{"drift", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
			chunk, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
			sum := sha256.Sum256(canonical)
			var body []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_record_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, append(append([]any(nil), common...), int64(1), "owned-chunk-version", sum[:], int64(len(canonical)))...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			manifest, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: chunk.Binding, EventCount: 1, ChunkCount: 1, ChunkBytes: int64(len(canonical)), ChainRoot: hex.EncodeToString(sum[:])})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "expiry" {
				if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()+interval '10 seconds' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				var value string
				if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY kind,ordinal) FROM zasp_audit_export_intents i),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY kind,ordinal) FROM zasp_audit_export_receipts r),'completion',(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			f.api = worker
			err = auditExportBlockedCall(t, ctx, f, `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), manifest), `LOCK TABLE zasp_audit_export_intents IN SHARE MODE`, nil, func(tx pgx.Tx) error {
				if mode == "drift" {
					_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
					return err
				}
				_, err := tx.Exec(ctx, `SELECT pg_sleep(11)`)
				return err
			})
			want := "55000"
			if mode == "expiry" {
				want = "42501"
			}
			if auditExportSQLState(err) != want || snapshot() != before {
				t.Fatal("manifest wait accepted lost authority or persisted partial intent", err)
			}
		})
	}
}

func auditExportCaptureSingleRequest(t *testing.T, ctx context.Context, f auditExportPG, worker *pgx.Conn, request, common []any) (audit.ExportChunk, []byte) {
	t.Helper()
	var stamp time.Time
	if err := f.admin.QueryRow(ctx, `SELECT occurred_at FROM zasp_admin_audit WHERE organization_id=$1 AND id=$2`, request[0], request[8]).Scan(&stamp); err != nil {
		t.Fatal(err)
	}
	binding := audit.ExportBinding{OrganizationID: request[0].(string), WorkspaceID: request[1].(string), EnvironmentID: request[2].(string), ExportID: request[7].(string), CaptureID: common[4].(string)}
	chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: 1, FirstEvent: 1, EventCount: 1, PreviousDigest: audit.ExportZeroDigest, Events: []audit.ExportEvent{{Ordinal: 1, ID: request[8].(string), OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, ActorID: request[3].(string), Action: "audit_export.request", TargetID: binding.ExportID, Outcome: "succeeded", Metadata: map[string]string{}, OccurredAt: stamp.UTC().Format("2006-01-02T15:04:05.000000Z")}}}
	canonical, err := audit.EncodeExportChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return chunk, canonical
}

func TestAuditExportPostgresPreparePostWaitLossIsAtomic(t *testing.T) {
	for _, mode := range []string{"drift", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
			_, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
			if mode == "expiry" {
				if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()+interval '10 seconds' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				var value string
				if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'intents',(SELECT count(*) FROM zasp_audit_export_intents),'completion',(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			f.api = worker
			err := auditExportBlockedCall(t, ctx, f, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical), `LOCK TABLE zasp_audit_export_intents IN SHARE MODE`, nil, func(tx pgx.Tx) error {
				if mode == "drift" {
					_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
					return err
				}
				_, err := tx.Exec(ctx, `SELECT pg_sleep(11)`)
				return err
			})
			want := "55000"
			if mode == "expiry" {
				want = "42501"
			}
			if auditExportSQLState(err) != want {
				t.Fatal("prepare accepted post-insert-wait authority loss", err)
			}
			if snapshot() != before {
				t.Fatal("refused prepare left an issued intent or changed job")
			}
		})
	}
}

func TestAuditExportPostgresIssuedIntentSerializesWithFinalFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	policy := auditExportTestPolicy()
	request, common := auditExportClaimForCapture(t, ctx, f, worker, policy)
	_, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
	claim := `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	claimArgs := []any{request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, policy.PolicyID, common[10], request[11], request[12]}
	var body []byte
	for attempt := 1; attempt < 5; attempt++ {
		if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
			t.Fatal(err)
		}
		if err := worker.QueryRow(ctx, claim, claimArgs...).Scan(&body); err != nil || string(body) == "null" {
			t.Fatal("final lease fixture failed", err)
		}
	}
	common[5] = int64(5)
	common[6] = 5
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()+interval '10 seconds' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
		t.Fatal(err)
	}
	second, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	child, stop := context.WithTimeout(ctx, 25*time.Second)
	defer stop()
	first, err := worker.Begin(child)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(context.Background())
	prepare := `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	if err := first.QueryRow(child, prepare, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	settled := false
	defer func() {
		stop()
		_ = first.Rollback(context.Background())
		if !settled {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("final-failure child did not join")
			}
		}
	}()
	go func() {
		var value []byte
		err := second.QueryRow(child, claim, claimArgs...).Scan(&value)
		done <- result{value, err}
	}()
	for {
		var waiting bool
		if err := f.admin.QueryRow(child, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, second.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case value := <-done:
			settled = true
			t.Fatal("failure escaped uncommitted intent fence", value.err)
		case <-child.Done():
			t.Fatal("failure never reached organization fence")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// The prepared intent is real but its transaction is deliberately held.
	// Once the lease expires, recovery must see its committed bytes before failing.
	if _, err := f.admin.Exec(child, `SELECT pg_sleep(11)`); err != nil {
		t.Fatal(err)
	}
	if err := first.Commit(child); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-done:
		settled = true
		if value.err != nil || string(value.body) != "null" {
			t.Fatal("final failure did not settle after intent commit", value.err)
		}
	case <-child.Done():
		t.Fatal("final failure did not join")
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT status='failed' AND failure_code='execution_failed' AND attempt=5 AND generation=5 AND reserved_bytes=$3 AND (SELECT count(*) FROM zasp_audit_export_intents)=1 AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete')=1 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7], len(canonical)).Scan(&exact); err != nil || !exact {
		t.Fatal("concurrent failure lost issued-intent retained bytes", err)
	}
	if err := worker.QueryRow(ctx, prepare, append(append([]any(nil), common...), canonical)...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("late stale prepare changed failed job", err)
	}
}

func TestAuditExportPostgresRecordsExactChunkAndResumesPrefix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, outbox := auditExportWorkerConnections(t, ctx, f)
	policy := auditExportTestPolicy()
	request, common := auditExportClaimForCapture(t, ctx, f, worker, policy)
	_, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
	var body []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(canonical)
	record := `SELECT zasp_audit_export_record_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	args := append(append([]any(nil), common...), int64(1), "owned-sql-receipt-version", hash[:], int64(len(canonical)))
	if err := worker.QueryRow(ctx, record, args...).Scan(&body); err != nil {
		t.Fatal("registered exact chunk receipt unavailable", err)
	}
	if string(body) != `{"recorded": true}` {
		t.Fatal("receipt acknowledgement is not closed")
	}
	if err := worker.QueryRow(ctx, record, args...).Scan(&body); err != nil || string(body) != `{"recorded": true}` {
		t.Fatal("exact receipt replay failed", err)
	}
	for _, test := range []struct {
		index int
		value any
		state string
	}{{14, "changed-version", "23505"}, {14, "null", "22023"}, {14, "", "22023"}, {14, strings.Repeat("x", 1025), "22023"}, {14, "version-\u00e9", "22023"}, {14, "version\n", "22023"}, {15, bytes.Repeat([]byte{1}, 32), "22023"}, {16, int64(len(canonical) + 1), "22023"}, {13, int64(2), "42501"}, {5, int64(2), "42501"}} {
		bad := append([]any(nil), args...)
		bad[test.index] = test.value
		if err := worker.QueryRow(ctx, record, bad...).Scan(&body); auditExportSQLState(err) != test.state {
			t.Fatal("changed receipt or lease accepted", test.index, err)
		}
	}
	if _, err := outbox.Exec(ctx, record, args...); auditExportSQLState(err) != "42501" {
		t.Fatal("outbox recorded executor receipt", err)
	}
	if _, err := worker.Exec(ctx, `SELECT * FROM zasp_audit_export_receipts`); auditExportSQLState(err) != "42501" {
		t.Fatal("worker directly read private receipt table", err)
	}
	for _, mutation := range []string{`UPDATE zasp_audit_export_receipts SET version_id='changed-owner-version'`, `DELETE FROM zasp_audit_export_receipts`} {
		if _, err := f.admin.Exec(ctx, mutation); auditExportSQLState(err) != "42501" {
			t.Fatal("retained receipt was mutable", err)
		}
	}
	// Replace source and the worker lease after the receipt commits. Resumption
	// must use the immutable receipt prefix, not recapture or a caller cursor.
	if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1`, request[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("c", 64), 180, policy.PolicyID, common[10], request[11], request[12]).Scan(&body); err != nil {
		t.Fatal(err)
	}
	common[5] = int64(2)
	common[6] = 2
	common[8] = strings.Repeat("c", 64)
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var progress map[string]any
	if err := json.Unmarshal(body, &progress); err != nil || progress["next_chunk"] != float64(2) || progress["next_event"] != float64(2) || progress["recorded_chunk_count"] != float64(1) || progress["recorded_chunk_bytes"] != float64(len(canonical)) || progress["previous_digest"] != hex.EncodeToString(hash[:]) || progress["chain_root"] != hex.EncodeToString(hash[:]) {
		t.Fatal("restart lost contiguous committed prefix", err)
	}
	if err := worker.QueryRow(ctx, record, args...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("stale receipt replay accepted after new lease", err)
	}
	resumed := append(append([]any(nil), common...), args[13:]...)
	if err := worker.QueryRow(ctx, record, resumed...).Scan(&body); err != nil || string(body) != `{"recorded": true}` {
		t.Fatal("fresh lease could not replay exact committed receipt", err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_receipts)=1 AND (SELECT version_id='owned-sql-receipt-version' AND sha256=$3 AND size_bytes=$4 FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2 AND kind='chunk' AND ordinal=1) AND (SELECT captured AND event_count=1 AND generation=2 AND attempt=2 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2)`, request[0], request[7], hash[:], len(canonical)).Scan(&exact); err != nil || !exact {
		t.Fatal("receipt replay changed persisted authority", err)
	}
	snapshot := func() string {
		var value string
		if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'receipts',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_audit_export_receipts r),'intents',(SELECT jsonb_agg(to_jsonb(i)) FROM zasp_audit_export_intents i),'release',(SELECT to_jsonb(v) FROM zasp_schema_versions v WHERE version=52))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	beforeDown := snapshot()
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err == nil {
		t.Fatal("Down discarded retained receipt")
	}
	if snapshot() != beforeDown {
		t.Fatal("refused Down changed receipt, intent, job or release")
	}
}

func TestAuditExportPostgresReceiptRequiresContiguousChunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT $1,$2,$3,'pid_53000000-0000-4000-8000-'||lpad(n::text,12,'0'),$4,'receipt.fixture','owned fixture','succeeded','{}','2020-01-01T00:00:00Z' FROM generate_series(1,1000)n`, request[0], request[1], request[2], request[3]); err != nil {
		t.Fatal(err)
	}
	var body []byte
	capture := `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	if err := worker.QueryRow(ctx, capture, common...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var chunks [2]audit.ExportChunk
	var encoded [2][]byte
	var hashes [2][32]byte
	for index, first := range []int64{1, 1001} {
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), first)...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &chunks[index]); err != nil {
			t.Fatal(err)
		}
		chunks[index].Schema = audit.ExportChunkSchema
		if chunks[index].Ordinal != int64(index+1) || chunks[index].FirstEvent != first || chunks[index].EventCount != []int64{1000, 1}[index] {
			t.Fatal("two-chunk fixture is not contiguous")
		}
		var err error
		encoded[index], err = audit.EncodeExportChunk(chunks[index])
		if err != nil {
			t.Fatal(err)
		}
		hashes[index] = sha256.Sum256(encoded[index])
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), encoded[index])...).Scan(&body); err != nil {
			t.Fatal(err)
		}
	}
	record := `SELECT zasp_audit_export_record_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	second := append(append([]any(nil), common...), int64(2), "owned-second-version", hashes[1][:], int64(len(encoded[1])))
	if err := worker.QueryRow(ctx, record, second...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("receipt gap accepted", err)
	}
	var count int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_audit_export_receipts`).Scan(&count); err != nil || count != 0 {
		t.Fatal("gap left a partial receipt", err)
	}
	manifest := audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: chunks[0].Binding, EventCount: 1001, ChunkCount: 2, ChunkBytes: int64(len(encoded[0]) + len(encoded[1])), ChainRoot: hex.EncodeToString(hashes[1][:])}
	manifestBytes, err := audit.EncodeExportManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	prepareManifest := `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	for index := range chunks {
		args := append(append([]any(nil), common...), int64(index+1), []string{"owned-first-version", "owned-second-version"}[index], hashes[index][:], int64(len(encoded[index])))
		if err := worker.QueryRow(ctx, record, args...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if err := worker.QueryRow(ctx, capture, common...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		var progress map[string]any
		if err := json.Unmarshal(body, &progress); err != nil {
			t.Fatal(err)
		}
		wantNext := int64(1001)
		wantBytes := int64(len(encoded[0]))
		if index == 1 {
			wantNext++
			wantBytes += int64(len(encoded[1]))
		}
		if progress["next_chunk"] != float64(index+2) || progress["next_event"] != float64(wantNext) || progress["recorded_chunk_count"] != float64(index+1) || progress["recorded_chunk_bytes"] != float64(wantBytes) || progress["previous_digest"] != hex.EncodeToString(hashes[index][:]) {
			t.Fatal("committed prefix advanced over a gap or wrong bytes")
		}
		err := worker.QueryRow(ctx, prepareManifest, append(append([]any(nil), common...), manifestBytes)...).Scan(&body)
		if index == 0 && auditExportSQLState(err) != "42501" || index == 1 && err != nil {
			t.Fatal("manifest accepted a partial prefix or refused full two-chunk coverage", err)
		}
	}
	manifestSum := sha256.Sum256(manifestBytes)
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, append(append([]any(nil), common...), "owned-manifest-version", manifestSum[:], int64(len(manifestBytes)), "pid_52000091-0000-4000-8000-000000000091")...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	readArgs := []any{request[0], request[1], request[2], request[3], request[4], request[5], request[7], int64(2), manifestSum[:], request[11], request[12]}
	if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, readArgs...).Scan(&body); err != nil {
		t.Fatal("ready second page unavailable", err)
	}
	var read struct {
		Export    AuditExportDescriptor    `json:"export"`
		Authority auditExportReadAuthority `json:"authority"`
	}
	if json.Unmarshal(body, &read) != nil || read.Authority.Chunk == nil || read.Authority.Chunk.Ordinal != 2 || read.Authority.Chunk.FirstEvent != 1001 || read.Authority.Chunk.EventCount != 1 || read.Authority.Chunk.PreviousDigest != hex.EncodeToString(hashes[0][:]) || read.Authority.Chunk.SHA256 != hex.EncodeToString(hashes[1][:]) || read.Authority.Chunk.VersionID != "owned-second-version" {
		t.Fatal("second page lost frozen receipt authority")
	}
	for _, change := range []struct {
		index int
		value any
	}{{8, nil}, {8, bytes.Repeat([]byte{1}, 32)}, {7, int64(3)}} {
		bad := append([]any(nil), readArgs...)
		bad[change.index] = change.value
		if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, bad...).Scan(&body); auditExportSQLState(err) != "22023" {
			t.Fatal("missing/changed manifest pin or beyond-end ordinal accepted", err)
		}
	}
}

func TestAuditExportPostgresRecordPostWaitLossIsAtomic(t *testing.T) {
	for _, mode := range []string{"drift", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
			_, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
			hash := sha256.Sum256(canonical)
			var body []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if mode == "expiry" {
				if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()+interval '10 seconds' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				var value string
				if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'intents',(SELECT jsonb_agg(to_jsonb(i)) FROM zasp_audit_export_intents i),'receipts',(SELECT count(*) FROM zasp_audit_export_receipts),'completion',(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			f.api = worker
			args := append(append([]any(nil), common...), int64(1), "owned-wait-version", hash[:], int64(len(canonical)))
			err := auditExportBlockedCall(t, ctx, f, `SELECT zasp_audit_export_record_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, args, `LOCK TABLE zasp_audit_export_receipts IN SHARE MODE`, nil, func(tx pgx.Tx) error {
				if mode == "drift" {
					_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
					return err
				}
				_, err := tx.Exec(ctx, `SELECT pg_sleep(11)`)
				return err
			})
			want := "55000"
			if mode == "expiry" {
				want = "42501"
			}
			if auditExportSQLState(err) != want {
				t.Fatal("record accepted post-insert-wait authority loss", err)
			}
			if snapshot() != before {
				t.Fatal("record refusal changed receipt, intent, quota or audit")
			}
		})
	}
}

func TestAuditExportPostgresClaimHeartbeatAndBusyTerminal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, outbox := auditExportWorkerConnections(t, ctx, f)
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	policy := auditExportTestPolicy()
	digest, _ := migrations.AuditExportPolicyDigest(policy)
	digestBytes, _ := hex.DecodeString(digest)
	claim := `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	args := []any{request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 120, policy.PolicyID, digestBytes, request[11], request[12]}
	if err := worker.QueryRow(ctx, claim, args...).Scan(&body); err != nil {
		t.Fatal("registered export claim unavailable", err)
	}
	var lease map[string]any
	if err := json.Unmarshal(body, &lease); err != nil || len(lease) != 12 || lease["organization_id"] != request[0] || lease["export_id"] != request[7] || lease["policy_id"] != policy.PolicyID || lease["policy_digest"] != digest || lease["generation"] != float64(1) || lease["attempt"] != float64(1) || lease["captured"] != false {
		t.Fatal("closed claim authority", err)
	}
	original := append([]byte(nil), body...)
	if err := worker.QueryRow(ctx, claim, args...).Scan(&body); err != nil || !bytes.Equal(body, original) {
		t.Fatal("same claim replay changed authority", err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := f.admin.QueryRow(ctx, `SELECT to_jsonb(j)::text FROM zasp_audit_export_jobs j WHERE id=$1`, request[7]).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	busy := append([]any(nil), args...)
	busy[5] = strings.Repeat("c", 64)
	if err := worker.QueryRow(ctx, claim, busy...).Scan(&body); err != nil || string(body) != "null" {
		t.Fatal("busy lease was reacquired", err)
	}
	terminal := `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`
	terminalArgs := []any{request[0], request[1], request[2], request[7], policy.PolicyID, digestBytes, request[11], request[12]}
	if err := worker.QueryRow(ctx, terminal, terminalArgs...).Scan(&body); err != nil || string(body) != `{"state": "nonterminal"}` {
		t.Fatal("busy claim null became ACK authority", err)
	}
	for _, test := range []struct {
		index int
		value any
		state string
	}{{2, "pid_52000071-0000-4000-8000-000000000071", "P0002"}, {7, "pid_52000072-0000-4000-8000-000000000072", "42501"}, {8, bytes.Repeat([]byte{1}, 32), "42501"}} {
		bad := append([]any(nil), args...)
		bad[test.index] = test.value
		if err := worker.QueryRow(ctx, claim, bad...).Scan(&body); auditExportSQLState(err) != test.state {
			t.Fatal("claim scope/policy mismatch accepted", err)
		}
	}
	if _, err := outbox.Exec(ctx, claim, args...); auditExportSQLState(err) != "42501" {
		t.Fatal("outbox acquired executor lease", err)
	}
	if snapshot() != before {
		t.Fatal("busy/wrong-authority claim changed attempts or job")
	}
	common := []any{request[0], request[1], request[2], request[7], lease["capture_id"], int64(1), 1, args[4], args[5], policy.PolicyID, digestBytes, request[11], request[12]}
	heartbeat := `SELECT zasp_audit_export_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	if err := worker.QueryRow(ctx, heartbeat, append(append([]any(nil), common...), 180)...).Scan(&body); err != nil {
		t.Fatal("worker heartbeat unavailable", err)
	}
	var renewed map[string]any
	if err := json.Unmarshal(body, &renewed); err != nil || renewed["capture_id"] != lease["capture_id"] || renewed["generation"] != lease["generation"] || renewed["attempt"] != lease["attempt"] {
		t.Fatal("heartbeat changed lease identity", err)
	}
	oldExpiry, err := time.Parse(time.RFC3339Nano, lease["lease_expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	newExpiry, err := time.Parse(time.RFC3339Nano, renewed["lease_expires_at"].(string))
	if err != nil || !newExpiry.After(oldExpiry) {
		t.Fatal("heartbeat did not extend confirmed lease", err)
	}
	before = snapshot()
	stale := append([]any(nil), common...)
	stale[5] = int64(2)
	if err := worker.QueryRow(ctx, heartbeat, append(stale, 180)...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("stale heartbeat accepted", err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, heartbeat, append(append([]any(nil), common...), 180)...).Scan(&body); auditExportSQLState(err) != "55000" {
		t.Fatal("heartbeat accepted release drift", err)
	}
	if snapshot() != before {
		t.Fatal("rejected heartbeat changed job authority")
	}
}

func TestAuditExportPostgresCreateCapacityIsDurableTerminal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	policy := auditExportTestPolicy()
	policy.ExpectedCurrentPolicyID = policy.PolicyID
	policy.PolicyID = "pid_52000080-0000-4000-8000-000000000080"
	policy.MaximumInflight = 1
	auditExportConfigureSQL(t, ctx, f.admin, policy)
	first := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, first...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	failed := append([]any(nil), first...)
	failed[6] = "audit-export-capacity-refusal"
	failed[7] = "pid_52000081-0000-4000-8000-000000000081"
	failed[8] = "pid_52000082-0000-4000-8000-000000000082"
	failed[9] = "pid_52000083-0000-4000-8000-000000000083"
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, failed...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var descriptor map[string]any
	if err := json.Unmarshal(body, &descriptor); err != nil || descriptor["status"] != "failed" || descriptor["failure_code"] != "capacity_exceeded" {
		t.Fatal("Create exceeded bounded inflight without durable failure", err)
	}
	original := append([]byte(nil), body...)
	var atomic bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_jobs)=2 AND (SELECT count(*) FROM zasp_audit_export_idempotency)=2 AND (SELECT count(*) FROM zasp_audit_export_outbox)=2 AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.request')=2 AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete')=1`).Scan(&atomic); err != nil || !atomic {
		t.Fatal("capacity refusal lost atomic request/wakeup/completion authority", err)
	}
	digest, _ := migrations.AuditExportPolicyDigest(policy)
	digestBytes, _ := hex.DecodeString(digest)
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`, failed[0], failed[1], failed[2], failed[7], policy.PolicyID, digestBytes, failed[11], failed[12]).Scan(&body); err != nil {
		t.Fatal("capacity failure has no terminal ACK proof", err)
	}
	var terminal struct {
		State  string          `json:"state"`
		Export json.RawMessage `json:"export"`
	}
	if err := json.Unmarshal(body, &terminal); err != nil || terminal.State != "failed" || !bytes.Equal(terminal.Export, original) {
		t.Fatal("terminal capacity proof differs", err)
	}
	newPolicy := policy
	newPolicy.ExpectedCurrentPolicyID = policy.PolicyID
	newPolicy.PolicyID = "pid_52000090-0000-4000-8000-000000000090"
	newPolicy.MaximumInflight = 2
	auditExportConfigureSQL(t, ctx, f.admin, newPolicy)
	third := append([]any(nil), first...)
	third[6] = "audit-export-capacity-after-rotation"
	third[7] = "pid_52000084-0000-4000-8000-000000000084"
	third[8] = "pid_52000085-0000-4000-8000-000000000085"
	third[9] = "pid_52000086-0000-4000-8000-000000000086"
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, third...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &descriptor); err != nil || descriptor["status"] != "queued" {
		t.Fatal("failed job was counted as inflight", err)
	}
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, failed...).Scan(&body); err != nil || !bytes.Equal(body, original) {
		t.Fatal("rotation revived failed idempotency key", err)
	}
	if _, err := f.api.Exec(ctx, `UPDATE zasp_admin_audit SET metadata='{}' WHERE organization_id=$1 AND target_id=$2 AND action='audit_export.complete'`, failed[0], failed[7]); auditExportSQLState(err) != "42501" {
		t.Fatal("legacy API changed retained completion audit", err)
	}
	if _, err := f.api.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1 AND target_id=$2 AND action='audit_export.complete'`, failed[0], failed[7]); auditExportSQLState(err) != "42501" {
		t.Fatal("legacy API deleted retained completion audit", err)
	}
	if _, err := f.api.Exec(ctx, `UPDATE zasp_admin_audit SET metadata='{"fixture":"unchanged legacy behavior"}' WHERE organization_id=$1 AND id=$2`, first[0], first[8]); err != nil {
		t.Fatal("completion fence changed unrelated legacy audit behavior", err)
	}
}

func TestAuditExportPostgresDistinctKeysSerializeCapacity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	policy := auditExportTestPolicy()
	policy.ExpectedCurrentPolicyID = policy.PolicyID
	policy.PolicyID = "pid_52000080-0000-4000-8000-000000000080"
	policy.MaximumInflight = 1
	auditExportConfigureSQL(t, ctx, f.admin, policy)
	second, err := pgx.ConnectConfig(ctx, f.api.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	child, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	firstTx, err := f.api.Begin(child)
	if err != nil {
		t.Fatal(err)
	}
	defer firstTx.Rollback(context.Background())
	first := f.createArgs()
	var body []byte
	if err := firstTx.QueryRow(child, postgresAuditExportCreateSQL, first...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var descriptor map[string]any
	if err := json.Unmarshal(body, &descriptor); err != nil || descriptor["status"] != "queued" {
		t.Fatal("first admission was not queued", err)
	}
	args := append([]any(nil), first...)
	args[6] = "audit-export-capacity-concurrent"
	args[7] = "pid_52000081-0000-4000-8000-000000000081"
	args[8] = "pid_52000082-0000-4000-8000-000000000082"
	args[9] = "pid_52000083-0000-4000-8000-000000000083"
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	settled := false
	defer func() {
		stop()
		_ = firstTx.Rollback(context.Background())
		if !settled {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("capacity admission child did not join")
			}
		}
	}()
	go func() {
		var value []byte
		err := second.QueryRow(child, postgresAuditExportCreateSQL, args...).Scan(&value)
		done <- result{value, err}
	}()
	for {
		var waiting bool
		if err := f.admin.QueryRow(child, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, second.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case value := <-done:
			settled = true
			t.Fatal("second key completed before first admission committed", value.err)
		case <-child.Done():
			t.Fatal("second admission never reached organization fence")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := firstTx.Commit(child); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-done:
		settled = true
		if value.err != nil {
			t.Fatal(value.err)
		}
		if err := json.Unmarshal(value.body, &descriptor); err != nil || descriptor["status"] != "failed" || descriptor["failure_code"] != "capacity_exceeded" {
			t.Fatal("concurrent key escaped inflight bound", err)
		}
	case <-child.Done():
		t.Fatal("second admission did not settle")
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_jobs WHERE status='queued')=1 AND (SELECT count(*) FROM zasp_audit_export_jobs WHERE status='failed' AND failure_code='capacity_exceeded')=1 AND (SELECT count(*) FROM zasp_audit_export_idempotency)=2 AND (SELECT count(*) FROM zasp_audit_export_outbox)=2 AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.request')=2 AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete')=1`).Scan(&exact); err != nil || !exact {
		t.Fatal("concurrent admission lost atomic authority", err)
	}
}

func TestAuditExportPostgresExpiredFinalLeaseBecomesDurableFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	policy := auditExportTestPolicy()
	digest, _ := migrations.AuditExportPolicyDigest(policy)
	digestBytes, _ := hex.DecodeString(digest)
	claim := `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	args := []any{request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 120, policy.PolicyID, digestBytes, request[11], request[12]}
	var captureID string
	for attempt := 1; attempt <= 5; attempt++ {
		if err := worker.QueryRow(ctx, claim, args...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		var lease map[string]any
		if err := json.Unmarshal(body, &lease); err != nil || lease["attempt"] != float64(attempt) || lease["generation"] != float64(attempt) {
			t.Fatal("expired lease did not advance once", err)
		}
		if attempt == 1 {
			captureID, _ = lease["capture_id"].(string)
		}
		if lease["capture_id"] != captureID {
			t.Fatal("retry changed capture identity")
		}
		if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
			t.Fatal(err)
		}
	}
	if err := worker.QueryRow(ctx, claim, args...).Scan(&body); err != nil || string(body) != "null" {
		t.Fatal("exhausted job received sixth lease", err)
	}
	terminal := `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`
	terminalArgs := []any{request[0], request[1], request[2], request[7], policy.PolicyID, digestBytes, request[11], request[12]}
	if err := worker.QueryRow(ctx, terminal, terminalArgs...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var result struct {
		State  string `json:"state"`
		Export struct {
			Status      string `json:"status"`
			FailureCode string `json:"failure_code"`
		} `json:"export"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.State != "failed" || result.Export.Status != "failed" || result.Export.FailureCode != "execution_failed" {
		t.Fatal("final expiry lacks durable terminal proof", err)
	}
	original := append([]byte(nil), body...)
	if err := worker.QueryRow(ctx, claim, args...).Scan(&body); err != nil || string(body) != "null" {
		t.Fatal("terminal replay changed job", err)
	}
	if err := worker.QueryRow(ctx, terminal, terminalArgs...).Scan(&body); err != nil || !bytes.Equal(original, body) {
		t.Fatal("terminal proof changed on replay", err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete')=1 AND (SELECT attempt=5 AND generation=5 AND completion_audit_id IS NOT NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2)`, request[0], request[7]).Scan(&exact); err != nil || !exact {
		t.Fatal("exhaustion changed attempts or duplicated completion", err)
	}
}

func TestAuditExportPostgresWorkerRefusesPostWaitChange(t *testing.T) {
	for _, mode := range []string{"claim-admission-drift", "claim-row-drift", "heartbeat-expired", "terminal-row-drift"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			request := f.createArgs()
			var body []byte
			if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			policy := auditExportTestPolicy()
			digest, _ := migrations.AuditExportPolicyDigest(policy)
			digestBytes, _ := hex.DecodeString(digest)
			statement := `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
			args := []any{request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 120, policy.PolicyID, digestBytes, request[11], request[12]}
			lock := `SELECT id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2 FOR UPDATE`
			lockArgs := []any{request[0], request[7]}
			if mode == "claim-admission-drift" {
				lock = `SELECT pg_advisory_xact_lock(hashtextextended('zasp-audit-export-admission|'||$1,0))`
				lockArgs = []any{request[0]}
			}
			if mode == "heartbeat-expired" {
				if err := worker.QueryRow(ctx, statement, args...).Scan(&body); err != nil {
					t.Fatal(err)
				}
				var lease map[string]any
				if err := json.Unmarshal(body, &lease); err != nil {
					t.Fatal(err)
				}
				statement = `SELECT zasp_audit_export_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
				args = []any{request[0], request[1], request[2], request[7], lease["capture_id"], int64(1), 1, "audit-export-worker", strings.Repeat("b", 64), policy.PolicyID, digestBytes, request[11], request[12], 180}
			}
			if mode == "terminal-row-drift" {
				statement = `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`
				args = []any{request[0], request[1], request[2], request[7], policy.PolicyID, digestBytes, request[11], request[12]}
			}
			snapshot := func() string {
				t.Helper()
				var value string
				if err := f.admin.QueryRow(ctx, `SELECT (to_jsonb(j)-'lease_expires_at')::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			f.api = worker
			err := auditExportBlockedCall(t, ctx, f, statement, args, lock, lockArgs, func(tx pgx.Tx) error {
				if mode == "heartbeat-expired" {
					_, err := tx.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[7])
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
				return err
			})
			want := "55000"
			if mode == "heartbeat-expired" {
				want = "42501"
			}
			if auditExportSQLState(err) != want {
				t.Fatal("worker accepted post-wait change", err)
			}
			if snapshot() != before {
				t.Fatal("refused worker changed durable job")
			}
		})
	}
}

func TestAuditExportPostgresTerminalRejectsUnprovenFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET status='failed',failure_code='execution_failed' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
		t.Fatal(err)
	}
	policy := auditExportTestPolicy()
	digest, _ := migrations.AuditExportPolicyDigest(policy)
	digestBytes, _ := hex.DecodeString(digest)
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`, request[0], request[1], request[2], request[7], policy.PolicyID, digestBytes, request[11], request[12]).Scan(&body); auditExportSQLState(err) != "55000" {
		t.Fatal("unproven failure became ACK authority", err)
	}
}

func TestAuditExportPostgresCaptureFreezesCompleteCanonicalSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT $1,$2,$3,'pid_53000000-0000-4000-8000-'||lpad(n::text,12,'0'),$4,'integration.webhook','owned fixture','rejected',jsonb_build_object('counter',n,'verified',true,'token','owned source secret','quote','<>&'), '2026-09-12T13:14:15.000123Z'::timestamptz FROM generate_series(1,1050)n`, request[0], "pid_53000001-0000-4000-8000-000000000001", "pid_53000002-0000-4000-8000-000000000002", request[3]); err != nil {
		t.Fatal(err)
	}
	// Freeze expectations independently from real source columns using the Go
	// public projection. No successful snapshot, plan, intent or receipt is seeded.
	rows, err := f.admin.Query(ctx, `SELECT id,organization_id,workspace_id,environment_id,actor_id,action,target_id,outcome,(SELECT COALESCE(jsonb_object_agg(key,value),'{}'::jsonb) FROM jsonb_each_text(a.metadata)),occurred_at FROM zasp_admin_audit a WHERE organization_id=$1 ORDER BY occurred_at DESC,id COLLATE "C" DESC`, request[0])
	if err != nil {
		t.Fatal(err)
	}
	var expected []audit.ExportEvent
	for rows.Next() {
		var event audit.ExportEvent
		var metadata []byte
		var stamp time.Time
		if err := rows.Scan(&event.ID, &event.OrganizationID, &event.WorkspaceID, &event.EnvironmentID, &event.ActorID, &event.Action, &event.TargetID, &event.Outcome, &metadata, &stamp); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		event.Ordinal = int64(len(expected) + 1)
		event.OccurredAt = stamp.UTC().Format("2006-01-02T15:04:05.000000Z")
		projected, err := audit.ProjectExportEvent(event)
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		expected = append(expected, projected)
	}
	rows.Close()
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	if len(expected) != 1051 {
		t.Fatal("source fixture count", len(expected))
	}
	policy := auditExportTestPolicy()
	digest, _ := migrations.AuditExportPolicyDigest(policy)
	digestBytes, _ := hex.DecodeString(digest)
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, policy.PolicyID, digestBytes, request[11], request[12]).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var lease map[string]any
	if err := json.Unmarshal(body, &lease); err != nil {
		t.Fatal(err)
	}
	common := []any{request[0], request[1], request[2], request[7], lease["capture_id"], int64(1), 1, "audit-export-worker", strings.Repeat("b", 64), policy.PolicyID, digestBytes, request[11], request[12]}
	capture := `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	if err := worker.QueryRow(ctx, capture, common...).Scan(&body); err != nil {
		t.Fatal("registered frozen capture unavailable", err)
	}
	original := append([]byte(nil), body...)
	var progress struct {
		State          string              `json:"state"`
		Captured       bool                `json:"captured"`
		Binding        audit.ExportBinding `json:"binding"`
		EventCount     int64               `json:"event_count"`
		ChunkCount     int64               `json:"chunk_count"`
		ChunkBytes     int64               `json:"chunk_bytes"`
		ChainRoot      string              `json:"chain_root"`
		NextChunk      int64               `json:"next_chunk"`
		NextEvent      int64               `json:"next_event"`
		RecordedCount  int64               `json:"recorded_chunk_count"`
		RecordedBytes  int64               `json:"recorded_chunk_bytes"`
		PreviousDigest string              `json:"previous_digest"`
	}
	if err := json.Unmarshal(body, &progress); err != nil || progress.State != "processing" || !progress.Captured || progress.EventCount != 1051 || progress.ChunkCount != 2 || progress.NextChunk != 1 || progress.NextEvent != 1 || progress.RecordedCount != 0 || progress.RecordedBytes != 0 || progress.PreviousDigest != audit.ExportZeroDigest {
		t.Fatal("capture did not freeze complete planned authority", err)
	}
	if progress.Binding != (audit.ExportBinding{OrganizationID: request[0].(string), WorkspaceID: request[1].(string), EnvironmentID: request[2].(string), ExportID: request[7].(string), CaptureID: lease["capture_id"].(string)}) {
		t.Fatal("capture substituted destination binding")
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET metadata=jsonb_build_object('counter',999) WHERE organization_id=$1`, request[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,'pid_53000000-0000-4000-8000-000000009999',$4,'late.backdated','owned fixture','succeeded','{}','2020-01-01T00:00:00Z')`, request[0], request[1], request[2], request[3]); err != nil {
		t.Fatal(err)
	}
	var next int64 = 1
	var chunkOrdinal int64 = 1
	var chunkBytes int64
	previous := audit.ExportZeroDigest
	for next <= int64(len(expected)) {
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), next)...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if len(body) > audit.ExportMaximumChunkBytes {
			t.Fatal("SQL frozen page exceeded wire bound")
		}
		var page struct {
			Binding        audit.ExportBinding `json:"binding"`
			Ordinal        int64               `json:"ordinal"`
			FirstEvent     int64               `json:"first_event"`
			EventCount     int64               `json:"event_count"`
			PreviousDigest string              `json:"previous_digest"`
			Events         []json.RawMessage   `json:"events"`
			NextEvent      *int64              `json:"next_event"`
		}
		if err := json.Unmarshal(body, &page); err != nil || page.Binding != progress.Binding || page.Ordinal != chunkOrdinal || page.FirstEvent != next || page.PreviousDigest != previous || page.EventCount != int64(len(page.Events)) || len(page.Events) < 1 || len(page.Events) > 1000 {
			t.Fatal("frozen page range or binding mismatch", err)
		}
		chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: page.Binding, Ordinal: page.Ordinal, FirstEvent: next, EventCount: page.EventCount, PreviousDigest: previous}
		for index, raw := range page.Events {
			event := expected[int(next)-1+index]
			canonical, err := audit.EncodeExportEvent(event)
			if err != nil || !bytes.Equal(raw, canonical) {
				t.Fatal("capture changed, omitted, reordered or re-read source event", next+int64(index), err)
			}
			chunk.Events = append(chunk.Events, event)
		}
		canonical, err := audit.EncodeExportChunk(chunk)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		previous = hex.EncodeToString(sum[:])
		chunkBytes += int64(len(canonical))
		next += page.EventCount
		chunkOrdinal++
		if next <= int64(len(expected)) {
			if page.NextEvent == nil || *page.NextEvent != next {
				t.Fatal("frozen page skipped next event")
			}
		} else if page.NextEvent != nil {
			t.Fatal("frozen page invented trailing events")
		}
	}
	if chunkBytes != progress.ChunkBytes || previous != progress.ChainRoot {
		t.Fatal("SQL plan differs from complete canonical chunk chain")
	}
	manifest, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: progress.Binding, EventCount: progress.EventCount, ChunkCount: progress.ChunkCount, ChunkBytes: chunkBytes, ChainRoot: previous})
	if err != nil {
		t.Fatal(err)
	}
	var reserved int64
	if err := f.admin.QueryRow(ctx, `SELECT reserved_bytes FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&reserved); err != nil || reserved != chunkBytes+int64(len(manifest)) {
		t.Fatal("quota did not reserve exact chunk plus manifest bytes", err)
	}
	if err := worker.QueryRow(ctx, capture, common...).Scan(&body); err != nil || !bytes.Equal(body, original) {
		t.Fatal("capture retry changed frozen authority after source mutation", err)
	}
}

func TestAuditExportPostgresCaptureFailureHasNoPartialSnapshot(t *testing.T) {
	for _, mode := range []string{"invalid-source", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			policy := auditExportTestPolicy()
			if mode == "capacity" {
				policy.ExpectedCurrentPolicyID = policy.PolicyID
				policy.PolicyID = "pid_52000080-0000-4000-8000-000000000080"
				policy.MaximumExportBytes = 1
				auditExportConfigureSQL(t, ctx, f.admin, policy)
			}
			request := f.createArgs()
			var body []byte
			if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if mode == "invalid-source" {
				if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES($1,$2,$3,'pid_53000000-0000-4000-8000-000000009999',$4,'owned.invalid','fixture','succeeded',jsonb_build_object('token',chr(10)))`, request[0], request[1], request[2], request[3]); err != nil {
					t.Fatal(err)
				}
			}
			digest, _ := migrations.AuditExportPolicyDigest(policy)
			digestBytes, _ := hex.DecodeString(digest)
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, policy.PolicyID, digestBytes, request[11], request[12]).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var lease map[string]any
			if err := json.Unmarshal(body, &lease); err != nil {
				t.Fatal(err)
			}
			common := []any{request[0], request[1], request[2], request[7], lease["capture_id"], int64(1), 1, "audit-export-worker", strings.Repeat("b", 64), policy.PolicyID, digestBytes, request[11], request[12]}
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body); err != nil {
				t.Fatal("registered capture failure unavailable", err)
			}
			var result map[string]any
			code := "invalid_source"
			if mode == "capacity" {
				code = "capacity_exceeded"
			}
			if err := json.Unmarshal(body, &result); err != nil || len(result) != 2 || result["state"] != "failed" || result["failure_code"] != code {
				t.Fatal("capture failure lost stable reason", err)
			}
			var exact bool
			if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_audit_export_events) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_chunks) AND (SELECT status='failed' AND NOT captured AND reserved_bytes=0 AND lease_expires_at IS NULL AND completion_audit_id IS NOT NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2) AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete')=1`, request[0], request[7]).Scan(&exact); err != nil || !exact {
				t.Fatal("capture failure left partial source, quota or lease", err)
			}
		})
	}
}

func TestAuditExportPostgresCapturePostFreezeWaitIsAtomic(t *testing.T) {
	for _, mode := range []string{"drift-after-freeze", "expiry-after-freeze", "expiry-before-capacity-failure", "deadline-before-capacity-failure", "deadline-before-capacity-audit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			policy := auditExportTestPolicy()
			if strings.Contains(mode, "capacity") {
				policy.ExpectedCurrentPolicyID = policy.PolicyID
				policy.PolicyID = "pid_52000080-0000-4000-8000-000000000080"
				policy.MaximumExportBytes = 1
				if strings.HasPrefix(mode, "deadline") {
					policy.CaptureTimeoutSeconds = 5
				}
				auditExportConfigureSQL(t, ctx, f.admin, policy)
			}
			request := f.createArgs()
			var body []byte
			if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			digest, _ := migrations.AuditExportPolicyDigest(policy)
			digestBytes, _ := hex.DecodeString(digest)
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, policy.PolicyID, digestBytes, request[11], request[12]).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var lease map[string]any
			if err := json.Unmarshal(body, &lease); err != nil {
				t.Fatal(err)
			}
			common := []any{request[0], request[1], request[2], request[7], lease["capture_id"], int64(1), 1, "audit-export-worker", strings.Repeat("b", 64), policy.PolicyID, digestBytes, request[11], request[12]}
			if strings.HasPrefix(mode, "expiry") {
				if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()+interval '10 seconds' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				t.Helper()
				var value string
				if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'events',(SELECT count(*) FROM zasp_audit_export_events),'chunks',(SELECT count(*) FROM zasp_audit_export_chunks),'completion',(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'))::text FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			f.api = worker
			lock := `LOCK TABLE zasp_audit_export_chunks IN SHARE MODE`
			if strings.HasSuffix(mode, "audit") {
				lock = `LOCK TABLE zasp_admin_audit IN SHARE MODE`
			}
			err := auditExportBlockedCall(t, ctx, f, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common, lock, nil, func(tx pgx.Tx) error {
				if mode == "drift-after-freeze" {
					_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
					return err
				}
				seconds := 11
				if strings.HasPrefix(mode, "deadline") {
					seconds = 6
				}
				_, err := tx.Exec(ctx, `SELECT pg_sleep($1)`, seconds)
				return err
			})
			want := "42501"
			if mode == "drift-after-freeze" {
				want = "55000"
			}
			if strings.HasPrefix(mode, "deadline") {
				want = "57014"
			}
			if auditExportSQLState(err) != want {
				t.Error("capture accepted post-freeze authority loss", err)
			}
			if snapshot() != before {
				t.Error("post-freeze refusal changed snapshot, reservation, job or completion")
			}
		})
	}
}

func TestAuditExportPostgresCaptureExhaustionReleasesUnissuedBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	policy := auditExportTestPolicy()
	digest, _ := migrations.AuditExportPolicyDigest(policy)
	digestBytes, _ := hex.DecodeString(digest)
	args := []any{request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, policy.PolicyID, digestBytes, request[11], request[12]}
	claim := `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	for attempt := 1; attempt <= 5; attempt++ {
		if err := worker.QueryRow(ctx, claim, args...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if attempt == 1 {
			var lease map[string]any
			if err := json.Unmarshal(body, &lease); err != nil {
				t.Fatal(err)
			}
			common := []any{request[0], request[1], request[2], request[7], lease["capture_id"], int64(1), 1, "audit-export-worker", strings.Repeat("b", 64), policy.PolicyID, digestBytes, request[11], request[12]}
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var reserved bool
			if err := f.admin.QueryRow(ctx, `SELECT captured AND reserved_bytes>0 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&reserved); err != nil || !reserved {
				t.Fatal("capture did not reserve planned bytes", err)
			}
		}
		if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, request[0], request[7]); err != nil {
			t.Fatal(err)
		}
	}
	if err := worker.QueryRow(ctx, claim, args...).Scan(&body); err != nil || string(body) != "null" {
		t.Fatal("captured exhaustion did not settle", err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT status='failed' AND failure_code='execution_failed' AND captured AND reserved_bytes=0 AND completion_audit_id IS NOT NULL AND (SELECT count(*) FROM zasp_audit_export_events)=1 AND (SELECT count(*) FROM zasp_audit_export_chunks)=1 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, request[0], request[7]).Scan(&exact); err != nil || !exact {
		t.Fatal("failure retained never-issued reservation or lost frozen evidence", err)
	}
}

func auditExportClaimForCapture(t *testing.T, ctx context.Context, f auditExportPG, worker *pgx.Conn, policy migrations.AuditExportConfiguration) ([]any, []any) {
	t.Helper()
	request := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, request...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	digest, err := migrations.AuditExportPolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes, _ := hex.DecodeString(digest)
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request[0], request[1], request[2], request[7], "audit-export-worker", strings.Repeat("b", 64), 180, policy.PolicyID, digestBytes, request[11], request[12]).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var lease map[string]any
	if err := json.Unmarshal(body, &lease); err != nil {
		t.Fatal(err)
	}
	return request, []any{request[0], request[1], request[2], request[7], lease["capture_id"], int64(1), 1, "audit-export-worker", strings.Repeat("b", 64), policy.PolicyID, digestBytes, request[11], request[12]}
}

func TestAuditExportPostgresCaptureSnapshotExcludesConcurrentChanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	var stamp time.Time
	if err := f.admin.QueryRow(ctx, `SELECT occurred_at FROM zasp_admin_audit WHERE organization_id=$1 AND id=$2`, request[0], request[8]).Scan(&stamp); err != nil {
		t.Fatal(err)
	}
	expected, err := audit.EncodeExportEvent(audit.ExportEvent{Ordinal: 1, ID: request[8].(string), OrganizationID: request[0].(string), WorkspaceID: request[1].(string), EnvironmentID: request[2].(string), ActorID: request[3].(string), Action: "audit_export.request", TargetID: request[7].(string), Outcome: "succeeded", Metadata: map[string]string{}, OccurredAt: stamp.UTC().Format("2006-01-02T15:04:05.000000Z")})
	if err != nil {
		t.Fatal(err)
	}
	f.api = worker
	err = auditExportBlockedCall(t, ctx, f, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common, `LOCK TABLE zasp_audit_export_chunks IN SHARE MODE`, nil, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE zasp_admin_audit SET metadata='{"after":"freeze"}' WHERE organization_id=$1 AND id=$2`, request[0], request[8]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,'pid_53000000-0000-4000-8000-000000009999',$4,'late.backdated','fixture','succeeded','{}','2020-01-01T00:00:00Z')`, request[0], request[1], request[2], request[3])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var frozen []byte
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT canonical_event FROM zasp_audit_export_events WHERE organization_id=$1 AND export_id=$2 AND ordinal=1`, request[0], request[7]).Scan(&frozen); err != nil || !bytes.Equal(frozen, expected) {
		t.Fatal("concurrent source update changed statement snapshot", err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1)=2 AND (SELECT metadata='{"after":"freeze"}'::jsonb FROM zasp_admin_audit WHERE organization_id=$1 AND id=$2) AND (SELECT event_count=1 AND captured FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$3) AND (SELECT count(*) FROM zasp_audit_export_events)=1`, request[0], request[8], request[7]).Scan(&exact); err != nil || !exact {
		t.Fatal("capture did not exclude concurrent backdated arrival", err)
	}
}

func TestAuditExportPostgresCaptureCancellationRollsBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	blocker, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `LOCK TABLE zasp_audit_export_chunks IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	child, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	settled := false
	defer func() {
		stop()
		_ = blocker.Rollback(context.Background())
		if !settled {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("cancelled capture failed to join")
			}
		}
	}()
	go func() {
		var body []byte
		done <- worker.QueryRow(child, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body)
	}()
	waitCtx, stopWait := context.WithTimeout(ctx, 10*time.Second)
	defer stopWait()
	for {
		var waiting bool
		if err := blocker.QueryRow(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, worker.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			settled = true
			t.Fatal("capture completed before cancellation boundary", err)
		case <-waitCtx.Done():
			t.Fatal("capture did not reach frozen-plan wait")
		case <-time.After(10 * time.Millisecond):
		}
	}
	stop()
	select {
	case err := <-done:
		settled = true
		if err == nil || !errors.Is(err, context.Canceled) && auditExportSQLState(err) != "57014" {
			t.Fatal("cancelled capture returned success or unrelated error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capture cancellation did not settle")
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_audit_export_events) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_chunks) AND NOT EXISTS(SELECT 1 FROM zasp_admin_audit WHERE action='audit_export.complete') AND (SELECT status='processing' AND NOT captured AND reserved_bytes=0 AND attempt=1 AND generation=1 AND completion_audit_id IS NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2)`, request[0], request[7]).Scan(&exact); err != nil || !exact {
		t.Fatal("cancelled capture retained partial effects", err)
	}
}

func TestAuditExportPostgresCaptureExactChunkByteBoundary(t *testing.T) {
	for _, extraByte := range []bool{false, true} {
		t.Run(fmt.Sprintf("extra-byte-%t", extraByte), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
			binding := audit.ExportBinding{OrganizationID: request[0].(string), WorkspaceID: request[1].(string), EnvironmentID: request[2].(string), ExportID: request[7].(string), CaptureID: common[4].(string)}
			chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: 1, FirstEvent: 1, EventCount: 11, PreviousDigest: audit.ExportZeroDigest, Events: []audit.ExportEvent{}}
			header, err := json.Marshal(chunk)
			if err != nil {
				t.Fatal(err)
			}
			used := len(header) + 10 // separators for eleven complete events
			for ordinal := 1; ordinal <= 11; ordinal++ {
				metadata := map[string]string{}
				for key := 0; key < 32; key++ {
					value := "x"
					if ordinal < 11 {
						value = strings.Repeat("<", 512)
					}
					metadata[fmt.Sprintf("k%02d", key)] = value
				}
				event := audit.ExportEvent{Ordinal: int64(ordinal), ID: fmt.Sprintf("pid_53000000-0000-4000-8000-%012d", 200-ordinal), OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, ActorID: request[3].(string), Action: "integration.webhook", TargetID: "owned source fixture", Outcome: "succeeded", Metadata: metadata, OccurredAt: "2099-01-01T00:00:00.000000Z"}
				encoded, err := audit.EncodeExportEvent(event)
				if err != nil {
					t.Fatal(err)
				}
				if ordinal < 11 {
					used += len(encoded)
				} else {
					remaining := audit.ExportMaximumChunkBytes - used - len(encoded)
					if remaining < 0 {
						t.Fatal("byte fixture overflowed before padding")
					}
					for key := 0; key < 32 && remaining > 0; key++ {
						addition := min(remaining, 3071)
						target := addition + 1
						escaped, plain := target/6, target%6
						if escaped+plain > 512 {
							plain = 512 - escaped
						}
						metadata[fmt.Sprintf("k%02d", key)] = strings.Repeat("<", escaped) + strings.Repeat("x", plain)
						remaining -= 6*escaped + plain - 1
					}
					if remaining != 0 {
						t.Fatal("byte fixture could not reach exact boundary")
					}
				}
				chunk.Events = append(chunk.Events, event)
			}
			canonical, err := audit.EncodeExportChunk(chunk)
			if err != nil || len(canonical) != 1048576 {
				t.Fatal("independent exact-byte source fixture", len(canonical), err)
			}
			if extraByte {
				changed := false
				for key, value := range chunk.Events[10].Metadata {
					if value == "x" {
						chunk.Events[10].Metadata[key] = "xx"
						changed = true
						break
					}
				}
				if !changed {
					t.Fatal("missing byte-padding slot")
				}
				oversized, err := json.Marshal(chunk)
				if err != nil || len(oversized) != 1048577 {
					t.Fatal("independent one-byte-over fixture", len(oversized), err)
				}
			}
			for _, event := range chunk.Events {
				metadata, err := json.Marshal(event.Metadata)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz)`, event.OrganizationID, event.WorkspaceID, event.EnvironmentID, event.ID, event.ActorID, event.Action, event.TargetID, event.Outcome, metadata, event.OccurredAt); err != nil {
					t.Fatal(err)
				}
			}
			var body []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var progress map[string]any
			if err := json.Unmarshal(body, &progress); err != nil || progress["event_count"] != float64(12) || progress["chunk_count"] != float64(2) {
				t.Fatal("byte boundary capture dropped source", err)
			}
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), int64(1))...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if len(body) > 1048576 {
				t.Fatal("SQL aggregated oversized frozen page")
			}
			var page struct {
				Binding        audit.ExportBinding `json:"binding"`
				Ordinal        int64               `json:"ordinal"`
				FirstEvent     int64               `json:"first_event"`
				EventCount     int64               `json:"event_count"`
				PreviousDigest string              `json:"previous_digest"`
				Events         []audit.ExportEvent `json:"events"`
				NextEvent      *int64              `json:"next_event"`
			}
			wantCount := int64(11)
			if extraByte {
				wantCount = 10
			}
			if err := json.Unmarshal(body, &page); err != nil || page.EventCount != wantCount || int64(len(page.Events)) != wantCount || page.NextEvent == nil || *page.NextEvent != wantCount+1 {
				t.Fatal("SQL chunk split ignored exact complete-byte boundary", err)
			}
			actual, err := audit.EncodeExportChunk(audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: page.Binding, Ordinal: page.Ordinal, FirstEvent: page.FirstEvent, EventCount: page.EventCount, PreviousDigest: page.PreviousDigest, Events: page.Events})
			if err != nil || !extraByte && len(actual) != 1048576 {
				t.Fatal("SQL exact boundary is not canonical codec bytes", err)
			}
		})
	}
}

func TestAuditExportPostgresCaptureRetainedQuotaAcrossPolicyRevisions(t *testing.T) {
	for _, fits := range []bool{true, false} {
		t.Run(fmt.Sprintf("exact-fit-%t", fits), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			oldPolicy := auditExportTestPolicy()
			first, common := auditExportClaimForCapture(t, ctx, f, worker, oldPolicy)
			second := append([]any(nil), first...)
			second[6] = "audit-export-retained-second"
			second[7] = "pid_52000081-0000-4000-8000-000000000081"
			second[8] = "pid_52000082-0000-4000-8000-000000000082"
			second[9] = "pid_52000083-0000-4000-8000-000000000083"
			var body []byte
			if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, second...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			capture := `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
			if err := worker.QueryRow(ctx, capture, common...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), int64(1))...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var page struct {
				Binding        audit.ExportBinding `json:"binding"`
				Ordinal        int64               `json:"ordinal"`
				FirstEvent     int64               `json:"first_event"`
				EventCount     int64               `json:"event_count"`
				PreviousDigest string              `json:"previous_digest"`
				Events         []audit.ExportEvent `json:"events"`
				NextEvent      *int64              `json:"next_event"`
			}
			if err := json.Unmarshal(body, &page); err != nil || page.EventCount != 2 || len(page.Events) != 2 || page.NextEvent != nil {
				t.Fatal("quota source fixture", err)
			}
			chunk, err := audit.EncodeExportChunk(audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: page.Binding, Ordinal: page.Ordinal, FirstEvent: page.FirstEvent, EventCount: page.EventCount, PreviousDigest: page.PreviousDigest, Events: page.Events})
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(chunk)
			manifest, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: page.Binding, EventCount: 2, ChunkCount: 1, ChunkBytes: int64(len(chunk)), ChainRoot: hex.EncodeToString(hash[:])})
			if err != nil {
				t.Fatal(err)
			}
			expectedBytes := int64(len(chunk) + len(manifest))
			var firstBytes int64
			if err := f.admin.QueryRow(ctx, `SELECT reserved_bytes FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, first[0], first[7]).Scan(&firstBytes); err != nil || firstBytes != expectedBytes {
				t.Fatal("first reservation not exact codec bytes", err)
			}
			policy := oldPolicy
			policy.ExpectedCurrentPolicyID = oldPolicy.PolicyID
			policy.PolicyID = "pid_52000080-0000-4000-8000-000000000080"
			policy.MaximumRetainedBytes = 2 * expectedBytes
			if !fits {
				policy.MaximumRetainedBytes--
			}
			auditExportConfigureSQL(t, ctx, f.admin, policy)
			digest, _ := migrations.AuditExportPolicyDigest(oldPolicy)
			digestBytes, _ := hex.DecodeString(digest)
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, second[0], second[1], second[2], second[7], "audit-export-worker", strings.Repeat("c", 64), 180, oldPolicy.PolicyID, digestBytes, second[11], second[12]).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var lease map[string]any
			if err := json.Unmarshal(body, &lease); err != nil {
				t.Fatal(err)
			}
			secondCommon := []any{second[0], second[1], second[2], second[7], lease["capture_id"], int64(1), 1, "audit-export-worker", strings.Repeat("c", 64), oldPolicy.PolicyID, digestBytes, second[11], second[12]}
			if err := worker.QueryRow(ctx, capture, secondCommon...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
			if fits && result["state"] != "processing" || !fits && (result["state"] != "failed" || result["failure_code"] != "capacity_exceeded") {
				t.Fatal("capture did not apply exact current retained limit to old queued policy")
			}
			wantSecond := int64(0)
			if fits {
				wantSecond = expectedBytes
			}
			var exact bool
			if err := f.admin.QueryRow(ctx, `SELECT (SELECT reserved_bytes=$3 AND captured AND policy_id=$5 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2) AND (SELECT reserved_bytes=$4 AND policy_id=$5 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$6)`, first[0], first[7], expectedBytes, wantSecond, oldPolicy.PolicyID, second[7]).Scan(&exact); err != nil || !exact {
				t.Fatal("quota rotation rebound historical policy or changed retained bytes", err)
			}
		})
	}
}

func TestAuditExportPostgresCaptureLargeSourceHasBoundedPages(t *testing.T) {
	for _, test := range []struct {
		name  string
		rows  int
		large bool
	}{{"100001-events", 100001, false}, {"1000-large-events", 1000, true}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
			if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT $1,$2,$3,'pid_53000000-0000-4000-8000-'||lpad(n::text,12,'0'),$4,'integration.webhook','large-fixture','succeeded',CASE WHEN $5 THEN (SELECT jsonb_object_agg(repeat('<',62)||lpad(k::text,2,'0'),repeat('<',512)) FROM generate_series(1,32) k) ELSE jsonb_build_object('payload',repeat('x',512),'counter',n) END,'2099-01-01T00:00:00Z'::timestamptz FROM generate_series(1,$6::integer)n`, request[0], request[1], request[2], request[3], test.large, test.rows); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			var body []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&body); err != nil {
				t.Fatal("scale capture failed within approved budget", err)
			}
			captureDuration := time.Since(started)
			var progress struct {
				State      string              `json:"state"`
				Binding    audit.ExportBinding `json:"binding"`
				EventCount int64               `json:"event_count"`
				ChunkCount int64               `json:"chunk_count"`
				ChunkBytes int64               `json:"chunk_bytes"`
				ChainRoot  string              `json:"chain_root"`
			}
			if err := json.Unmarshal(body, &progress); err != nil || progress.State != "processing" || progress.EventCount != int64(test.rows+1) || progress.ChunkBytes <= 64<<20 {
				t.Fatal("scale capture truncated, failed or imposed64MiB cap", err)
			}
			t.Logf("scale capture frozen: events=%d chunks=%d bytes=%d capture=%s", progress.EventCount, progress.ChunkCount, progress.ChunkBytes, captureDuration)
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), 300)...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			baseline, peak := memory.HeapAlloc, memory.HeapAlloc
			var next int64 = 1
			var ordinal int64 = 1
			var chunkBytes int64
			previousDigest := audit.ExportZeroDigest
			remaining := test.rows
			requests := 0
			var prior audit.ExportEvent
			for next <= progress.EventCount {
				if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), next)...).Scan(&body); err != nil {
					t.Fatal(err)
				}
				if len(body) > 1048576 {
					t.Fatal("SQL returned unbounded large-event page")
				}
				var page struct {
					Binding        audit.ExportBinding `json:"binding"`
					Ordinal        int64               `json:"ordinal"`
					FirstEvent     int64               `json:"first_event"`
					EventCount     int64               `json:"event_count"`
					PreviousDigest string              `json:"previous_digest"`
					Events         []audit.ExportEvent `json:"events"`
					NextEvent      *int64              `json:"next_event"`
				}
				if err := json.Unmarshal(body, &page); err != nil || page.Binding != progress.Binding || page.Ordinal != ordinal || page.FirstEvent != next || page.EventCount != int64(len(page.Events)) || len(page.Events) < 1 || len(page.Events) > 1000 || page.PreviousDigest != previousDigest {
					t.Fatal("scale page changed bound or range", err)
				}
				if test.large && len(page.Events) >= 1000 {
					t.Fatal("large-event page used count-only bound")
				}
				for _, event := range page.Events {
					if prior.ID != "" && (prior.OccurredAt < event.OccurredAt || prior.OccurredAt == event.OccurredAt && prior.ID <= event.ID) {
						t.Fatal("scale global order changed")
					}
					if event.ID == request[8].(string) {
						requests++
					} else {
						if event.ID != fmt.Sprintf("pid_53000000-0000-4000-8000-%012d", remaining) || event.ActorID != request[3] || event.Action != "integration.webhook" || event.TargetID != "large-fixture" || event.Outcome != "succeeded" || event.OccurredAt != "2099-01-01T00:00:00.000000Z" {
							t.Fatal("scale omitted or changed source event")
						}
						if test.large {
							if len(event.Metadata) != 32 {
								t.Fatal("large metadata omitted")
							}
							for key, value := range event.Metadata {
								if len(key) != 64 || !strings.HasPrefix(key, strings.Repeat("<", 62)) || value != strings.Repeat("<", 512) {
									t.Fatal("large metadata changed")
								}
							}
						} else if len(event.Metadata) != 2 || event.Metadata["payload"] != strings.Repeat("x", 512) || event.Metadata["counter"] != strconv.Itoa(remaining) {
							t.Fatal("scale numeric source projection changed")
						}
						remaining--
					}
					prior = event
				}
				chunk, err := audit.EncodeExportChunk(audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: page.Binding, Ordinal: page.Ordinal, FirstEvent: page.FirstEvent, EventCount: page.EventCount, PreviousDigest: page.PreviousDigest, Events: page.Events})
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(chunk)
				previousDigest = hex.EncodeToString(hash[:])
				chunkBytes += int64(len(chunk))
				next += page.EventCount
				ordinal++
				if next <= progress.EventCount {
					if page.NextEvent == nil || *page.NextEvent != next {
						t.Fatal("scale skipped next event")
					}
				} else if page.NextEvent != nil {
					t.Fatal("scale invented trailing page")
				}
				runtime.ReadMemStats(&memory)
				peak = max(peak, memory.HeapAlloc)
			}
			if remaining != 0 || requests != 1 || ordinal-1 != progress.ChunkCount || chunkBytes != progress.ChunkBytes || previousDigest != progress.ChainRoot {
				t.Fatal("scale did not preserve complete source chain")
			}
			if peak-baseline > 64<<20 {
				t.Fatal("Go retained whole-export-scale heap", peak-baseline)
			}
			t.Logf("AUDIT_EXPORT_CAPTURE_SCALE events=%d chunks=%d canonical_bytes=%d capture_ms=%d traversal_ms=%d peak_heap_delta=%d", progress.EventCount, progress.ChunkCount, chunkBytes, captureDuration.Milliseconds(), time.Since(started).Milliseconds()-captureDuration.Milliseconds(), peak-baseline)
		})
	}
}

func TestAuditExportPostgresCanonicalFrozenEventBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	id := "pid_52000050-0000-4000-8000-000000000050"
	metadata := map[string]any{"counter": 42, "verified": true, "quote": "<>&\"\\ café\u2028\u2029", "API_KEY": "owned-fixture-secret", "authorİzation": "owned-fixture-secret"}
	input, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	stamp := "2026-09-12T13:14:15.000123Z"
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,$4,$5,'integration.webhook',$6,'rejected',$7,$8::timestamptz)`, f.identity.Scope.OrganizationID().String(), f.identity.Scope.WorkspaceID().String(), f.identity.Scope.EnvironmentID().String(), id, f.identity.PrincipalID.String(), "provider <value> & \"\\ café", input, stamp); err != nil {
		t.Fatal(err)
	}
	query := `SELECT zasp_audit_export_event_bytes($1,a) FROM zasp_admin_audit a WHERE id=$2`
	var actual []byte
	if err := f.admin.QueryRow(ctx, query, int64(1), id).Scan(&actual); err != nil {
		t.Fatal("SQL frozen codec unavailable", err)
	}
	event := audit.ExportEvent{Ordinal: 1, ID: id, OrganizationID: f.identity.Scope.OrganizationID().String(), WorkspaceID: f.identity.Scope.WorkspaceID().String(), EnvironmentID: f.identity.Scope.EnvironmentID().String(), ActorID: f.identity.PrincipalID.String(), Action: "integration.webhook", TargetID: "provider <value> & \"\\ café", Outcome: "rejected", Metadata: map[string]string{"counter": "42", "verified": "true", "quote": "<>&\"\\ café\u2028\u2029", "API_KEY": "owned-fixture-secret", "authorİzation": "owned-fixture-secret"}, OccurredAt: stamp}
	projected, err := audit.ProjectExportEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := audit.EncodeExportEvent(projected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("SQL and Go frozen canonical bytes differ")
	}
	if _, err := audit.DecodeExportEvent(actual); err != nil {
		t.Fatal("SQL bytes rejected by production codec", err)
	}
	for _, test := range []struct{ name, statement string }{
		{"empty-value", `UPDATE zasp_admin_audit SET metadata='{"counter":""}' WHERE id=$1`},
		{"invalid-secret-before-redaction", `UPDATE zasp_admin_audit SET metadata=jsonb_build_object('token',chr(10)) WHERE id=$1`},
		{"too-many-keys", `UPDATE zasp_admin_audit SET metadata=(SELECT jsonb_object_agg('key'||n,'value') FROM generate_series(1,33) n) WHERE id=$1`},
		{"invalid-action", `UPDATE zasp_admin_audit SET action='invalid..action' WHERE id=$1`},
		{"overlong-action", `UPDATE zasp_admin_audit SET action=repeat('a',128) WHERE id=$1`},
		{"zero-time", `UPDATE zasp_admin_audit SET occurred_at='0001-01-01T00:00:00Z' WHERE id=$1`},
		{"equal-scope", `UPDATE zasp_admin_audit SET workspace_id=organization_id WHERE id=$1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, test.statement, id); err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRow(ctx, query, int64(1), id).Scan(&actual); auditExportSQLState(err) != "22023" {
				t.Fatal("invalid source silently projected", err)
			}
		})
	}
}

type auditExportPG struct {
	admin, api *pgx.Conn
	identity   RequestIdentity
	digest     [32]byte
}

func auditExportWorkerConnections(t *testing.T, ctx context.Context, f auditExportPG) (*pgx.Conn, *pgx.Conn) {
	t.Helper()
	if _, err := f.admin.Exec(ctx, `CREATE ROLE audit_export_worker_fixture LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE audit_export_outbox_fixture LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var registered bool
	if err := f.admin.QueryRow(ctx, `SELECT zasp_audit_export_register_workers('audit_export_worker_fixture','audit_export_outbox_fixture')`).Scan(&registered); err != nil || !registered {
		t.Fatal("registered export workers unavailable", err)
	}
	connections := make([]*pgx.Conn, 0, 2)
	for _, name := range []string{"audit_export_worker_fixture", "audit_export_outbox_fixture"} {
		config := f.admin.Config().Copy()
		config.User = name
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		if !auditHTTPFixtureOwnConnection(ctx, "audit export "+name, connection) {
			t.Cleanup(func() {
				closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := connection.Close(closeCtx); err != nil {
					t.Error("export worker connection close", err)
				}
			})
		}
		connections = append(connections, connection)
	}
	return connections[0], connections[1]
}

func TestAuditExportPostgresWorkerRegistrationIsIsolated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	worker, outbox := auditExportWorkerConnections(t, ctx, f)
	if err := precisionMigrationRunner(t, f.admin).RegisterAuditExportWorkers(ctx, "audit_export_worker_fixture", "audit_export_outbox_fixture"); err != nil {
		t.Fatal("runner worker registration replay", err)
	}
	for index, connection := range []*pgx.Conn{worker, outbox} {
		for roleIndex, role := range []string{"zasp_audit_export_worker", "zasp_audit_export_outbox"} {
			var ready bool
			if err := connection.QueryRow(ctx, `SELECT zasp_audit_export_worker_readiness($1,$2,$3)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint(), role).Scan(&ready); err != nil || ready != (index == roleIndex) {
				t.Fatal("cross-authority worker readiness", err)
			}
		}
		if _, err := connection.Exec(ctx, `SELECT * FROM zasp_audit_export_worker_bindings`); auditExportSQLState(err) != "42501" {
			t.Fatal("worker read private bindings", err)
		}
		if _, err := connection.Exec(ctx, `SELECT zasp_audit_export_register_workers('audit_export_worker_fixture','audit_export_outbox_fixture')`); auditExportSQLState(err) != "42501" {
			t.Fatal("worker registered authority", err)
		}
	}
	var registered bool
	if err := f.admin.QueryRow(ctx, `SELECT zasp_audit_export_register_workers('audit_export_worker_fixture','audit_export_outbox_fixture')`).Scan(&registered); err != nil || !registered {
		t.Fatal("worker registration replay", err)
	}
	if _, err := f.api.Exec(ctx, `SELECT zasp_audit_export_register_workers('audit_export_worker_fixture','audit_export_outbox_fixture')`); auditExportSQLState(err) != "42501" {
		t.Fatal("API registered worker", err)
	}
	if _, err := f.admin.Exec(ctx, `SELECT zasp_audit_export_register_workers('audit_export_worker_fixture','audit_export_worker_fixture')`); auditExportSQLState(err) != "22023" {
		t.Fatal("same principal acquired both authorities", err)
	}
	if _, err := f.admin.Exec(ctx, `CREATE ROLE audit_export_other_fixture LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `SELECT zasp_audit_export_register_workers('audit_export_other_fixture','audit_export_outbox_fixture')`); auditExportSQLState(err) != "23505" {
		t.Fatal("registered executor silently replaced", err)
	}
	var acquired bool
	if err := f.admin.QueryRow(ctx, `SELECT pg_has_role('audit_export_other_fixture','zasp_audit_export_worker','MEMBER')`).Scan(&acquired); err != nil || acquired {
		t.Fatal("conflicting registration left a grant", err)
	}
	if _, err := f.admin.Exec(ctx, `GRANT zasp_discovery_api TO audit_export_worker_fixture`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_worker_readiness($1,$2,'zasp_audit_export_worker')`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatal("mixed authority worker remained ready", err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatal("worker role drift escaped complete graph readiness", err)
	}
	if _, err := f.admin.Exec(ctx, `REVOKE zasp_discovery_api FROM audit_export_worker_fixture`); err != nil {
		t.Fatal(err)
	}
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err != nil {
		t.Fatal("unused worker registration rollback", err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox')) AND zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("worker authority rollback did not restore51", err)
	}
}

func TestAuditExportPostgresWorkerRegistrationWaitRefusesDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	if _, err := f.admin.Exec(ctx, `CREATE ROLE audit_export_worker_fixture LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE audit_export_outbox_fixture LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	connection, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	f.api = connection
	err = auditExportBlockedCall(t, ctx, f, `SELECT to_jsonb(zasp_audit_export_register_workers('audit_export_worker_fixture','audit_export_outbox_fixture'))`, nil, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-audit-export-registration',0))`, nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
		return err
	})
	if auditExportSQLState(err) != "55000" {
		t.Fatal("worker registration accepted postwait drift", err)
	}
	var unchanged bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_worker_bindings)=0 AND NOT pg_has_role('audit_export_worker_fixture','zasp_audit_export_worker','MEMBER') AND NOT pg_has_role('audit_export_outbox_fixture','zasp_audit_export_outbox','MEMBER')`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("rejected registration retained role authority", err)
	}
}

func TestAuditExportPostgresWorkerTransitiveAndSetAuthorityRefused(t *testing.T) {
	for _, mode := range []string{"indirect-before-registration", "indirect-after-registration", "set-option-drift"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			var worker *pgx.Conn
			if mode == "indirect-before-registration" {
				if _, err := f.admin.Exec(ctx, `CREATE ROLE audit_export_worker_fixture LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE audit_export_outbox_fixture LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
					t.Fatal(err)
				}
			} else {
				worker, _ = auditExportWorkerConnections(t, ctx, f)
			}
			if mode == "set-option-drift" {
				tx, err := f.admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority;GRANT zasp_audit_export_worker TO audit_export_worker_fixture WITH SET TRUE`); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := f.admin.Exec(ctx, `CREATE ROLE audit_export_bridge NOLOGIN INHERIT;GRANT zasp_discovery_api TO audit_export_bridge;GRANT audit_export_bridge TO audit_export_worker_fixture`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "indirect-before-registration" {
				if _, err := f.admin.Exec(ctx, `SELECT zasp_audit_export_register_workers('audit_export_worker_fixture','audit_export_outbox_fixture')`); auditExportSQLState(err) != "42501" {
					t.Fatal("indirect legacy authority registered as executor", err)
				}
				var unchanged bool
				if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_worker_bindings)=0 AND NOT pg_has_role('audit_export_worker_fixture','zasp_audit_export_worker','MEMBER')`).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("indirect refusal left worker grant", err)
				}
				return
			}
			var ready bool
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_worker_readiness($1,$2,'zasp_audit_export_worker')`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("worker accepted widened authority", err)
			}
			if err := f.admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("complete graph accepted widened authority", err)
			}
		})
	}
}

func TestAuditExportPostgresSourceReadGrantAndExactRollback(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		name := "new-owner-read"
		if preexisting {
			name = "preexisting-select-grant-option"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			if preexisting {
				if _, err := admin.Exec(ctx, `GRANT SELECT ON zasp_admin_audit TO zasp_discovery_authority WITH GRANT OPTION`); err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(ctx, `GRANT SELECT(metadata) ON zasp_admin_audit TO zasp_discovery_api`); err != nil {
					t.Fatal(err)
				}
			}
			aclQuery := `SELECT jsonb_build_object('owner',relowner::regrole::text,'acl',relacl::text,'columns',(SELECT jsonb_agg(jsonb_build_object('number',attnum,'name',attname,'acl',attacl::text) ORDER BY attnum) FROM pg_attribute WHERE attrelid=pg_class.oid AND attnum>0 AND NOT attisdropped))::text FROM pg_class WHERE oid='zasp_admin_audit'::regclass`
			var before string
			if err := admin.QueryRow(ctx, aclQuery).Scan(&before); err != nil {
				t.Fatal(err)
			}
			installAuditExports(t, ctx, admin)
			if _, err := admin.Exec(ctx, `UPDATE zasp_audit_export_source_acl SET before_state=after_state`); auditExportSQLState(err) != "42501" {
				t.Fatal("saved source privilege authority changed", err)
			}
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
				t.Fatal(err)
			}
			var count int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM zasp_admin_audit`).Scan(&count); err != nil {
				t.Fatal("capture function owner cannot read audit source", err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			var unsafe bool
			if err := admin.QueryRow(ctx, `SELECT has_table_privilege('zasp_audit_export_worker','zasp_admin_audit','SELECT') OR has_table_privilege('zasp_audit_export_outbox','zasp_admin_audit','SELECT') OR has_table_privilege('zasp_discovery_authority','zasp_admin_audit','UPDATE')`).Scan(&unsafe); err != nil || unsafe {
				t.Fatal("capture grant widened caller or mutation authority", err)
			}
			if _, err := admin.Exec(ctx, `GRANT SELECT ON zasp_admin_audit TO zasp_audit_export_outbox`); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("full source ACL drift was not detected", err)
			}
			if _, err := admin.Exec(ctx, `REVOKE SELECT ON zasp_admin_audit FROM zasp_audit_export_outbox`); err != nil {
				t.Fatal(err)
			}
			if err := precisionMigrationRunner(t, admin).DownProductionAuditExports(ctx); err != nil {
				t.Fatal("source read grant rollback failed", err)
			}
			var after string
			if err := admin.QueryRow(ctx, aclQuery).Scan(&after); err != nil || before != after {
				t.Fatal("source ACL/grant option was not restored exactly", err)
			}
		})
	}
}

func TestAuditExportPostgresSourceColumnACLDrift(t *testing.T) {
	for _, test := range []struct{ name, grant string }{
		{"outbox-column-read", `GRANT SELECT(metadata) ON zasp_admin_audit TO zasp_audit_export_outbox`},
		{"authority-column-update", `GRANT UPDATE(metadata) ON zasp_admin_audit TO zasp_discovery_authority`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			if _, err := f.admin.Exec(ctx, test.grant); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := f.admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil {
				t.Fatal(err)
			}
			if ready {
				t.Error("source column ACL drift remained ready")
			}
			if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err == nil {
				t.Error("Down accepted changed source column authority")
			}
			var retained bool
			if err := f.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=52)`).Scan(&retained); err != nil || !retained {
				t.Error("source ACL drift rollback changed release state", err)
			}
		})
	}
}

func auditExportTestPolicy() migrations.AuditExportConfiguration {
	return migrations.AuditExportConfiguration{PolicyID: "pid_52000041-0000-4000-8000-000000000041", Bucket: "zasp-audit-export-fixture", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/52000042-0000-4000-8000-000000000042", MaximumExportBytes: 1 << 30, MaximumRetainedBytes: 10 << 30, MaximumInflight: 2, CaptureTimeoutSeconds: 120}
}

func auditExportConfigureSQL(t *testing.T, ctx context.Context, admin *pgx.Conn, config migrations.AuditExportConfiguration) []byte {
	t.Helper()
	var prior any
	if config.ExpectedCurrentPolicyID != "" {
		prior = config.ExpectedCurrentPolicyID
	}
	var body []byte
	if err := admin.QueryRow(ctx, `SELECT zasp_audit_export_configure($1,$2,$3,$4,$5,$6,$7,$8,$9)`, config.PolicyID, prior, config.Bucket, config.ExpectedBucketOwner, config.KMSKeyARN, config.MaximumExportBytes, config.MaximumRetainedBytes, config.MaximumInflight, config.CaptureTimeoutSeconds).Scan(&body); err != nil {
		t.Fatal("owner policy configuration unavailable", err)
	}
	var policy map[string]any
	if err := json.Unmarshal(body, &policy); err != nil {
		t.Fatal(err)
	}
	digest, err := migrations.AuditExportPolicyDigest(config)
	if err != nil || policy["policy_digest"] != digest || policy["policy_id"] != config.PolicyID {
		t.Fatal("SQL policy differs from trusted canonical digest", err)
	}
	return body
}

func TestAuditExportPostgresPolicyRotationPinsQueuedJobs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	config := auditExportTestPolicy()
	if err := precisionMigrationRunner(t, f.admin).ConfigureAuditExports(ctx, config); err != nil {
		t.Fatal("runner policy replay failed", err)
	}
	firstPolicy := auditExportConfigureSQL(t, ctx, f.admin, config)
	if replay := auditExportConfigureSQL(t, ctx, f.admin, config); string(replay) != string(firstPolicy) {
		t.Fatal("policy retry changed revision")
	}
	f.register(t, ctx)
	args := f.createArgs()
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	originalDescriptor := append([]byte(nil), body...)
	var before string
	if err := f.admin.QueryRow(ctx, `SELECT to_jsonb(j)::text FROM zasp_audit_export_jobs j WHERE id=$1`, args[7]).Scan(&before); err != nil {
		t.Fatal(err)
	}
	second := config
	second.PolicyID = "pid_52000044-0000-4000-8000-000000000044"
	second.ExpectedCurrentPolicyID = config.PolicyID
	second.KMSKeyARN = "arn:aws:kms:us-east-1:123456789012:key/52000045-0000-4000-8000-000000000045"
	second.MaximumInflight = 1
	auditExportConfigureSQL(t, ctx, f.admin, second)
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); err != nil || !bytes.Equal(body, originalDescriptor) {
		t.Fatal("policy rotation changed original Create replay", err)
	}
	var after string
	if err := f.admin.QueryRow(ctx, `SELECT to_jsonb(j)::text FROM zasp_audit_export_jobs j WHERE id=$1`, args[7]).Scan(&after); err != nil || before != after {
		t.Fatal("rotation rebound queued job", err)
	}
	var policyID string
	if err := f.admin.QueryRow(ctx, `SELECT storage_policy->>'policy_id' FROM zasp_audit_export_jobs WHERE id=$1`, args[7]).Scan(&policyID); err != nil || policyID != config.PolicyID {
		t.Fatal("job lost original policy", err)
	}
	args[6] = "audit-export-second-policy-key"
	args[7] = "pid_52000046-0000-4000-8000-000000000046"
	args[8] = "pid_52000047-0000-4000-8000-000000000047"
	args[9] = "pid_52000048-0000-4000-8000-000000000048"
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT storage_policy->>'policy_id' FROM zasp_audit_export_jobs WHERE id=$1`, args[7]).Scan(&policyID); err != nil || policyID != second.PolicyID {
		t.Fatal("new job did not select new revision", err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET storage_policy=jsonb_set(storage_policy,'{bucket}','"rebound-bucket"') WHERE id=$1`, args[7]); auditExportSQLState(err) != "42501" {
		t.Fatal("immutable job policy was rewritten", err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_policies SET bucket='rebound-bucket' WHERE policy_id=$1`, config.PolicyID); auditExportSQLState(err) != "42501" {
		t.Fatal("immutable policy was rewritten", err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT zasp_audit_export_configure($1,NULL,$2,$3,$4,$5,$6,$7,$8)`, config.PolicyID, config.Bucket, config.ExpectedBucketOwner, config.KMSKeyARN, config.MaximumExportBytes, config.MaximumRetainedBytes, config.MaximumInflight, config.CaptureTimeoutSeconds).Scan(&body); auditExportSQLState(err) != "23505" {
		t.Fatal("old policy retry rewound current revision", err)
	}
}

func TestAuditExportPostgresPolicyConfigurationRefusalsAndRollback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	config := auditExportTestPolicy()
	args := []any{config.PolicyID, nil, config.Bucket, config.ExpectedBucketOwner, config.KMSKeyARN, config.MaximumExportBytes, config.MaximumRetainedBytes, config.MaximumInflight, config.CaptureTimeoutSeconds}
	query := `SELECT zasp_audit_export_configure($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	var body []byte
	for _, test := range []struct {
		name  string
		index int
		value any
		state string
	}{
		{"changed-revision", 2, "changed-bucket", "23505"}, {"changed-predecessor", 1, "pid_52000043-0000-4000-8000-000000000043", "23505"},
		{"stale-CAS", 0, "pid_52000044-0000-4000-8000-000000000044", "23505"}, {"raw-prefix", 2, "bucket/exports", "22023"},
		{"alias-key", 4, "arn:aws:kms:us-east-1:123456789012:alias/export", "22023"}, {"unsafe-integer", 5, int64(1 << 53), "22023"},
		{"missing-owner", 3, nil, "22023"}, {"unbounded-capture", 8, 121, "22023"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := append([]any(nil), args...)
			changed[test.index] = test.value
			if err := f.admin.QueryRow(ctx, query, changed...).Scan(&body); auditExportSQLState(err) != test.state {
				t.Fatal("configuration refusal", err)
			}
		})
	}
	if err := f.api.QueryRow(ctx, query, args...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("API configured storage", err)
	}
	for _, statement := range []string{`SELECT * FROM zasp_audit_export_policies`, `UPDATE zasp_audit_export_current_policy SET policy_id=NULL`} {
		if _, err := f.api.Exec(ctx, statement); auditExportSQLState(err) != "42501" {
			t.Fatal("API accessed private policy table", err)
		}
	}
	var unchanged bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_policies)=1 AND (SELECT policy_id FROM zasp_audit_export_current_policy)=$1`, config.PolicyID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("refusal changed configuration", err)
	}
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM zasp_audit_export_current_policy`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	var ready bool
	err = tx.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready)
	_ = tx.Rollback(ctx)
	if err != nil || ready {
		t.Fatal("missing current-policy singleton remained ready", err)
	}
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err != nil {
		t.Fatal("configuration-only rollback failed", err)
	}
	var restored bool
	if err := f.admin.QueryRow(ctx, `SELECT to_regclass('public.zasp_audit_export_policies') IS NULL AND zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&restored); err != nil || !restored {
		t.Fatal("configuration-only rollback did not restore 51", err)
	}
	installAuditExports(t, ctx, f.admin)
	if err := f.admin.QueryRow(ctx, `SELECT count(*)=0 FROM zasp_audit_export_policies`).Scan(&restored); err != nil || !restored {
		t.Fatal("reinstall retained old configuration", err)
	}
}

func TestAuditExportPostgresPolicyWaitRechecksRelease(t *testing.T) {
	for _, operation := range []string{"configure", "create"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			query := postgresAuditExportCreateSQL
			args := f.createArgs()
			if operation == "configure" {
				connection, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close(context.Background())
				f.api = connection
				config := auditExportTestPolicy()
				query = `SELECT zasp_audit_export_configure($1,$2,$3,$4,$5,$6,$7,$8,$9)`
				args = []any{"pid_52000044-0000-4000-8000-000000000044", config.PolicyID, config.Bucket, config.ExpectedBucketOwner, config.KMSKeyARN, config.MaximumExportBytes, config.MaximumRetainedBytes, config.MaximumInflight, config.CaptureTimeoutSeconds}
			}
			err := auditExportBlockedCall(t, ctx, f, query, args, `SELECT policy_id FROM zasp_audit_export_current_policy WHERE singleton FOR UPDATE`, nil, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
				return err
			})
			if auditExportSQLState(err) != "55000" {
				t.Fatal("policy wait accepted release drift", err)
			}
			var unchanged bool
			if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_policies)=1 AND (SELECT count(*) FROM zasp_audit_export_jobs)=0 AND (SELECT count(*) FROM zasp_audit_export_idempotency)=0 AND (SELECT count(*) FROM zasp_audit_export_outbox)=0 AND NOT EXISTS(SELECT 1 FROM zasp_admin_audit WHERE action='audit_export.request')`).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("postwait refusal retained effects", err)
			}
		})
	}
}

func auditExportPGFixture(t *testing.T, ctx context.Context) auditExportPG {
	return auditExportPGFixtureWithPolicy(t, ctx, auditExportTestPolicy())
}

func auditExportPGFixtureWithPolicy(t *testing.T, ctx context.Context, policy migrations.AuditExportConfiguration) auditExportPG {
	t.Helper()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	api := sandboxSessionAPI(t, ctx, admin)
	installAuditExports(t, ctx, admin)
	if err := precisionMigrationRunner(t, admin).ConfigureAuditExports(ctx, policy); err != nil {
		t.Fatal("registered owner policy configuration", err)
	}
	f := auditExportPG{admin: admin, api: api, identity: fixtureRequestIdentity(t), digest: sha256.Sum256([]byte("owned-audit-export-browser-fixture"))}
	_, err := admin.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($1,$2,$3,$4,$5,'["view_audit"]',$6,clock_timestamp()+interval '1 hour',clock_timestamp())`, f.digest[:], f.identity.PrincipalID.String(), f.identity.Scope.OrganizationID().String(), f.identity.Scope.WorkspaceID().String(), f.identity.Scope.EnvironmentID().String(), f.identity.CSRFToken)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f auditExportPG) createArgs() []any {
	request := sha256.Sum256([]byte("{}"))
	return []any{f.identity.Scope.OrganizationID().String(), f.identity.Scope.WorkspaceID().String(), f.identity.Scope.EnvironmentID().String(), f.identity.PrincipalID.String(), f.digest[:], f.identity.CSRFToken, "audit-export-postgres-key", "pid_52000001-0000-4000-8000-000000000001", "pid_52000002-0000-4000-8000-000000000002", "pid_52000003-0000-4000-8000-000000000003", request[:], migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()}
}

func (f auditExportPG) register(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := precisionMigrationRunner(t, f.admin).RegisterAuditExportAPI(ctx, f.api.Config().User); err != nil {
		t.Fatal("registered export runner capability unavailable", err)
	}
	var registered bool
	if err := f.admin.QueryRow(ctx, `SELECT zasp_audit_export_register_api($1)`, f.api.Config().User).Scan(&registered); err != nil || !registered {
		t.Fatal("registered export API capability unavailable", err)
	}
}

func TestAuditExportPostgresUsesVerifiedGroupScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	args := f.createArgs()
	f.groupScope(t, ctx)
	var body json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); err != nil {
		t.Fatal("current verified security-admin scope rejected", err)
	}
	if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_identity_member_groups WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3]); err != nil {
		t.Fatal(err)
	}
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("revoked group scope accepted on replay", err)
	}
}

func (f auditExportPG) groupScope(t *testing.T, ctx context.Context) {
	t.Helper()
	args := f.createArgs()
	for _, fixture := range []struct {
		statement string
		args      []any
	}{
		{`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, []any{args[0], args[3]}},
		{`DELETE FROM zasp_authorized_scopes WHERE organization_id=$1 AND principal_id=$4 AND workspace_id=$2 AND environment_id=$3`, args[:4]},
		{`INSERT INTO zasp_identity_member_groups(organization_id,principal_id,group_reference) VALUES($1,$2,'scim-group-test-audit-export')`, []any{args[0], args[3]}},
		{`INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($1,'scim-group-test-audit-export','security_admin',$2,$3)`, args[:3]},
	} {
		if _, err := f.admin.Exec(ctx, fixture.statement, fixture.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditExportPostgresCreatesDurableQueuedJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	args := f.createArgs()
	var created, replay json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&created); err != nil {
		t.Fatal("authorized durable create unavailable", err)
	}
	descriptor, err := decodeAuditExportDescriptor(created)
	if err != nil || descriptor.Status != "queued" || descriptor.ID != args[7] || descriptor.AuditCorrelationID != args[8] || descriptor.EventCount != nil {
		t.Fatal("invalid queued descriptor", err)
	}
	args[7], args[8], args[9] = "pid_52000011-0000-4000-8000-000000000001", "pid_52000012-0000-4000-8000-000000000002", "pid_52000013-0000-4000-8000-000000000003"
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&replay); err != nil || string(created) != string(replay) {
		t.Fatal("idempotent create changed authority", err)
	}
	var counts []int64
	if err := f.admin.QueryRow(ctx, `SELECT ARRAY[(SELECT count(*) FROM zasp_audit_export_jobs),(SELECT count(*) FROM zasp_audit_export_idempotency),(SELECT count(*) FROM zasp_audit_export_outbox),(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.request')]`).Scan(&counts); err != nil {
		t.Fatal(err)
	}
	for _, count := range counts {
		if count != 1 {
			t.Fatal("create/replay did not retain exactly one job, key, outbox and request audit", counts)
		}
	}
	readArgs := append(append([]any(nil), args[:6]...), descriptor.ID, int64(1), nil, args[11], args[12])
	var read struct {
		Export    AuditExportDescriptor `json:"export"`
		Authority json.RawMessage       `json:"authority"`
	}
	var body json.RawMessage
	if err := f.api.QueryRow(ctx, `SELECT zasp_audit_export_get($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, readArgs...).Scan(&body); err != nil || json.Unmarshal(body, &read) != nil || read.Export.ID != descriptor.ID || string(read.Authority) != "null" {
		t.Fatal("queued read returned false contents or lost descriptor", err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	if version, err := database.SchemaVersion(ctx); err != nil || version != ProductionRecoverySchemaVersion {
		t.Fatal("actual Go schema readiness rejected", version, err)
	}
	if payload, err := database.QueryJSON(ctx, postgresAuditExportReadySQL, args[11], args[12]); err != nil || string(payload) != "true" {
		t.Fatal("actual Go JSON capability readiness rejected", string(payload), err)
	}
	repository, err := NewAuditExportRepository(database)
	if err != nil {
		t.Fatal("actual Go export repository unavailable", err)
	}
	identity := f.identity
	identity.Permissions = []string{"view", "view_audit"}
	goCreated, err := repository.Create(ctx, identity, AuditExportCreate{ExportID: args[7].(string), AuditID: args[8].(string), OutboxID: args[9].(string), IdempotencyKey: args[6].(string), SessionDigest: f.digest[:]})
	if err != nil || goCreated.ID != descriptor.ID {
		t.Fatal("Go create replay lost persisted authority", err)
	}
	goRead, err := repository.Get(ctx, identity, AuditExportRead{ExportID: descriptor.ID, SessionDigest: f.digest[:], ChunkOrdinal: 1})
	if err != nil || goRead.export.ID != descriptor.ID || goRead.authority != nil {
		t.Fatal("Go queued Get mismatch", err)
	}
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err == nil {
		t.Fatal("rollback erased retained export authority")
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatal("rejected rollback damaged export authority", err)
	}
}

func TestAuditExportPostgresSameKeyRace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	second, err := pgx.ConnectConfig(ctx, f.api.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	child, stop := context.WithTimeout(ctx, 10*time.Second)
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 2)
	received := 0
	defer func() {
		stop()
		for received < 2 {
			select {
			case <-done:
				received++
			case <-time.After(5 * time.Second):
				t.Error("same-key API race did not join")
				return
			}
		}
	}()
	start := make(chan struct{})
	for index, connection := range []*pgx.Conn{f.api, second} {
		args := f.createArgs()
		if index == 1 {
			args[7] = "pid_52000031-0000-4000-8000-000000000031"
			args[8] = "pid_52000032-0000-4000-8000-000000000032"
			args[9] = "pid_52000033-0000-4000-8000-000000000033"
		}
		go func() {
			<-start
			var body []byte
			err := connection.QueryRow(child, postgresAuditExportCreateSQL, args...).Scan(&body)
			done <- result{body, err}
		}()
	}
	close(start)
	var first []byte
	for received < 2 {
		select {
		case value := <-done:
			received++
			if value.err != nil {
				t.Fatal(value.err)
			}
			if first == nil {
				first = value.body
			} else if string(first) != string(value.body) {
				t.Fatal("same-key race returned different jobs")
			}
		case <-child.Done():
			t.Fatal("same-key race timed out")
		}
	}
	var single bool
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_jobs)=1 AND (SELECT count(*) FROM zasp_audit_export_outbox)=1 AND (SELECT count(*) FROM zasp_audit_export_idempotency)=1 AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.request')=1`).Scan(&single); err != nil || !single {
		t.Fatal("same-key race created duplicate or partial effects", err)
	}
}

// The callback runs only after PostgreSQL reports the exact API connection is
// blocked. Own cancellation and joining before either fixture connection closes.
func auditExportBlockedCall(t *testing.T, ctx context.Context, f auditExportPG, statement string, args []any, lockStatement string, lockArgs []any, blocked func(pgx.Tx) error) error {
	t.Helper()
	child, cancel := context.WithTimeout(ctx, 20*time.Second)
	blocker, err := f.admin.Begin(child)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	observer, err := pgx.ConnectConfig(child, f.admin.Config().Copy())
	if err != nil {
		cancel()
		_ = blocker.Rollback(context.Background())
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	if _, err := blocker.Exec(child, lockStatement, lockArgs...); err != nil {
		cancel()
		_ = blocker.Rollback(context.Background())
		t.Fatal(err)
	}
	done := make(chan error, 1)
	settled := false
	defer func() {
		cancel()
		_ = blocker.Rollback(context.Background())
		if !settled {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("export API call failed to join")
			}
		}
	}()
	go func() { var body []byte; done <- f.api.QueryRow(child, statement, args...).Scan(&body) }()
	for {
		var waiting bool
		if err := observer.QueryRow(child, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, f.api.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			settled = true
			t.Fatal("call failed before lock", err)
		case <-child.Done():
			t.Fatal("call never reached lock")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := blocked(blocker); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(child); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		settled = true
		return err
	case <-child.Done():
		t.Fatal("call did not settle")
		return child.Err()
	}
}

func TestAuditExportPostgresRefusesPostWaitChange(t *testing.T) {
	for _, mode := range []string{"create-drift", "create-scope-revoked", "create-group-revoked", "create-expired", "membership-revoked", "get-drift"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			args := f.createArgs()
			lock := `SELECT pg_advisory_xact_lock(hashtextextended(concat_ws('|','zasp-audit-export-create',$1::text,$2::text,$3::text,$4::text,$5::text),0))`
			lockArgs := append(append([]any(nil), args[:4]...), args[6])
			statement := postgresAuditExportCreateSQL
			state := "55000"
			if mode == "get-drift" {
				var body []byte
				if err := f.api.QueryRow(ctx, statement, args...).Scan(&body); err != nil {
					t.Fatal(err)
				}
				statement = postgresAuditExportGetSQL
				lock = `SELECT 1 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2 FOR UPDATE`
				lockArgs = []any{args[0], args[7]}
				args = append(append([]any(nil), args[:6]...), args[7], int64(1), nil, args[11], args[12])
			}
			if mode == "membership-revoked" {
				lock = `SELECT 1 FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2 FOR UPDATE`
				lockArgs = []any{args[0], args[3]}
				state = "42501"
			}
			if mode == "create-scope-revoked" {
				state = "42501"
			}
			if mode == "create-group-revoked" {
				state = "42501"
				f.groupScope(t, ctx)
			}
			if mode == "create-expired" {
				state = "28000"
				if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE token_digest=$1`, f.digest[:]); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				var value string
				if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('jobs',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM zasp_audit_export_jobs t),'keys',(SELECT jsonb_agg(to_jsonb(t) ORDER BY export_id) FROM zasp_audit_export_idempotency t),'outbox',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM zasp_audit_export_outbox t),'audit',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM zasp_admin_audit t WHERE action='audit_export.request'))::text`).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			err := auditExportBlockedCall(t, ctx, f, statement, args, lock, lockArgs, func(tx pgx.Tx) error {
				var err error
				switch mode {
				case "create-scope-revoked":
					_, err = tx.Exec(ctx, `DELETE FROM zasp_authorized_scopes WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3])
				case "create-group-revoked":
					_, err = tx.Exec(ctx, `DELETE FROM zasp_identity_member_groups WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3])
				case "membership-revoked":
					_, err = tx.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3])
				case "create-expired":
					_, err = tx.Exec(ctx, `SELECT pg_sleep(2.1)`)
				default:
					_, err = tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
				}
				return err
			})
			if auditExportSQLState(err) != state {
				t.Error("postwait authority change accepted or wrong refusal", err)
			}
			if snapshot() != before {
				t.Error("postwait refusal left export effects")
			}
		})
	}
}

func auditExportSQLState(err error) string {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return databaseError.Code
	}
	return ""
}

func TestAuditExportPostgresReadKeepsPhysicalScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	args := f.createArgs()
	var created []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&created); err != nil {
		t.Fatal(err)
	}
	workspace := "pid_52000021-0000-4000-8000-000000000021"
	environment := "pid_52000022-0000-4000-8000-000000000022"
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(organization_id,principal_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$3,$4,'Another current scope','["view_audit"]')`, args[0], args[3], workspace, environment); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET workspace_id=$2,environment_id=$3,authenticated_at=clock_timestamp()-interval '1 hour' WHERE token_digest=$1`, f.digest[:], workspace, environment); err != nil {
		t.Fatal(err)
	}
	readArgs := []any{args[0], workspace, environment, args[3], args[4], args[5], args[7], int64(1), nil, args[11], args[12]}
	var result struct {
		Export    AuditExportDescriptor `json:"export"`
		Authority json.RawMessage       `json:"authority"`
	}
	var body []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, readArgs...).Scan(&body); err != nil || json.Unmarshal(body, &result) != nil || result.Export.WorkspaceID != args[1] || result.Export.EnvironmentID != args[2] || string(result.Authority) != "null" {
		t.Fatal("read changed immutable physical scope or required fresh auth", err)
	}
	readArgs[6] = "pid_52000023-0000-4000-8000-000000000023"
	if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, readArgs...).Scan(&body); auditExportSQLState(err) != "P0002" {
		t.Fatal("missing export not scoped404", err)
	}
	foreignOrg := "pid_52000024-0000-4000-8000-000000000024"
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role) VALUES($1,$2,'owned-export-foreign-org','owned-export-foreign-member','security_admin')`, foreignOrg, args[3]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(organization_id,principal_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$3,$4,'Foreign scope','["view_audit"]')`, foreignOrg, args[3], workspace, environment); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET organization_id=$2 WHERE token_digest=$1`, f.digest[:], foreignOrg); err != nil {
		t.Fatal(err)
	}
	readArgs[0] = foreignOrg
	readArgs[6] = args[7]
	if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, readArgs...).Scan(&body); auditExportSQLState(err) != "P0002" {
		t.Fatal("foreign export existence leaked", err)
	}
	var count int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_admin_audit WHERE action LIKE 'audit_export.%'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("read mutated export audit", err)
	}
}

func TestAuditExportPostgresRechecksBrowserAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	args := f.createArgs()
	var body json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); auditExportSQLState(err) != "42501" {
		t.Fatal("unregistered capability accepted", err)
	}
	f.register(t, ctx)
	for _, test := range []struct {
		name, change, restore, state string
		mutate                       func([]any)
	}{
		{name: "missing-session", state: "28000", mutate: func(args []any) { digest := sha256.Sum256([]byte("unknown-owned-session")); args[4] = digest[:] }},
		{name: "csrf", state: "42501", mutate: func(args []any) { args[5] = "different-csrf-value-at-least-32-bytes" }},
		{name: "request-digest", state: "22023", mutate: func(args []any) { digest := sha256.Sum256([]byte(`{"unexpected":true}`)); args[10] = digest[:] }},
		{name: "expired", change: `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE token_digest=$1`, restore: `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE token_digest=$1`, state: "28000"},
		{name: "revoked", change: `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, restore: `UPDATE zasp_product_sessions SET revoked_at=NULL WHERE token_digest=$1`, state: "28000"},
		{name: "stale-auth", change: `UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE token_digest=$1`, restore: `UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp() WHERE token_digest=$1`, state: "42501"},
		{name: "membership-role", change: `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE principal_id=(SELECT principal_id FROM zasp_product_sessions WHERE token_digest=$1)`, restore: `UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=(SELECT principal_id FROM zasp_product_sessions WHERE token_digest=$1)`, state: "42501"},
		{name: "membership-inactive", change: `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT principal_id FROM zasp_product_sessions WHERE token_digest=$1)`, restore: `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=(SELECT principal_id FROM zasp_product_sessions WHERE token_digest=$1)`, state: "42501"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.change != "" {
				if _, err := f.admin.Exec(ctx, test.change, f.digest[:]); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := f.admin.Exec(ctx, test.restore, f.digest[:]); err != nil {
						t.Error(err)
					}
				}()
			}
			input := append([]any(nil), args...)
			if test.mutate != nil {
				test.mutate(input)
			}
			if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, input...).Scan(&body); auditExportSQLState(err) != test.state {
				t.Fatal("wrong refusal", err)
			}
			var unchanged bool
			if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_audit_export_jobs) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_idempotency) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_outbox) AND NOT EXISTS(SELECT 1 FROM zasp_admin_audit WHERE action='audit_export.request')`).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("refusal left partial export effects", err)
			}
		})
	}
	for _, statement := range []string{`SELECT * FROM zasp_audit_export_jobs`, `UPDATE zasp_audit_export_jobs SET status='processing'`, `DELETE FROM zasp_audit_export_api_bindings`, `SELECT zasp_audit_export_register_api('invocation_discovery_api')`} {
		if _, err := f.api.Exec(ctx, statement); auditExportSQLState(err) != "42501" {
			t.Fatal("API gained direct or registration authority", err)
		}
	}
}
