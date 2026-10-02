package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"reflect"
	"strings"
	"testing"
	"time"
)

type auditExportOutboxQueueDriver struct {
	messages []jobqueue.DriverMessage
	calls    int
	change   string
	cancel   context.CancelFunc
	deadline time.Time
}

func (d *auditExportOutboxQueueDriver) PublishBatch(ctx context.Context, messages []jobqueue.DriverMessage) ([]jobqueue.DriverPublished, error) {
	d.calls++
	if deadline, ok := ctx.Deadline(); ok {
		d.deadline = deadline
	}
	d.messages = append(d.messages, messages...)
	if d.change == "lost response" && d.calls == 1 {
		return nil, errors.New("saved publish response lost")
	}
	if d.change == "cancel" {
		d.cancel()
	}
	published := make([]jobqueue.DriverPublished, len(messages))
	for i, message := range messages {
		messageID := "audit-export-provider-" + message.JobID.String()
		if d.change == "invalid acknowledgement" {
			messageID = "invalid provider message id"
		}
		published[i] = jobqueue.DriverPublished{EntryID: message.EntryID, JobID: message.JobID, MessageID: messageID}
	}
	return published, nil
}
func (*auditExportOutboxQueueDriver) ConsumeBatch(context.Context, int) ([]jobqueue.DriverDelivery, error) {
	return nil, nil
}
func (*auditExportOutboxQueueDriver) AcknowledgeBatch(context.Context, []jobqueue.DriverReceipt) ([]domain.ProductID, error) {
	return nil, errors.New("outbox cannot acknowledge consumed work")
}

func auditExportOutboxTestProcessor(t *testing.T, a *postgresAuditExportOutboxAuthority, driver *auditExportOutboxQueueDriver, batch int) *auditExportOutboxProcessor {
	t.Helper()
	publisher, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: 30 * time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	p, err := newAuditExportOutboxProcessor(auditExportOutboxProcessorConfig{Authority: a, Publisher: publisher, WorkerID: "audit-export-outbox", LeaseSeconds: 180, BatchSize: batch, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuditExportOutboxEmptyOrMultiRowPublication(t *testing.T) {
	for _, count := range []int{0, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, db, _ := auditExportOutboxAuthorityFixture(t)
			driver := &auditExportOutboxQueueDriver{}
			p := auditExportOutboxTestProcessor(t, a, driver, 2)
			finishes := 0
			db.respond = func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				if sql == auditExportOutboxClaimSQL {
					rows := make([]any, 0, count)
					for i := 0; i < count; i++ {
						row := auditExportOutboxWire()
						row["export_id"] = fmt.Sprintf("pid_520000%02d-0000-4000-8000-0000000000%02d", 50+i, 50+i)
						row["outbox_id"] = fmt.Sprintf("pid_520000%02d-0000-4000-8000-0000000000%02d", 70+i, 70+i)
						rows = append(rows, row)
					}
					return json.Marshal(rows)
				}
				if sql != auditExportOutboxFinishSQL {
					t.Fatal("valid batch retried")
				}
				id := fmt.Sprintf("pid_520000%02d-0000-4000-8000-0000000000%02d", 50+finishes, 50+finishes)
				outbox := fmt.Sprintf("pid_520000%02d-0000-4000-8000-0000000000%02d", 70+finishes, 70+finishes)
				ack, _ := jobqueue.CanonicalProviderAcknowledgement("audit-export-provider-" + id)
				if args[3] != outbox || args[8] != ack {
					t.Fatal("batch finish crossed acknowledgement/lease")
				}
				finishes++
				return json.RawMessage(`{"finished":true}`), nil
			}
			if p.RunOnce(context.Background()) != nil || finishes != count || len(driver.messages) != count {
				t.Fatal("batch silently lost or fabricated work")
			}
			if count == 0 && driver.calls != 0 {
				t.Fatal("empty claim published")
			}
		})
	}
}

func TestAuditExportOutboxProcessorRejectsInvalidConstructionAndGeneratedTokens(t *testing.T) {
	for _, failure := range []string{"authority", "publisher", "typed nil publisher", "worker", "lease", "batch", "retry", "token function"} {
		t.Run(failure, func(t *testing.T) {
			a, _, _ := auditExportOutboxAuthorityFixture(t)
			p := auditExportOutboxTestProcessor(t, a, &auditExportOutboxQueueDriver{}, 1)
			config := p.config
			switch failure {
			case "authority":
				config.Authority = nil
			case "publisher":
				config.Publisher = nil
			case "typed nil publisher":
				var queue *jobqueue.Queue
				config.Publisher = queue
			case "worker":
				config.WorkerID = "!"
			case "lease":
				config.LeaseSeconds = 301
			case "batch":
				config.BatchSize = 11
			case "retry":
				config.RetrySeconds = 0
			case "token function":
				config.NewLeaseToken = nil
			}
			if _, err := newAuditExportOutboxProcessor(config); err == nil {
				t.Fatal("invalid outbox process configuration accepted")
			}
		})
	}
	for name, token := range auditExportRejectedLeaseTokens() {
		t.Run(name, func(t *testing.T) {
			a, db, _ := auditExportOutboxAuthorityFixture(t)
			driver := &auditExportOutboxQueueDriver{}
			p := auditExportOutboxTestProcessor(t, a, driver, 1)
			p.config.NewLeaseToken = func() (string, error) { return token, nil }
			if p.RunOnce(context.Background()) == nil || len(db.queries) != 0 || driver.calls != 0 {
				t.Fatal("invalid generated token reached DB/provider")
			}
		})
	}
}

func TestAuditExportOutboxUncertainPublishRemainsRetryableAtSaturatedAttempt(t *testing.T) {
	for _, failure := range []string{"lost response", "finish before commit", "finish committed response lost"} {
		t.Run(failure, func(t *testing.T) {
			a, db, _ := auditExportOutboxAuthorityFixture(t)
			driver := &auditExportOutboxQueueDriver{change: failure}
			p := auditExportOutboxTestProcessor(t, a, driver, 1)
			claims, retries, finishes := 0, 0, 0
			delivered := false
			db.respond = func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				switch sql {
				case auditExportOutboxClaimSQL:
					claims++
					if delivered {
						return json.RawMessage(`[]`), nil
					}
					wire := auditExportOutboxWire()
					wire["generation"] = int64(6 + claims)
					wire["attempt"] = 100
					return json.Marshal([]any{wire})
				case auditExportOutboxRetrySQL:
					retries++
					if args[6] != int64(7) || args[7] != 100 || args[8] != 30 {
						t.Fatal("retry altered saturated attempt/generation fence")
					}
					return json.RawMessage(`{"retried":true}`), nil
				case auditExportOutboxFinishSQL:
					finishes++
					if args[6] != int64(6+claims) || args[7] != 100 {
						t.Fatal("completion lost new generation while attempt saturated")
					}
					if finishes == 1 && failure == "finish before commit" {
						return nil, errors.New("finish not committed")
					}
					delivered = true
					if finishes == 1 && failure == "finish committed response lost" {
						return nil, errors.New("finish response lost")
					}
					return json.RawMessage(`{"finished":true}`), nil
				}
				t.Fatal("unexpected outbox state transition")
				return nil, nil
			}
			if p.RunOnce(context.Background()) == nil {
				t.Fatal("uncertain publication/finish reported complete")
			}
			// New processor, same declared durable outbox/provider state. This is not
			// actual database or process restart proof.
			resumed := auditExportOutboxTestProcessor(t, a, driver, 1)
			if resumed.RunOnce(context.Background()) != nil || !delivered {
				t.Fatal("uncertain publish stranded durable outbox")
			}
			wantPublishes := 2
			if failure == "finish committed response lost" {
				wantPublishes = 1
			}
			if driver.calls != wantPublishes || claims != 2 {
				t.Fatal("replay publication disposition differs")
			}
			if failure == "lost response" && retries != 1 || failure != "lost response" && retries != 0 {
				t.Fatal("unexpected retry disposition")
			}
			if len(driver.messages) == 2 && string(driver.messages[0].Body) != string(driver.messages[1].Body) {
				t.Fatal("publication retry changed immutable wakeup")
			}
		})
	}
}

func TestAuditExportOutboxNoFinishAfterMalformedOrCanceledPublish(t *testing.T) {
	for _, failure := range []string{"invalid acknowledgement", "cancel", "readiness drift", "retry malformed"} {
		t.Run(failure, func(t *testing.T) {
			a, db, _ := auditExportOutboxAuthorityFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			driver := &auditExportOutboxQueueDriver{change: failure, cancel: cancel}
			if failure == "retry malformed" {
				driver.change = "invalid acknowledgement"
			}
			p := auditExportOutboxTestProcessor(t, a, driver, 1)
			finishes, retries := 0, 0
			db.respond = func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					if failure == "readiness drift" && driver.calls > 0 {
						return json.RawMessage(`false`), nil
					}
					return json.RawMessage(`true`), nil
				}
				if sql == auditExportOutboxClaimSQL {
					return json.Marshal([]any{auditExportOutboxWire()})
				}
				if sql == auditExportOutboxFinishSQL {
					finishes++
					return json.RawMessage(`{"finished":true}`), nil
				}
				if sql == auditExportOutboxRetrySQL {
					retries++
					if failure == "retry malformed" {
						return json.RawMessage(`{"retried":false}`), nil
					}
					return json.RawMessage(`{"retried":true}`), nil
				}
				t.Fatal("unexpected SQL")
				return nil, nil
			}
			if p.RunOnce(ctx) == nil || finishes != 0 {
				t.Fatal("unverified publication finished durable outbox")
			}
			if failure == "cancel" && retries != 0 {
				t.Fatal("canceled caller detached retry SQL")
			}
			if failure == "invalid acknowledgement" && retries != 1 {
				t.Fatal("unknown publication was not retained for retry")
			}
		})
	}
}

func TestAuditExportOutboxPublishHonorsRemainingLeaseAndParentBudget(t *testing.T) {
	for _, parentBound := range []bool{false, true} {
		t.Run(fmt.Sprint(parentBound), func(t *testing.T) {
			a, db, _ := auditExportOutboxAuthorityFixture(t)
			driver := &auditExportOutboxQueueDriver{}
			p := auditExportOutboxTestProcessor(t, a, driver, 1)
			expiry := time.Now().Add(8 * time.Second)
			ctx := context.Background()
			want := expiry.Add(-5 * time.Second)
			if parentBound {
				var cancel context.CancelFunc
				want = time.Now().Add(time.Second)
				ctx, cancel = context.WithDeadline(ctx, want)
				defer cancel()
			}
			db.respond = func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				if sql == auditExportOutboxClaimSQL {
					wire := auditExportOutboxWire()
					wire["lease_expires_at"] = expiry
					return json.Marshal([]any{wire})
				}
				return json.RawMessage(`{"finished":true}`), nil
			}
			if p.RunOnce(ctx) != nil || !driver.deadline.Equal(want) {
				t.Fatal("publication extended confirmed lease/caller budget")
			}
		})
	}
}

func TestAuditExportOutboxPublishesCanonicalWakeupBeforeFencedFinish(t *testing.T) {
	a, db, _ := auditExportOutboxAuthorityFixture(t)
	f := newAuditExportExecutionFixture(t, true)
	expected := auditExportDispatchJobFixture(t, f)
	driver := &runtimeCoordinatorQueueDriver{steps: &runtimeCoordinatorSteps{}, messageID: "audit-export-provider-message-1"}
	publisher, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	finished := false
	db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
		if sql == auditExportWorkerReadySQL {
			return json.RawMessage(`true`), nil
		}
		if sql == auditExportOutboxClaimSQL {
			return json.Marshal([]any{auditExportOutboxWire()})
		}
		if sql != auditExportOutboxFinishSQL {
			t.Fatal("successful publish must finish, not retry")
		}
		if driver.message.JobID != expected.JobID || driver.message.Scope != expected.Scope || driver.message.Kind != "audit-export" {
			t.Fatal("finish preceded canonical scoped publish")
		}
		expectedAck, _ := jobqueue.CanonicalProviderAcknowledgement("audit-export-provider-message-1")
		if args[8] != expectedAck {
			t.Fatal("unverified provider acknowledgement persisted")
		}
		finished = true
		return json.RawMessage(`{"finished":true}`), nil
	}
	p, err := newAuditExportOutboxProcessor(auditExportOutboxProcessorConfig{Authority: a, Publisher: publisher, WorkerID: "audit-export-outbox", LeaseSeconds: 180, BatchSize: 1, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if p.RunOnce(context.Background()) != nil || !finished {
		t.Fatal("real queue publication and durable finish missing")
	}
	deliveries, err := publisher.ConsumeBatch(context.Background(), 1)
	if err != nil || len(deliveries) != 1 || string(deliveries[0].Job.Payload) != string(expected.Payload) || deliveries[0].Job.AuthorityDigest != expected.AuthorityDigest {
		t.Fatal("published wakeup differs from canonical persisted identities", err)
	}
}

func TestAuditExportOutboxEmptyAndMaximumClaimsPreserveExpiryInstant(t *testing.T) {
	for _, count := range []int{0, 10} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, db, _ := auditExportOutboxAuthorityFixture(t)
			expiry := time.Now().Add(179 * time.Second)
			db.respond = func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				rows := make([]any, 0, count)
				for i := 0; i < count; i++ {
					w := auditExportOutboxWire()
					w["export_id"] = fmt.Sprintf("pid_520000%02d-0000-4000-8000-0000000000%02d", 50+i, 50+i)
					w["outbox_id"] = fmt.Sprintf("pid_520000%02d-0000-4000-8000-0000000000%02d", 70+i, 70+i)
					w["lease_expires_at"] = expiry.In(time.FixedZone("fixture", -7*60*60)).Format(time.RFC3339Nano)
					rows = append(rows, w)
				}
				return json.Marshal(rows)
			}
			leases, err := a.Claim(context.Background(), "audit-export-outbox", strings.Repeat("a", 64), 180, 10)
			if err != nil || leases == nil || len(leases) != count {
				t.Fatal("bounded valid claim refused", err)
			}
			for _, lease := range leases {
				if lease.ExpiresAt.Location() != time.UTC || !lease.ExpiresAt.Equal(expiry) {
					t.Fatal("SQL timezone changed lease instant")
				}
			}
		})
	}
}

func TestAuditExportOutboxPreservesEarlierCallerDeadline(t *testing.T) {
	a, db, lease := auditExportOutboxAuthorityFixture(t)
	deadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	db.respond = func(call context.Context, sql string, _ ...any) (json.RawMessage, error) {
		actual, ok := call.Deadline()
		if !ok || !actual.Equal(deadline) {
			t.Fatal("caller deadline detached or extended")
		}
		if sql == auditExportWorkerReadySQL {
			return json.RawMessage(`true`), nil
		}
		if sql == auditExportOutboxFinishSQL {
			return json.RawMessage(`{"finished":true}`), nil
		}
		if sql == auditExportOutboxRetrySQL {
			return json.RawMessage(`{"retried":true}`), nil
		}
		return json.Marshal([]any{auditExportOutboxWire()})
	}
	if _, err := a.Claim(ctx, "audit-export-outbox", strings.Repeat("a", 64), 180, 1); err != nil {
		t.Fatal(err)
	}
	if a.Finish(ctx, lease, "sha256:"+strings.Repeat("a", 64)) != nil || a.Retry(ctx, lease, 30) != nil {
		t.Fatal("bounded transition refused")
	}
}

func TestAuditExportOutboxRejectsNonSQLLeaseTokens(t *testing.T) {
	for name, token := range auditExportRejectedLeaseTokens() {
		t.Run(name, func(t *testing.T) {
			a, db, lease := auditExportOutboxAuthorityFixture(t)
			if _, err := a.Claim(context.Background(), "audit-export-outbox", token, 180, 1); err == nil || len(db.queries) != 0 {
				t.Fatal("non-SQL token reached outbox claim")
			}
			lease.token = token
			if a.Finish(context.Background(), lease, "sha256:"+strings.Repeat("a", 64)) == nil || a.Retry(context.Background(), lease, 30) == nil || len(db.queries) != 0 {
				t.Fatal("non-SQL token reached outbox transition")
			}
		})
	}
}

func auditExportOutboxWire() map[string]any {
	return map[string]any{"organization_id": "pid_52000001-0000-4000-8000-000000000001", "workspace_id": "pid_52000002-0000-4000-8000-000000000002", "environment_id": "pid_52000003-0000-4000-8000-000000000003", "outbox_id": "pid_52000030-0000-4000-8000-000000000030", "export_id": "pid_52000004-0000-4000-8000-000000000004", "policy_id": "pid_52000041-0000-4000-8000-000000000041", "generation": int64(7), "attempt": 2, "lease_expires_at": time.Now().UTC().Add(179 * time.Second).Format(time.RFC3339Nano)}
}

func auditExportOutboxAuthorityFixture(t *testing.T) (*postgresAuditExportOutboxAuthority, *auditExportWorkerDatabase, auditExportOutboxLease) {
	t.Helper()
	db := &auditExportWorkerDatabase{}
	db.respond = func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
		if sql == auditExportWorkerReadySQL {
			return json.RawMessage(`true`), nil
		}
		return json.Marshal([]any{auditExportOutboxWire()})
	}
	a, err := newPostgresAuditExportOutboxAuthority(db)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := a.Claim(context.Background(), "audit-export-outbox", strings.Repeat("a", 64), 180, 1)
	if err != nil || len(leases) != 1 {
		t.Fatal("fixture lease", err)
	}
	db.queries = nil
	return a, db, leases[0]
}

func TestAuditExportOutboxFreshReadinessRefusesAllOperations(t *testing.T) {
	for _, operation := range []string{"claim", "finish", "retry"} {
		for _, failure := range []string{"false", "null", "empty", "type", "trailing", "duplicate", "database", "panic", "cancel"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				a, db, lease := auditExportOutboxAuthorityFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				db.respond = func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
					if sql != auditExportWorkerReadySQL {
						t.Fatal("operation SQL reached after failed readiness")
					}
					switch failure {
					case "database":
						return nil, errors.New("unavailable")
					case "panic":
						panic("unavailable")
					case "cancel":
						cancel()
						return json.RawMessage(`true`), nil
					case "empty":
						return nil, nil
					case "type":
						return json.RawMessage(`"true"`), nil
					case "trailing":
						return json.RawMessage(`true false`), nil
					case "duplicate":
						return json.RawMessage(`{"ready":true,"ready":true}`), nil
					}
					return json.RawMessage(failure), nil
				}
				var err error
				switch operation {
				case "claim":
					_, err = a.Claim(ctx, "audit-export-outbox", strings.Repeat("a", 64), 180, 1)
				case "finish":
					err = a.Finish(ctx, lease, "sha256:"+strings.Repeat("a", 64))
				case "retry":
					err = a.Retry(ctx, lease, 30)
				}
				if err == nil || len(db.queries) != 1 {
					t.Fatal("readiness refused without exactly one SQL check", err, len(db.queries))
				}
			})
		}
	}
}

func TestAuditExportOutboxClaimRejectsMalformedDurableBindings(t *testing.T) {
	for _, failure := range []string{"null", "object", "trailing", "oversize", "duplicate outbox", "duplicate export", "over limit", "unknown", "alias", "duplicate key", "missing", "bad scope", "bad export", "bad policy", "outbox alias", "zero generation", "unsafe generation", "zero attempt", "over attempt", "expired", "far expiry"} {
		t.Run(failure, func(t *testing.T) {
			a, db, _ := auditExportOutboxAuthorityFixture(t)
			db.respond = func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				w := auditExportOutboxWire()
				switch failure {
				case "null":
					return json.RawMessage(`null`), nil
				case "object":
					return json.RawMessage(`{"items":[]}`), nil
				case "trailing":
					return json.RawMessage(`[] []`), nil
				case "oversize":
					return json.RawMessage(strings.Repeat(" ", 16385)), nil
				case "unknown":
					w["bucket"] = "foreign"
				case "alias":
					w["Policy_ID"] = w["policy_id"]
					delete(w, "policy_id")
				case "missing":
					delete(w, "attempt")
				case "bad scope":
					w["organization_id"] = "invalid"
				case "bad export":
					w["export_id"] = "invalid"
				case "bad policy":
					w["policy_id"] = "invalid"
				case "outbox alias":
					w["outbox_id"] = w["export_id"]
				case "zero generation":
					w["generation"] = 0
				case "unsafe generation":
					w["generation"] = int64(9007199254740992)
				case "zero attempt":
					w["attempt"] = 0
				case "over attempt":
					w["attempt"] = 101
				case "expired":
					w["lease_expires_at"] = time.Now().Add(-time.Second)
				case "far expiry":
					w["lease_expires_at"] = time.Now().Add(time.Hour)
				}
				if failure == "duplicate key" {
					b, _ := json.Marshal(w)
					return json.RawMessage("[" + strings.Replace(string(b), `"attempt":2`, `"attempt":2,"attempt":2`, 1) + "]"), nil
				}
				if failure == "duplicate outbox" || failure == "over limit" {
					return json.Marshal([]any{w, w})
				}
				if failure == "duplicate export" {
					other := auditExportOutboxWire()
					other["outbox_id"] = "pid_52000031-0000-4000-8000-000000000031"
					return json.Marshal([]any{w, other})
				}
				return json.Marshal([]any{w})
			}
			limit := 2
			if failure == "over limit" {
				limit = 1
			}
			if _, err := a.Claim(context.Background(), "audit-export-outbox", strings.Repeat("a", 64), 180, limit); err == nil {
				t.Fatal("malformed persisted lease accepted")
			}
		})
	}
}

func TestAuditExportOutboxTransitionsRejectUnconfirmedResultsAndForeignLeases(t *testing.T) {
	for _, operation := range []string{"finish", "retry"} {
		for _, failure := range []string{"false", "null", "missing", "alias", "duplicate", "unknown", "trailing", "lost response", "cancel", "foreign owner", "expired", "invalid input"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				a, db, lease := auditExportOutboxAuthorityFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				key := "finished"
				if operation == "retry" {
					key = "retried"
				}
				db.respond = func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
					if sql == auditExportWorkerReadySQL {
						return json.RawMessage(`true`), nil
					}
					switch failure {
					case "lost response":
						return nil, errors.New("response lost")
					case "cancel":
						cancel()
						return json.RawMessage(`{"` + key + `":true}`), nil
					case "null":
						return json.RawMessage(`{"` + key + `":null}`), nil
					case "missing":
						return json.RawMessage(`{}`), nil
					case "alias":
						return json.RawMessage(`{"` + strings.ToUpper(key) + `":true}`), nil
					case "duplicate":
						return json.RawMessage(`{"` + key + `":true,"` + key + `":true}`), nil
					case "unknown":
						return json.RawMessage(`{"` + key + `":true,"extra":true}`), nil
					case "trailing":
						return json.RawMessage(`{"` + key + `":true} {}`), nil
					}
					return json.RawMessage(`{"` + key + `":false}`), nil
				}
				if failure == "foreign owner" {
					lease.owner = &postgresAuditExportOutboxAuthority{wire: a.wire}
				}
				if failure == "expired" {
					lease.ExpiresAt = time.Now().Add(4 * time.Second)
				}
				ack, seconds := "sha256:"+strings.Repeat("a", 64), 30
				if failure == "invalid input" {
					ack = "raw-provider-id"
					seconds = 301
				}
				var err error
				if operation == "finish" {
					err = a.Finish(ctx, lease, ack)
				} else {
					err = a.Retry(ctx, lease, seconds)
				}
				if err == nil {
					t.Fatal("unconfirmed transition accepted")
				}
				if (failure == "foreign owner" || failure == "expired" || failure == "invalid input") && len(db.queries) != 0 {
					t.Fatal("invalid local authority reached SQL")
				}
			})
		}
	}
}

// Declared SQL only: real compiled-pin authority/argument and decoder behavior,
// not installed PostgreSQL or successful provider publication evidence.
func TestAuditExportOutboxAuthorityBindsClaimAndTransitions(t *testing.T) {
	db := &auditExportWorkerDatabase{}
	wire := auditExportOutboxWire()
	operations := 0
	db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
		if sql == auditExportWorkerReadySQL {
			if !reflect.DeepEqual(args, []any{migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint(), "zasp_audit_export_outbox"}) {
				t.Fatal("outbox readiness identity differs")
			}
			return json.RawMessage(`true`), nil
		}
		operations++
		switch sql {
		case auditExportOutboxClaimSQL:
			if !reflect.DeepEqual(args, []any{"audit-export-outbox", strings.Repeat("a", 64), 180, 2, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()}) {
				t.Fatal("claim scope/fence arguments differ")
			}
			return json.Marshal([]any{wire})
		case auditExportOutboxFinishSQL, auditExportOutboxRetrySQL:
			var transition any = "sha256:" + strings.Repeat("a", 64)
			if sql == auditExportOutboxRetrySQL {
				transition = 30
			}
			want := []any{wire["organization_id"], wire["workspace_id"], wire["environment_id"], wire["outbox_id"], "audit-export-outbox", strings.Repeat("a", 64), int64(7), 2, transition, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()}
			if !reflect.DeepEqual(args, want) {
				t.Fatal("transition lost scoped lease fence")
			}
			if sql == auditExportOutboxRetrySQL {
				return json.RawMessage(`{"retried":true}`), nil
			}
			return json.RawMessage(`{"finished":true}`), nil
		}
		t.Fatal("unexpected SQL")
		return nil, nil
	}
	a, err := newPostgresAuditExportOutboxAuthority(db)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := a.Claim(context.Background(), "audit-export-outbox", strings.Repeat("a", 64), 180, 2)
	if err != nil || len(leases) != 1 {
		t.Fatalf("valid claim refused: %v", err)
	}
	lease := leases[0]
	if lease.ExportID != wire["export_id"] || lease.PolicyID != wire["policy_id"] || lease.Generation != 7 || lease.Attempt != 2 || lease.ExpiresAt.Location() != time.UTC {
		t.Fatal("claim lost persisted identity")
	}
	if a.Finish(context.Background(), lease, "sha256:"+strings.Repeat("a", 64)) != nil || a.Retry(context.Background(), lease, 30) != nil {
		t.Fatal("valid fenced transition refused")
	}
	if operations != 3 || len(db.queries) != 7 {
		t.Fatalf("startup plus every operation readiness omitted: queries=%d ops=%d", len(db.queries), operations)
	}
}
