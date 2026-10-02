package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type reconcileQueryFixture struct {
	call func(context.Context, string, ...any) (json.RawMessage, error)
}

func TestExistingTestClientCancelStoppedFencesReceipts(t *testing.T) {
	_, _, r := fixtureExistingTestEvidence(t)
	for _, mode := range []string{"cancelled", "unknown", "noop", "noop_unknown", "run", "changed_null", "state", "classification", "expired", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
			claim := existingTestClaim{scope: r.Scope, run: snapshotRun, step: snapshotStep, testRun: r.RunID, version: 2, generation: snapshotGeneration, expires: now.Add(time.Minute), worker: "stop-client", token: [32]byte{1}}
			db := &reconcileQueryFixture{call: func(_ context.Context, q string, args ...any) (json.RawMessage, error) {
				want := append(claim.args(), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
				if q != "SELECT zasp_production_security_agent_existing_tests_reconcile_cancel_stopped($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)" || !reflect.DeepEqual(args, want) {
					t.Fatal("cancellation lost guarded ownership")
				}
				v := map[string]any{"test_run_id": r.RunID, "state": "cancelled", "generation": snapshotGeneration, "cancellation_outcome": "cancelled_before_execution", "changed": true}
				switch mode {
				case "unknown":
					v["state"], v["cancellation_outcome"] = "failed", "outcome_unknown"
				case "noop":
					v["state"], v["cancellation_outcome"], v["changed"] = "queued", nil, false
				case "noop_unknown":
					v["state"], v["cancellation_outcome"], v["changed"] = "queued", "outcome_unknown", false
				case "run":
					v["test_run_id"] = snapshotRun
				case "changed_null":
					v["changed"] = nil
				case "state":
					v["state"] = "queued"
				case "classification":
					v["cancellation_outcome"] = "outcome_unknown"
				case "expired":
					now = now.Add(time.Minute)
				}
				b, _ := json.Marshal(v)
				if mode == "duplicate" {
					b = []byte(strings.Replace(string(b), `"changed":true`, `"changed":true,"changed":true`, 1))
				}
				return b, nil
			}}
			client, _ := newExistingTestClient(db, "stop-client", func() time.Time { return now })
			err := client.CancelStopped(context.Background(), claim)
			want := mode == "cancelled" || mode == "unknown" || mode == "noop"
			if (err == nil) != want {
				t.Fatalf("accepted=%t want=%t", err == nil, want)
			}
		})
	}
}

func TestExistingTestClientRejectsCorruptReceipts(t *testing.T) {
	_, _, r := fixtureExistingTestEvidence(t)
	for _, operation := range []string{"claim", "heartbeat", "release"} {
		for _, bad := range []string{"version", "run", "expiry", "duplicate", "null", "wait_expired"} {
			t.Run(operation+"/"+bad, func(t *testing.T) {
				now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
				token := [32]byte{1}
				claim := existingTestClaim{scope: r.Scope, run: snapshotRun, step: snapshotStep, testRun: r.RunID, version: 2, generation: snapshotGeneration, worker: "test-reconciler", token: token, expires: now.Add(30 * time.Second)}
				db := &reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) {
					value := map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "generation": snapshotGeneration, "version": 2, "lease_expires_at": "2026-09-17T00:00:30Z"}
					if operation == "claim" {
						value["organization_id"] = r.Scope.OrganizationID().String()
						value["workspace_id"] = r.Scope.WorkspaceID().String()
						value["environment_id"] = r.Scope.EnvironmentID().String()
						value["test_run_id"] = r.RunID
					}
					if operation == "release" {
						delete(value, "lease_expires_at")
						value["version"] = 3
						value["state"] = "pending"
						value["next_check_at"] = "2026-09-17T00:00:30Z"
					}
					switch bad {
					case "version":
						value["version"] = 0
					case "run":
						value["run_id"] = "invalid"
					case "expiry":
						if operation == "release" {
							value["next_check_at"] = "2026-09-18T00:00:30Z"
						} else {
							value["lease_expires_at"] = "2026-09-18T00:00:30Z"
						}
					case "wait_expired":
						now = now.Add(time.Minute)
					}
					body, _ := json.Marshal(value)
					if bad == "duplicate" {
						body = []byte(strings.Replace(string(body), `"step_id":`, `"step_id":"`+snapshotStep+`","step_id":`, 1))
					}
					if operation == "claim" {
						body = append(append([]byte("["), body...), ']')
					}
					if bad == "null" {
						body = []byte("null")
					}
					return body, nil
				}}
				client, _ := newExistingTestClient(db, "test-reconciler", func() time.Time { return now })
				var err error
				switch operation {
				case "claim":
					_, err = client.Claim(context.Background(), r.Scope, 30, 1)
				case "heartbeat":
					_, err = client.Heartbeat(context.Background(), claim, 30)
				case "release":
					_, err = client.Release(context.Background(), claim, 30)
				}
				if err == nil {
					t.Fatal("corrupt receipt accepted")
				}
			})
		}
	}
}

func (d *reconcileQueryFixture) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	return d.call(ctx, q, args...)
}

// Wrong function routing, omitted release pins, or a changed ownership tuple
// must break this client contract before it is used by the worker loop.
func TestExistingTestClientRoutesExactLeaseAndPins(t *testing.T) {
	_, _, evidence := fixtureExistingTestEvidence(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	calls := 0
	var token []byte
	db := &reconcileQueryFixture{call: func(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
		calls++
		if len(args) < 2 || args[len(args)-2] != migrations.ProductionSecurityAgentExistingTests().Checksum() || args[len(args)-1] != migrations.SecurityAgentExistingTestsFingerprint() {
			t.Fatal("missing compiled authority")
		}
		if !reflect.DeepEqual(args[:3], []any{evidence.Scope.OrganizationID().String(), evidence.Scope.WorkspaceID().String(), evidence.Scope.EnvironmentID().String()}) {
			t.Fatal("changed scope")
		}
		switch calls {
		case 1:
			if q != "SELECT zasp_production_security_agent_existing_tests_reconcile_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)" || len(args) != 9 || args[3] != "test-reconciler" || args[5] != 30 || args[6] != 2 {
				t.Fatal("claim arguments")
			}
			token = append([]byte(nil), args[4].([]byte)...)
			if len(token) != 32 {
				t.Fatal("lease bytes")
			}
			return json.Marshal([]any{map[string]any{"organization_id": args[0], "workspace_id": args[1], "environment_id": args[2], "run_id": snapshotRun, "step_id": snapshotStep, "test_run_id": evidence.RunID, "generation": snapshotGeneration, "version": 2, "lease_expires_at": "2026-09-17T00:00:30Z"}})
		case 2, 3, 4:
			if !reflect.DeepEqual(args[3:9], []any{snapshotRun, snapshotStep, "test-reconciler", token, int64(2), snapshotGeneration}) {
				t.Fatalf("ownership changed: call%d", calls)
			}
			if calls == 2 {
				if q != "SELECT zasp_production_security_agent_existing_tests_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)" {
					t.Fatal("read route")
				}
				return fixtureExistingTestSnapshot(t, evidence), nil
			}
			if calls == 3 {
				if q != "SELECT zasp_production_security_agent_existing_tests_reconcile_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)" || args[9] != 60 {
					t.Fatal("heartbeat route")
				}
				return []byte(`{"run_id":"` + snapshotRun + `","step_id":"` + snapshotStep + `","generation":"` + snapshotGeneration + `","version":2,"lease_expires_at":"2026-09-17T00:01:00Z"}`), nil
			}
			if q != "SELECT zasp_production_security_agent_existing_tests_reconcile_release($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)" || args[9] != 60 {
				t.Fatal("release route")
			}
			return []byte(`{"run_id":"` + snapshotRun + `","step_id":"` + snapshotStep + `","generation":"` + snapshotGeneration + `","version":3,"state":"pending","next_check_at":"2026-09-17T00:01:00Z"}`), nil
		}
		t.Fatal("unexpected query")
		return nil, errors.New("unexpected")
	}}
	client, err := newExistingTestClient(db, "test-reconciler", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	claims, err := client.Claim(context.Background(), evidence.Scope, 30, 2)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim %v", err)
	}
	snapshot, err := client.Evidence(context.Background(), claims[0])
	if err != nil || snapshot.After == nil || snapshot.After.RunID != evidence.RunID {
		t.Fatalf("read %v", err)
	}
	claim, err := client.Heartbeat(context.Background(), claims[0], 60)
	if err != nil || !claim.expires.Equal(now.Add(time.Minute)) {
		t.Fatalf("renew %v", err)
	}
	next, err := client.Release(context.Background(), claim, 60)
	if err != nil || !next.Equal(now.Add(time.Minute)) || calls != 4 {
		t.Fatalf("release %v calls%d", err, calls)
	}
}

func TestExistingTestClientRejectsInvalidAndUnavailableWithoutFallback(t *testing.T) {
	_, _, evidence := fixtureExistingTestEvidence(t)
	calls := 0
	db := &reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) {
		calls++
		return nil, errors.New("private provider detail")
	}}
	client, _ := newExistingTestClient(db, "test-reconciler", time.Now)
	if _, err := client.Claim(context.Background(), evidence.Scope, 9, 1); err == nil || calls != 0 {
		t.Fatal("invalid claim reached database")
	}
	if _, err := client.Claim(context.Background(), evidence.Scope, 30, 1); err != errRuntimeUnavailable || calls != 1 {
		t.Fatal("database error escaped or fallback queried")
	}
}

func TestExistingTestClientRejectsEntireMixedClaimBatch(t *testing.T) {
	_, _, r := fixtureExistingTestEvidence(t)
	for _, bad := range []string{"duplicate_link", "foreign_tenant", "oversized"} {
		t.Run(bad, func(t *testing.T) {
			now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
			db := &reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) {
				row := map[string]any{"organization_id": r.Scope.OrganizationID().String(), "workspace_id": r.Scope.WorkspaceID().String(), "environment_id": r.Scope.EnvironmentID().String(), "run_id": snapshotRun, "step_id": snapshotStep, "test_run_id": r.RunID, "generation": snapshotGeneration, "version": 2, "lease_expires_at": "2026-09-17T00:00:30Z"}
				first, _ := json.Marshal(row)
				if bad == "foreign_tenant" {
					row["organization_id"] = snapshotRun
					row["step_id"] = snapshotRun
				}
				second, _ := json.Marshal(row)
				return []byte("[" + string(first) + "," + string(second) + "]"), nil
			}}
			client, _ := newExistingTestClient(db, "test-reconciler", func() time.Time { return now })
			limit := 2
			if bad == "oversized" {
				limit = 1
			}
			claims, err := client.Claim(context.Background(), r.Scope, 30, limit)
			if err == nil || len(claims) != 0 {
				t.Fatal("partial or malformed claim batch accepted")
			}
		})
	}
}
