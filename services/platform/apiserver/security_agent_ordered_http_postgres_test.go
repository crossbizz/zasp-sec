package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func orderedHTTPPostgresHandler(t *testing.T, c *pgx.Conn, o, w, e, actor string) (http.Handler, RequestIdentity) {
	t.Helper()
	a, id := orderedResourceGo(t, c, o, w, e, actor)
	id.FreshAuthenticated = true
	id.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	return orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("ordered request delegated to legacy") })), id
}

func orderedHTTPCall(t *testing.T, h http.Handler, id RequestIdentity, op, resource, body, key string, version int64, want int) *httptest.ResponseRecorder {
	t.Helper()
	method := "POST"
	if op == "getSecurityAgentActivation" || op == "getSecurityAgentRun" || op == "getSecurityAgentApproval" {
		method = "GET"
	}
	r := orderedHTTPRequest(id, op, method, resource, body)
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("If-Match", `"`+strconv.FormatInt(version, 10)+`"`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%s: %d %v %s", op, w.Code, w.Header(), w.Body.String())
	}
	return w
}

func orderedHTTPProof(t *testing.T, ctx context.Context, owner *pgx.Conn, o, actor, op, key string, w *httptest.ResponseRecorder) {
	t.Helper()
	var audit, receipt string
	if err := owner.QueryRow(ctx, `SELECT audit_id,receipt_id FROM zasp_security_agent_request_receipts WHERE organization_id=$1 AND principal_id=$2 AND operation=$3 AND idempotency_key=$4`, o, actor, op, key).Scan(&audit, &receipt); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("X-Audit-ID") != audit || w.Header().Get("X-Mutation-Receipt-ID") != receipt {
		t.Fatal("headers are not persisted proof", w.Header(), audit, receipt)
	}
}

func TestSecurityAgentOrderedHTTPLifecyclePostgres(t *testing.T) {
	for _, planning := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued", true: "planning"}[planning], func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
					t.Fatal(err)
				}
				public62Seed(t, ctx, owner, o, w, e, testID, actor)
				h, id := orderedHTTPPostgresHandler(t, api, o, w, e, actor)
				draft := orderedHTTPCall(t, h, id, "getSecurityAgentActivation", public62Definition, "", "", 0, 200)
				if draft.Body.String() != `{"id":"`+public62Definition+`","activation":"draft","enabled":false,"version":1}`+"\n" || draft.Header().Get("ETag") != `"1"` {
					t.Fatal(draft.Body.String())
				}
				activation := orderedHTTPCall(t, h, id, "activateSecurityAgent", public62Definition, `{"activation":"supervised"}`, "ordered-http-activation", 1, 200)
				orderedHTTPProof(t, ctx, owner, o, actor, "activateSecurityAgent", "ordered-http-activation", activation)
				before := public62Snapshot(t, ctx, owner)
				replay := orderedHTTPCall(t, h, id, "activateSecurityAgent", public62Definition, `{"activation":"supervised"}`, "ordered-http-activation", 1, 200)
				if replay.Body.String() != activation.Body.String() || replay.Header().Get("ETag") != `"2"` || public62Snapshot(t, ctx, owner) != before {
					t.Fatal("activation replay changed")
				}
				orderedHTTPCall(t, h, id, "activateSecurityAgent", public62Definition, `{"activation":"supervised"}`, "ordered-http-activation", 2, 409)
				body := `{"environment_id":"` + e + `","trigger_kind":"finding","trigger_id":"` + public62Finding + `","trigger_version":1,"trigger_source":"credential"}`
				triggered := orderedHTTPCall(t, h, id, "runSecurityAgent", public62Definition, body, "ordered-http-trigger", 2, 202)
				orderedHTTPProof(t, ctx, owner, o, actor, "runSecurityAgent", "ordered-http-trigger", triggered)
				var run SecurityAgentRun
				if json.Unmarshal(triggered.Body.Bytes(), &run) != nil || run.State != "queued" || run.Version != 1 || len(run.EvidenceIDs) != 1 || run.EvidenceIDs[0] != public62Finding {
					t.Fatal(triggered.Body.String())
				}
				conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close(ctx)
				restarted, restartedID := orderedHTTPPostgresHandler(t, conn, o, w, e, actor)
				before = public62Snapshot(t, ctx, owner)
				replay = orderedHTTPCall(t, restarted, restartedID, "runSecurityAgent", public62Definition, body, "ordered-http-trigger", 2, 202)
				if replay.Body.String() != triggered.Body.String() || public62Snapshot(t, ctx, owner) != before {
					t.Fatal("trigger replay changed")
				}
				orderedHTTPCall(t, h, id, "runSecurityAgent", public62Definition, body, "ordered-http-trigger", 3, 409)
				orderedHTTPCall(t, h, id, "getSecurityAgentRun", run.ID, "", "", 0, 200)
				expected := int64(1)
				state := "cancelled"
				if planning {
					if _, err := orderedPlanningCall(ctx, worker, map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run.ID, "worker_id": "ordered-http-planner", "lease_token": "ordered-http-lease-001", "operation": "claim", "payload": map[string]any{}}); err != nil {
						t.Fatal(err)
					}
					expected = 2
					state = "needs_human"
				}
				cancelled := orderedHTTPCall(t, h, id, "cancelSecurityAgentRun", run.ID, "", "ordered-http-cancel", expected, 200)
				orderedHTTPProof(t, ctx, owner, o, actor, "cancelSecurityAgentRun", "ordered-http-cancel", cancelled)
				type runWire SecurityAgentRun
				var got struct {
					runWire
					Ordered struct {
						CleanupRequired bool `json:"cleanup_required"`
					} `json:"ordered"`
				}
				if json.Unmarshal(cancelled.Body.Bytes(), &got) != nil || got.State != state || got.Version != expected+1 || got.Ordered.CleanupRequired {
					t.Fatal(cancelled.Body.String())
				}
				before = public62Snapshot(t, ctx, owner)
				replay = orderedHTTPCall(t, restarted, restartedID, "cancelSecurityAgentRun", run.ID, "", "ordered-http-cancel", expected, 200)
				if replay.Body.String() != cancelled.Body.String() || public62Snapshot(t, ctx, owner) != before {
					t.Fatal("cancel replay changed")
				}
				orderedHTTPCall(t, h, id, "cancelSecurityAgentRun", run.ID, "", "ordered-http-terminal", expected+1, 409)
			})
		})
	}
}

func TestSecurityAgentOrderedHTTPApprovalPostgres(t *testing.T) {
	for _, decision := range []string{"approved", "rejected", "cancelled"} {
		t.Run(decision, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
				run, _ := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
				h, id := orderedHTTPPostgresHandler(t, api, o, w, e, orderedProgressionApprover)
				detail := orderedHTTPCall(t, h, id, "getSecurityAgentRun", run, "", "", 0, 200)
				var v SecurityAgentRunDetail
				if json.Unmarshal(detail.Body.Bytes(), &v) != nil || len(v.Approvals) != 1 || len(v.Plan.Steps) != 2 {
					t.Fatal(detail.Body.String())
				}
				approval := v.Approvals[0]
				pending := orderedHTTPCall(t, h, id, "getSecurityAgentApproval", approval.ID, "", "", 0, 200)
				if pending.Header().Get("ETag") != `"1"` {
					t.Fatal(pending.Header())
				}
				before := public62Snapshot(t, ctx, owner)
				if decision == "cancelled" {
					orderedHTTPCall(t, h, id, "decideSecurityAgentApproval", approval.ID, `{"decision":"cancelled"}`, "ordered-http-decision", 1, 400)
					if public62Snapshot(t, ctx, owner) != before {
						t.Fatal("approval cancelled mutated")
					}
					orderedHTTPCall(t, h, id, "cancelSecurityAgentRun", run, "", "ordered-http-waiting-cancel", 3, 200)
					return
				}
				decided := orderedHTTPCall(t, h, id, "decideSecurityAgentApproval", approval.ID, `{"decision":"`+decision+`"}`, "ordered-http-decision", 1, 200)
				orderedHTTPProof(t, ctx, owner, o, orderedProgressionApprover, "decideSecurityAgentApproval", "ordered-http-decision", decided)
				var got SecurityAgentApproval
				if json.Unmarshal(decided.Body.Bytes(), &got) != nil || got.State != decision || got.Version != 2 {
					t.Fatal(decided.Body.String())
				}
				conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close(ctx)
				again, _ := orderedHTTPPostgresHandler(t, conn, o, w, e, orderedProgressionApprover)
				before = public62Snapshot(t, ctx, owner)
				replay := orderedHTTPCall(t, again, id, "decideSecurityAgentApproval", approval.ID, `{"decision":"`+decision+`"}`, "ordered-http-decision", 1, 200)
				if replay.Body.String() != decided.Body.String() || public62Snapshot(t, ctx, owner) != before {
					t.Fatal("decision replay changed")
				}
				read := orderedHTTPCall(t, h, id, "getSecurityAgentApproval", approval.ID, "", "", 0, 200)
				if read.Body.String() != decided.Body.String() {
					t.Fatal(read.Body.String(), decided.Body.String())
				}
			})
		})
	}
}

func TestSecurityAgentOrderedHTTPAppliedCancellationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		public62TypedDecision(t, ctx, api, o, w, e, run, 3)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, run, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedApplication(t, ctx, owner, key, stored)
		if _, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "complete", 5, 2), keys); err != nil {
			t.Fatal(err)
		}
		if _, err := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, run, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
			t.Fatal(err)
		}
		h, id := orderedHTTPPostgresHandler(t, api, o, w, e, orderedProgressionApprover)
		detail := orderedHTTPCall(t, h, id, "getSecurityAgentRun", run, "", "", 0, 200)
		var got struct {
			Ordered struct {
				Steps []SecurityAgentPublicStep `json:"steps"`
			} `json:"ordered"`
		}
		if json.Unmarshal(detail.Body.Bytes(), &got) != nil || got.Ordered.Steps[0].Receipt == nil || !got.Ordered.Steps[1].Dependency.Ready {
			t.Fatal(detail.Body.String())
		}
		cancelled := orderedHTTPCall(t, h, id, "cancelSecurityAgentRun", run, "", "ordered-http-applied-cancel", 7, 200)
		var result struct {
			State   string `json:"state"`
			Ordered struct {
				CleanupRequired bool `json:"cleanup_required"`
			} `json:"ordered"`
		}
		if json.Unmarshal(cancelled.Body.Bytes(), &result) != nil || result.State != "cancelled" || !result.Ordered.CleanupRequired {
			t.Fatal(cancelled.Body.String())
		}
		orderedHTTPProof(t, ctx, owner, o, orderedProgressionApprover, "cancelSecurityAgentRun", "ordered-http-applied-cancel", cancelled)
	})
}

func TestSecurityAgentOrderedHTTPTerminalPostgres(t *testing.T) {
	public62TerminalFixture(t, func(ctx context.Context, owner, _, api, _ *pgx.Conn, o, w, e, run string, _ []string) {
		h, id := orderedHTTPPostgresHandler(t, api, o, w, e, orderedProgressionApprover)
		read := orderedHTTPCall(t, h, id, "getSecurityAgentRun", run, "", "", 0, 200)
		var got struct {
			SecurityAgentRunDetail
			Ordered struct {
				Steps []SecurityAgentPublicStep `json:"steps"`
			} `json:"ordered"`
		}
		if json.Unmarshal(read.Body.Bytes(), &got) != nil || got.Run.State != "contained" || got.Verification != "verified" || got.Ordered.Steps[1].Settlement != "not_reproduced" {
			t.Fatal(read.Body.String())
		}
		before := public62Snapshot(t, ctx, owner)
		orderedHTTPCall(t, h, id, "cancelSecurityAgentRun", run, "", "ordered-http-terminal-cancel", got.Run.Version, 409)
		if public62Snapshot(t, ctx, owner) != before {
			t.Fatal("terminal cancel changed owner")
		}
	}, false)
}
