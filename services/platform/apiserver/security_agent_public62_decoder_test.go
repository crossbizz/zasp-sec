package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func orderedPublicRunFixture(id RequestIdentity, run string, admitted bool) map[string]any {
	v := map[string]any{"contract_version": 62, "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "run_id": run, "definition_id": public62Definition, "definition_version": 2, "state": "queued", "version": 1, "admitted": false, "steps": []any{}, "verification": "pending"}
	if !admitted {
		return v
	}
	step0, _ := CanonicalDiscoveryID(id.Scope, "security_agent_step", run+"\x1f0")
	step1, _ := CanonicalDiscoveryID(id.Scope, "security_agent_step", run+"\x1f1")
	approval, _ := CanonicalDiscoveryID(id.Scope, "security_agent_ordered_approval", run+"\x1f"+step0)
	steps := []any{}
	for i, s := range []string{step0, step1} {
		state, action, settlement, cleanup := "waiting_approval", "create_temporary_policy", "not_applicable", "not_started"
		var pred, kind, aid any
		approvalState, av := "pending", 1
		if i == 0 {
			aid = approval
		} else {
			state, action, settlement, cleanup = "blocked", "run_test", "pending", "not_applicable"
			pred, kind = step0, "temporary_policy_applied.v1"
			approvalState, av = "absent", 0
		}
		steps = append(steps, map[string]any{"step_id": s, "index": i, "action": action, "state": state, "version": 1, "authorization": "approval_required", "dependency": map[string]any{"predecessor_step_id": pred, "required_receipt_kind": kind, "satisfied": i == 0, "blocked": i == 1, "ready": i == 0}, "approval": map[string]any{"state": approvalState, "version": av, "approval_id": aid}, "receipt": nil, "settlement": settlement, "cleanup": map[string]any{"state": cleanup, "version": 0, "attempt": 0, "partial": false, "cleaned": false}})
	}
	v["admitted"], v["state"], v["version"], v["steps"] = true, "waiting_approval", 3, steps
	return v
}

func TestSecurityAgentPublic62DecoderContradictions(t *testing.T) {
	id := orderedPublicIdentity()
	run := public62Finding
	cases := map[string]func(map[string]any){
		"contract":                           func(v map[string]any) { v["contract_version"] = 61 },
		"foreign-org":                        func(v map[string]any) { v["organization_id"] = public62Definition },
		"foreign-workspace":                  func(v map[string]any) { v["workspace_id"] = public62Definition },
		"foreign-env":                        func(v map[string]any) { v["environment_id"] = public62Definition },
		"wrong-run":                          func(v map[string]any) { v["run_id"] = public62Definition },
		"bad-definition":                     func(v map[string]any) { v["definition_id"] = "secret credential" },
		"definition-version":                 func(v map[string]any) { v["definition_version"] = 0 },
		"version":                            func(v map[string]any) { v["version"] = 1000001 },
		"state":                              func(v map[string]any) { v["state"] = "success" },
		"optimistic-verification":            func(v map[string]any) { v["verification"] = "remediated" },
		"approval-outside-waiting-aggregate": func(v map[string]any) { v["state"] = "running" },
		"terminal-pending-approval": func(v map[string]any) {
			v["state"], v["verification"] = "cancelled", "cancelled"
			nested(v, 0, "dependency")["ready"] = false
		},
		"unadmitted-steps":          func(v map[string]any) { v["admitted"] = false },
		"missing-step":              func(v map[string]any) { v["steps"] = v["steps"].([]any)[:1] },
		"extra-step":                func(v map[string]any) { s := v["steps"].([]any); v["steps"] = append(s, s[0]) },
		"duplicate-step":            func(v map[string]any) { s := v["steps"].([]any); s[1] = s[0] },
		"reordered-step":            func(v map[string]any) { s := v["steps"].([]any); s[0], s[1] = s[1], s[0] },
		"gap":                       func(v map[string]any) { step(v, 1)["index"] = 2 },
		"wrong-step-id":             func(v map[string]any) { step(v, 0)["step_id"] = public62Definition },
		"wrong-action":              func(v map[string]any) { step(v, 0)["action"] = "run_test" },
		"step-version":              func(v map[string]any) { step(v, 0)["version"] = 0 },
		"step-version-ahead-of-run": func(v map[string]any) { step(v, 0)["version"] = 4 },
		"approval-version-ahead-of-step": func(v map[string]any) {
			v["state"] = "running"
			step(v, 0)["state"] = "authorized"
			nested(v, 0, "approval")["state"], nested(v, 0, "approval")["version"] = "approved", 2
		},
		"step-state":              func(v map[string]any) { step(v, 0)["state"] = "queued" },
		"authorization":           func(v map[string]any) { step(v, 0)["authorization"] = "allowed" },
		"predecessor":             func(v map[string]any) { nested(v, 1, "dependency")["predecessor_step_id"] = public62Definition },
		"receipt-kind-dependency": func(v map[string]any) { nested(v, 1, "dependency")["required_receipt_kind"] = "unknown" },
		"false-satisfied":         func(v map[string]any) { nested(v, 1, "dependency")["satisfied"] = true },
		"false-blocked":           func(v map[string]any) { nested(v, 1, "dependency")["blocked"] = false },
		"false-ready":             func(v map[string]any) { nested(v, 1, "dependency")["ready"] = true },
		"approval-version":        func(v map[string]any) { nested(v, 0, "approval")["version"] = 0 },
		"approval-id":             func(v map[string]any) { nested(v, 0, "approval")["approval_id"] = public62Definition },
		"approval-state":          func(v map[string]any) { nested(v, 0, "approval")["state"] = "approved" },
		"invented-approval":       func(v map[string]any) { nested(v, 1, "approval")["version"] = 1 },
		"invented-receipt": func(v map[string]any) {
			step(v, 0)["receipt"] = map[string]any{"kind": "temporary_policy_applied.v1", "version": 1, "digest": "sha256:" + strings.Repeat("a", 64), "reference": public62Definition}
		},
		"settlement":         func(v map[string]any) { step(v, 1)["settlement"] = "not_reproduced" },
		"cleanup-state":      func(v map[string]any) { nested(v, 0, "cleanup")["state"] = "cleaned" },
		"cleanup-version":    func(v map[string]any) { nested(v, 0, "cleanup")["version"] = 1 },
		"cleanup-attempt":    func(v map[string]any) { nested(v, 0, "cleanup")["attempt"] = 1 },
		"cleanup-partial":    func(v map[string]any) { nested(v, 0, "cleanup")["partial"] = true },
		"cleanup-cleaned":    func(v map[string]any) { nested(v, 0, "cleanup")["cleaned"] = true },
		"test-cleanup":       func(v map[string]any) { nested(v, 1, "cleanup")["state"] = "pending" },
		"null-state":         func(v map[string]any) { v["state"] = nil },
		"missing-admitted":   func(v map[string]any) { delete(v, "admitted") },
		"private-run":        func(v map[string]any) { v["lease_token"] = "secret" },
		"private-step":       func(v map[string]any) { step(v, 0)["worker_id"] = "secret" },
		"private-dependency": func(v map[string]any) { nested(v, 0, "dependency")["provider_payload"] = map[string]any{} },
		"private-approval":   func(v map[string]any) { nested(v, 0, "approval")["credential_reference"] = "secret" },
		"private-cleanup":    func(v map[string]any) { nested(v, 0, "cleanup")["gateway_envelope"] = "secret" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := orderedPublicRunFixture(id, run, true)
			mutate(v)
			raw, _ := json.Marshal(v)
			db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return raw, nil }}
			repo, _ := NewSecurityAgentPublicRepository(db)
			got, err := repo.Run(context.Background(), id, run)
			if err != ErrRepositoryUnavailable || got.RunID != "" {
				t.Fatalf("contradiction accepted: %+v %v", got, err)
			}
		})
	}
}
func step(v map[string]any, i int) map[string]any             { return v["steps"].([]any)[i].(map[string]any) }
func nested(v map[string]any, i int, k string) map[string]any { return step(v, i)[k].(map[string]any) }

func TestSecurityAgentPublic62DecoderExactJSON(t *testing.T) {
	id := orderedPublicIdentity()
	for _, raw := range []string{`null`, `{}`, `{"contract_version":62,"ready":false}`, `{"contract_version":62,"ready":null}`, `{"contract_version":62,"ready":true,"ready":true}`, `{"contract_version":62,"ready":true} {}`, `{"contract_version":62,"ready":true,"lease_token":"secret"}`, `{"contract_version":62,"ready":true,"Ready":true}`, strings.Repeat(" ", 65537) + `{}`, "\xff"} {
		db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return []byte(raw), nil }}
		repo, _ := NewSecurityAgentPublicRepository(db)
		if err := repo.Ready(context.Background(), id); err != ErrRepositoryUnavailable {
			t.Fatalf("accepted %q: %v", raw[:min(100, len(raw))], err)
		}
	}
	for _, admitted := range []bool{false, true} {
		raw, _ := json.Marshal(orderedPublicRunFixture(id, public62Finding, admitted))
		db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return raw, nil }}
		repo, _ := NewSecurityAgentPublicRepository(db)
		if _, err := repo.Run(context.Background(), id, public62Finding); err != nil {
			t.Fatalf("valid DTO: %v", err)
		}
		for _, bad := range []string{strings.Replace(string(raw), `"contract_version":62`, `"contract_version":62,"contract_version":62`, 1), strings.Replace(string(raw), `"version":1`, `"version":null`, 1)} {
			db.query = func(context.Context, string, ...any) (json.RawMessage, error) { return []byte(bad), nil }
			if _, err := repo.Run(context.Background(), id, public62Finding); err != ErrRepositoryUnavailable {
				t.Fatal("ambiguous JSON accepted")
			}
		}
	}
}

func TestSecurityAgentPublic62DecoderPage(t *testing.T) {
	id := orderedPublicIdentity()
	run := public62Finding
	for name, mutate := range map[string]func(map[string]any){
		"null-items":             func(v map[string]any) { v["items"] = nil },
		"missing-cursor":         func(v map[string]any) { delete(v, "next_after_run_id") },
		"empty-cursor":           func(v map[string]any) { v["next_after_run_id"] = "" },
		"wrong-cursor":           func(v map[string]any) { v["next_after_run_id"] = public62Definition },
		"cursor-with-short-page": func(v map[string]any) { v["items"] = []any{}; v["next_after_run_id"] = run },
		"oversized": func(v map[string]any) {
			v["items"] = []any{orderedPublicRunFixture(id, run, false), orderedPublicRunFixture(id, run, false)}
		},
		"foreign-item": func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["environment_id"] = public62Definition },
	} {
		t.Run(name, func(t *testing.T) {
			v := map[string]any{"contract_version": 62, "items": []any{orderedPublicRunFixture(id, run, false)}, "next_after_run_id": nil}
			mutate(v)
			raw, _ := json.Marshal(v)
			db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return raw, nil }}
			repo, _ := NewSecurityAgentPublicRepository(db)
			if _, err := repo.Runs(context.Background(), id, "", 1); err != ErrRepositoryUnavailable {
				t.Fatal("invalid page", err)
			}
		})
	}
	raw, _ := json.Marshal(map[string]any{"contract_version": 62, "items": []any{orderedPublicRunFixture(id, run, false)}, "next_after_run_id": nil})
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return raw, nil }}
	repo, _ := NewSecurityAgentPublicRepository(db)
	if _, err := repo.Runs(context.Background(), id, run, 1); err != ErrRepositoryUnavailable {
		t.Fatal("cursor not ascending", err)
	}
}

func orderedPublicTerminalFixture(id RequestIdentity, run string) map[string]any {
	v := orderedPublicRunFixture(id, run, true)
	v["state"], v["verification"], v["version"] = "contained", "contained", 10
	for i, kind := range []string{"temporary_policy_applied.v1", "existing_test_settled.v1"} {
		s := step(v, i)
		s["state"], s["version"] = "succeeded", 4
		nested(v, i, "dependency")["satisfied"], nested(v, i, "dependency")["blocked"], nested(v, i, "dependency")["ready"] = true, false, false
		approval, _ := CanonicalDiscoveryID(id.Scope, "security_agent_ordered_approval", run+"\x1f"+s["step_id"].(string))
		s["approval"] = map[string]any{"state": "approved", "version": 2, "approval_id": approval}
		reference, _ := CanonicalDiscoveryID(id.Scope, "public62_evidence", run+"\x1f"+s["step_id"].(string)+"\x1f"+kind)
		s["receipt"] = map[string]any{"kind": kind, "version": 1, "digest": "sha256:" + strings.Repeat("a", 64), "reference": reference}
	}
	step(v, 1)["settlement"] = "not_reproduced"
	nested(v, 0, "cleanup")["state"] = "pending"
	return v
}

func TestSecurityAgentPublic62ReceiptAndAggregateContradictions(t *testing.T) {
	id := orderedPublicIdentity()
	run := public62Finding
	for name, mutate := range map[string]func(map[string]any){
		"receipt-kind":    func(v map[string]any) { step(v, 0)["receipt"].(map[string]any)["kind"] = "existing_test_settled.v1" },
		"receipt-version": func(v map[string]any) { step(v, 0)["receipt"].(map[string]any)["version"] = 2 },
		"receipt-digest": func(v map[string]any) {
			step(v, 0)["receipt"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("A", 64)
		},
		"receipt-reference":      func(v map[string]any) { step(v, 0)["receipt"].(map[string]any)["reference"] = public62Definition },
		"raw-receipt":            func(v map[string]any) { step(v, 0)["receipt"].(map[string]any)["body"] = map[string]any{} },
		"receipt-secret":         func(v map[string]any) { step(v, 0)["receipt"].(map[string]any)["artifact_locator"] = "s3://secret" },
		"missing-receipt":        func(v map[string]any) { step(v, 0)["receipt"] = nil },
		"false-remediation":      func(v map[string]any) { v["state"], v["verification"] = "remediated", "remediated" },
		"reproduced-containment": func(v map[string]any) { step(v, 1)["settlement"] = "reproduced" },
		"unknown-containment":    func(v map[string]any) { step(v, 1)["settlement"] = "unknown" },
		"terminal-ready":         func(v map[string]any) { nested(v, 0, "dependency")["ready"] = true },
		"settled-nonterminal":    func(v map[string]any) { v["state"], v["verification"] = "running", "pending" },
		"retryable-contained": func(v map[string]any) {
			step(v, 0)["cleanup"] = map[string]any{"state": "retryable", "version": 2, "attempt": 1, "partial": false, "cleaned": false}
		},
		"cleaned-before-store": func(v map[string]any) {
			v["state"], v["verification"] = "remediated", "remediated"
			step(v, 0)["cleanup"] = map[string]any{"state": "cleaned", "version": 1, "attempt": 1, "partial": false, "cleaned": true}
		},
		"cleaned-version": func(v map[string]any) {
			v["state"], v["verification"] = "remediated", "remediated"
			step(v, 0)["cleanup"] = map[string]any{"state": "cleaned", "version": 0, "attempt": 1, "partial": false, "cleaned": true}
		},
		"cleaned-attempt": func(v map[string]any) {
			v["state"], v["verification"] = "remediated", "remediated"
			step(v, 0)["cleanup"] = map[string]any{"state": "cleaned", "version": 3, "attempt": 101, "partial": false, "cleaned": true}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := orderedPublicTerminalFixture(id, run)
			mutate(v)
			raw, _ := json.Marshal(v)
			db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return raw, nil }}
			repo, _ := NewSecurityAgentPublicRepository(db)
			if _, err := repo.Run(context.Background(), id, run); err != ErrRepositoryUnavailable {
				t.Fatal("accepted contradiction", err)
			}
		})
	}
	v := orderedPublicTerminalFixture(id, run)
	raw, _ := json.Marshal(v)
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return raw, nil }}
	repo, _ := NewSecurityAgentPublicRepository(db)
	if _, err := repo.Run(context.Background(), id, run); err != nil {
		t.Fatal("valid contained", err)
	}
}

func TestSecurityAgentPublic62MutationResponseExactness(t *testing.T) {
	id := orderedPublicIdentity()
	q := SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "public62-go-test-0001"}
	run, _ := CanonicalDiscoveryID(id.Scope, "security_agent_run", public62Definition+"\x1f"+public62Finding+"\x1f1")
	for _, op := range []string{"activate", "trigger"} {
		var baseline map[string]any
		if op == "activate" {
			baseline = map[string]any{"contract_version": 62, "definition_id": public62Definition, "definition_version": 2, "activation": "supervised"}
		} else {
			baseline = map[string]any{"contract_version": 62, "run_id": run, "definition_id": public62Definition, "definition_version": 2, "state": "queued", "version": 1}
		}
		for field := range baseline {
			for _, invalid := range []any{nil, "secret", 0} {
				v := map[string]any{}
				for k, value := range baseline {
					v[k] = value
				}
				v[field] = invalid
				raw, _ := json.Marshal(v)
				db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return raw, nil }}
				repo, _ := NewSecurityAgentPublicRepository(db)
				var err error
				if op == "activate" {
					_, err = repo.Activate(context.Background(), id, public62Definition, 1)
				} else {
					_, err = repo.Trigger(context.Background(), id, q)
				}
				if err != ErrRepositoryUnavailable {
					t.Fatalf("%s.%s accepted %v", op, field, invalid)
				}
			}
		}
	}
}

func TestSecurityAgentPublic62CleanupStateMachine(t *testing.T) {
	id := orderedPublicIdentity()
	run := public62Finding
	check := func(t *testing.T, aggregate, state string, version, attempt int, partial, want bool) {
		t.Helper()
		v := orderedPublicTerminalFixture(id, run)
		v["state"], v["verification"] = aggregate, aggregate
		step(v, 0)["cleanup"] = map[string]any{"state": state, "version": version, "attempt": attempt, "partial": partial, "cleaned": state == "cleaned"}
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return raw, nil }}
		repo, err := NewSecurityAgentPublicRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		got, err := repo.Run(context.Background(), id, run)
		if want {
			if err != nil || got.Steps[0].Cleanup.Version != int64(version) || got.Steps[0].Cleanup.Attempt != int64(attempt) {
				t.Fatalf("valid cleanup rejected: %+v %v", got, err)
			}
		} else if err != ErrRepositoryUnavailable || got.RunID != "" {
			t.Fatalf("impossible cleanup accepted: %+v %v", got, err)
		}
	}
	// Literal SQL-derived floors: initial claim v1, every retry reconciles and
	// claims (+2), and completion needs a stored removal (+1) then complete (+1).
	for _, row := range []struct{ attempt, leased, retryable, cleaned int }{{1, 1, 2, 3}, {2, 3, 4, 5}, {3, 5, 6, 7}, {100, 199, 200, 201}} {
		for _, state := range []struct {
			name  string
			floor int
		}{{"leased", row.leased}, {"retryable", row.retryable}, {"cleaned", row.cleaned}} {
			for _, delta := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("%s/attempt%d/version%d", state.name, row.attempt, state.floor+delta), func(t *testing.T) {
					check(t, "needs_human", state.name, state.floor+delta, row.attempt, false, delta >= 0)
				})
			}
		}
	}
	for _, aggregate := range []string{"failed", "inconclusive", "contained", "remediated", "needs_human", "cancelled"} {
		t.Run("cleaned/aggregate-"+aggregate, func(t *testing.T) {
			check(t, aggregate, "cleaned", 3, 1, false, aggregate == "remediated" || aggregate == "needs_human" || aggregate == "cancelled")
		})
	}
	for _, aggregate := range []string{"contained", "remediated"} {
		for _, state := range []string{"leased", "retryable", "cleaned"} {
			t.Run("retry/"+aggregate+"/"+state, func(t *testing.T) { check(t, aggregate, state, 7, 3, false, false) })
		}
	}
	for _, state := range []string{"leased", "retryable", "cleaned"} {
		for _, aggregate := range []string{"needs_human", "cancelled", "remediated"} {
			t.Run("partial/"+aggregate+"/"+state, func(t *testing.T) { check(t, aggregate, state, 7, 3, true, aggregate != "remediated") })
		}
	}
	for _, attempt := range []int{0, 101} {
		t.Run(fmt.Sprintf("attempt-bound-%d", attempt), func(t *testing.T) { check(t, "needs_human", "cleaned", 999999, attempt, false, false) })
	}
	t.Run("version-ceiling", func(t *testing.T) { check(t, "needs_human", "cleaned", 999999, 100, false, true) })
	t.Run("version-overflow", func(t *testing.T) { check(t, "needs_human", "cleaned", 1000000, 100, false, false) })
}
