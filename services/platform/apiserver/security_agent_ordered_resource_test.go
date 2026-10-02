package apiserver

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

func orderedResourceCalls(a *SecurityAgentOrderedResourceAuthority, id RequestIdentity) []func() error {
	ctx := context.Background()
	return []func() error{
		func() error { _, e := a.GetActivation(ctx, id, public62Definition); return e },
		func() error {
			_, e := a.Activate(ctx, id, SecurityAgentOrderedActivation{public62Definition, 1, "supervised", "ordered-resource-test-1"})
			return e
		},
		func() error {
			_, e := a.Trigger(ctx, id, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{public62Definition, 2, public62Finding, 1, "ordered-resource-test-1"}, "finding", "credential"})
			return e
		},
		func() error { _, e := a.Run(ctx, id, public62Finding); return e },
		func() error {
			_, e := a.Cancel(ctx, id, SecurityAgentPublicCancellation{public62Finding, 1, "ordered-resource-test-1"})
			return e
		},
		func() error { _, e := a.Approval(ctx, id, public62Finding); return e },
		func() error {
			_, e := a.Decide(ctx, id, SecurityAgentOrderedDecision{public62Finding, 1, "approved", "ordered-resource-test-1"})
			return e
		},
	}
}

func TestSecurityAgentOrderedResourceClosedProjection(t *testing.T) {
	id := orderedPublicIdentity()
	changes := map[string]func(map[string]any){
		"private":             func(v map[string]any) { v["requester_id"] = public62Finding },
		"timestamp-offset":    func(v map[string]any) { v["created_at"] = "2026-09-20T00:00:00+00:00" },
		"timestamp-invalid":   func(v map[string]any) { v["created_at"] = "not a timestamp" },
		"timestamp-comma":     func(v map[string]any) { v["created_at"] = "2026-09-20T00:00:00,000Z" },
		"timestamp-precision": func(v map[string]any) { v["created_at"] = "2026-09-20T00:00:00.0000000001Z" },
		"future":              func(v map[string]any) { v["created_at"] = "2099-09-20T00:00:00Z" },
		"digest":              func(v map[string]any) { v["plan"].(map[string]any)["plan_hash"] = "sha256:bad" },
		"expiry":              func(v map[string]any) { v["plan"].(map[string]any)["expires_at"] = "2020-09-20T00:00:00Z" },
		"evidence":            func(v map[string]any) { v["trigger_id"] = "invalid" },
		"approval-id":         func(v map[string]any) { v["approvals"].([]any)[0].(map[string]any)["id"] = public62Finding },
		"approval-version":    func(v map[string]any) { v["approvals"].([]any)[0].(map[string]any)["version"] = 2 },
		"approval-ttl":        func(v map[string]any) { v["approvals"].([]any)[0].(map[string]any)["ttl_seconds"] = 0 },
		"approval-effect": func(v map[string]any) {
			v["approvals"].([]any)[0].(map[string]any)["expected_effect"] = "Run existing test"
		},
		"approval-expiry": func(v map[string]any) {
			v["approvals"].([]any)[0].(map[string]any)["expires_at"] = "2026-09-20T02:00:00Z"
		},
		"approval-created": func(v map[string]any) {
			v["approvals"].([]any)[0].(map[string]any)["created_at"] = "2020-09-20T00:00:00Z"
		},
		"missing-approval":   func(v map[string]any) { v["approvals"] = []any{} },
		"duplicate-approval": func(v map[string]any) { x := v["approvals"].([]any); v["approvals"] = append(x, x[0]) },
		"step-version":       func(v map[string]any) { step(v["ordered"].(map[string]any), 0)["version"] = 0 },
		"false-dependency":   func(v map[string]any) { nested(v["ordered"].(map[string]any), 1, "dependency")["satisfied"] = true },
		"oversized":          func(v map[string]any) { v["created_at"] = strings.Repeat("x", 17000) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			fixture := orderedResourceFixture(id, public62Definition, true)
			change(fixture)
			db := &orderedPublicDB{query: func(_ context.Context, _ string, args ...any) (json.RawMessage, error) {
				var q map[string]any
				_ = json.Unmarshal(args[2].(json.RawMessage), &q)
				if q["operation"] == "classify" {
					return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": "run", "resource_id": public62Definition, "family": "ordered_release61"})
				}
				return json.Marshal(fixture)
			}}
			a, _ := NewSecurityAgentOrderedResourceAuthority(db)
			v, err := a.Run(context.Background(), id, public62Definition)
			if err != ErrRepositoryUnavailable || !reflect.DeepEqual(v, SecurityAgentOrderedRunResource{}) || db.calls != 2 {
				t.Fatal(v, err, db.calls)
			}
		})
	}
}

func TestSecurityAgentOrderedResourceMutationBoundary(t *testing.T) {
	id := orderedPublicIdentity()
	q := SecurityAgentOrderedActivation{public62Definition, 1, "supervised", "ordered-resource-unit-01"}
	for _, mutation := range []string{"valid", "private", "wrong-audit", "wrong-receipt", "version", "cancel-context"} {
		t.Run(mutation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			db := &orderedPublicDB{query: func(bounded context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql != securityAgentPublicSQL || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentPublic().Checksum() || args[1] != migrations.SecurityAgentPublicFingerprint() {
					t.Fatal("unreviewed boundary", sql, args)
				}
				if deadline, ok := bounded.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("unbounded")
				}
				var request map[string]any
				_ = json.Unmarshal(args[2].(json.RawMessage), &request)
				if request["operation"] == "classify_mutation" {
					if request["mutation_kind"] != "activate" || request["definition_id"] != q.DefinitionID || request["idempotency_key"] != q.IdempotencyKey {
						t.Fatal(request)
					}
					return json.Marshal(map[string]any{"contract_version": 62, "mutation_kind": "activate", "definition_id": q.DefinitionID, "idempotency_key": q.IdempotencyKey, "trigger": nil, "family": "ordered_release61"})
				}
				want := map[string]any{"operation": "activate_resource", "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "definition_id": q.DefinitionID, "definition_version": float64(1), "activation": "supervised", "idempotency_key": q.IdempotencyKey}
				if !reflect.DeepEqual(request, want) {
					t.Fatal(request, want)
				}
				audit, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1factivate_resource\x1f"+q.IdempotencyKey)
				receipt, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1factivate_resource\x1f"+q.IdempotencyKey)
				response := map[string]any{"contract_version": 62, "id": q.DefinitionID, "activation": "supervised", "enabled": true, "version": 2, "audit_id": audit, "correlation_id": audit, "receipt_id": receipt, "replayed": false}
				switch mutation {
				case "private":
					response["provider_payload"] = "secret"
				case "wrong-audit":
					response["audit_id"] = public62Finding
				case "wrong-receipt":
					response["receipt_id"] = public62Finding
				case "version":
					response["version"] = 3
				case "cancel-context":
					cancel()
				}
				return json.Marshal(response)
			}}
			a, _ := NewSecurityAgentOrderedResourceAuthority(db)
			v, err := a.Activate(ctx, id, q)
			if mutation == "valid" {
				if err != nil || v.Version != 2 {
					t.Fatal(v, err)
				}
			} else if err != ErrRepositoryUnavailable || v != (SecurityAgentActivationResult{}) {
				t.Fatal(v, err)
			}
			if db.calls != 2 {
				t.Fatal(db.calls)
			}
		})
	}
}

func TestSecurityAgentOrderedResourceValidation(t *testing.T) {
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Fatal("invalid input reached SQL")
		return nil, nil
	}}
	a, _ := NewSecurityAgentOrderedResourceAuthority(db)
	ctx := context.Background()
	id := orderedPublicIdentity()
	for _, target := range []string{"draft", "validated", "autonomous", ""} {
		if _, err := a.Activate(ctx, id, SecurityAgentOrderedActivation{public62Definition, 1, target, "ordered-resource-unit-01"}); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, decision := range []string{"cancelled", "expired", ""} {
		if _, err := a.Decide(ctx, id, SecurityAgentOrderedDecision{public62Definition, 1, decision, "ordered-resource-unit-01"}); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, version := range []int64{0, -1, 1000000, 1000001} {
		if _, err := a.Cancel(ctx, id, SecurityAgentPublicCancellation{public62Definition, version, "ordered-resource-unit-01"}); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"", "short", strings.Repeat("x", 129)} {
		if _, err := a.Activate(ctx, id, SecurityAgentOrderedActivation{public62Definition, 1, "supervised", key}); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, c := range []context.Context{nil, canceled} {
		if _, err := a.Run(c, id, public62Definition); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	var missing *SecurityAgentOrderedResourceAuthority
	if _, err := missing.Run(ctx, id, public62Definition); err != ErrRepositoryOperation {
		t.Fatal(err)
	}
	if _, err := NewSecurityAgentOrderedResourceAuthority(nil); err != ErrRepositoryOperation {
		t.Fatal(err)
	}
	if db.calls != 0 {
		t.Fatal(db.calls)
	}
}

func TestSecurityAgentOrderedResourceIsolation(t *testing.T) {
	for _, kind := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
		for _, family := range []string{"ordered_release61", "legacy_or_missing", "error"} {
			id := public62FreshIdentity()
			id.CredentialKind = kind
			db := &orderedPublicDB{query: func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				var q map[string]any
				_ = json.Unmarshal(args[2].(json.RawMessage), &q)
				if q["operation"] != "classify" && q["operation"] != "classify_mutation" {
					t.Errorf("unexpected lifecycle/fallback: %v", q)
					return nil, ErrRepositoryUnavailable
				}
				if family == "error" {
					return nil, errors.New("private database failure")
				}
				if q["operation"] == "classify_mutation" {
					return json.Marshal(map[string]any{"contract_version": 62, "mutation_kind": q["mutation_kind"], "definition_id": q["definition_id"], "idempotency_key": q["idempotency_key"], "trigger": q["trigger"], "family": family})
				}
				return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": q["resource_kind"], "resource_id": q["resource_id"], "family": family})
			}}
			a, _ := NewSecurityAgentOrderedResourceAuthority(db)
			if kind == CredentialBrowserSession && family == "ordered_release61" {
				continue
			}
			for _, call := range orderedResourceCalls(a, id) {
				want := ErrSecurityAgentNotOwned
				if family == "error" {
					want = ErrRepositoryUnavailable
				} else if family == "ordered_release61" {
					want = ErrRepositoryOperation
				}
				if err := call(); err != want {
					t.Fatalf("%v %s: %v want %v", kind, family, err, want)
				}
			}
			if db.calls != 7 {
				t.Fatal("missing classification or fallback", db.calls)
			}
		}
	}
}

func orderedResourceFixture(id RequestIdentity, run string, admitted bool) map[string]any {
	base := orderedPublicRunFixture(id, run, admitted)
	v := map[string]any{"contract_version": 62, "ordered": base, "trigger_id": public62Finding, "created_at": "2026-09-20T00:00:00.000000Z", "plan": nil, "approvals": []any{}}
	if admitted {
		steps := base["steps"].([]any)
		s := steps[0].(map[string]any)
		approval := s["approval"].(map[string]any)
		v["plan"] = map[string]any{"plan_hash": "sha256:" + strings.Repeat("a", 64), "catalog_version": "security-agent-actions-v1", "expires_at": "2026-09-20T01:00:00.000000Z"}
		v["approvals"] = []any{map[string]any{"id": approval["approval_id"], "run_id": run, "step_id": s["step_id"], "state": "pending", "version": 1, "expires_at": "2026-09-20T01:00:00.000000Z", "created_at": "2026-09-20T00:01:00.000000Z", "expected_effect": "Apply temporary containment policy", "reversible": true, "ttl_seconds": 300}}
	}
	return v
}

func TestSecurityAgentOrderedResourceProjection(t *testing.T) {
	id := orderedPublicIdentity()
	for _, admitted := range []bool{false, true} {
		fixture := orderedResourceFixture(id, public62Definition, admitted)
		db := &orderedPublicDB{query: func(_ context.Context, _ string, args ...any) (json.RawMessage, error) {
			var q map[string]any
			_ = json.Unmarshal(args[2].(json.RawMessage), &q)
			if q["operation"] == "classify" {
				return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": "run", "resource_id": public62Definition, "family": "ordered_release61"})
			}
			if q["operation"] != "resource_run" {
				t.Fatal(q)
			}
			return json.Marshal(fixture)
		}}
		a, _ := NewSecurityAgentOrderedResourceAuthority(db)
		result, err := a.Run(context.Background(), id, public62Definition)
		if err != nil || !validSecurityAgentRunDetail(result.Detail, public62Definition) || result.CreatedAt.Location() != time.UTC {
			t.Fatal(result, err)
		}
		if admitted && (result.Detail.Plan.Steps[1].State != "queued" || !result.Steps[1].Dependency.Blocked || len(result.Detail.Approvals) != 1) {
			t.Fatal(result)
		}
	}
}

func TestSecurityAgentOrderedResourcePairProjection(t *testing.T) {
	id := orderedPublicIdentity()
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "step1", true: "terminal"}[terminal], func(t *testing.T) {
			var wire orderedResourceWire
			raw, _ := json.Marshal(orderedResourceFixture(id, public62Finding, true))
			if public62Decode(raw, &wire) != nil {
				t.Fatal("invalid test fixture")
			}
			r := &wire.Ordered
			r.Version = 7
			r.Steps[0].State, r.Steps[0].Version = "succeeded", 4
			r.Steps[0].Approval.State, r.Steps[0].Approval.Version = "approved", 2
			r.Steps[0].Dependency.Ready = false
			r.Steps[0].Cleanup.State = "pending"
			ref, _ := CanonicalDiscoveryID(id.Scope, "public62_evidence", r.RunID+"\x1f"+r.Steps[0].StepID+"\x1ftemporary_policy_applied.v1")
			r.Steps[0].Receipt = &SecurityAgentPublicReceipt{Kind: "temporary_policy_applied.v1", Version: 1, Digest: "sha256:" + strings.Repeat("a", 64), Reference: ref}
			aid, _ := CanonicalDiscoveryID(id.Scope, "security_agent_ordered_approval", r.RunID+"\x1f"+r.Steps[1].StepID)
			r.Steps[1].State, r.Steps[1].Version = "waiting_approval", 2
			r.Steps[1].Approval.State, r.Steps[1].Approval.Version, r.Steps[1].Approval.ApprovalID = "pending", 1, &aid
			r.Steps[1].Dependency.Satisfied, r.Steps[1].Dependency.Blocked, r.Steps[1].Dependency.Ready = true, false, true
			wire.Approvals[0].State, wire.Approvals[0].Version = "approved", 2
			wire.Approvals = append(wire.Approvals, orderedResourceApproval{ID: aid, RunID: r.RunID, StepID: r.Steps[1].StepID, State: "pending", Version: 1, ExpiresAt: wire.Plan.ExpiresAt, CreatedAt: wire.Approvals[0].CreatedAt, ExpectedEffect: "Run existing test"})
			if terminal {
				r.State, r.Verification, r.Version = "contained", "contained", 10
				r.Steps[1].State, r.Steps[1].Version, r.Steps[1].Settlement = "succeeded", 5, "not_reproduced"
				r.Steps[1].Approval.State, r.Steps[1].Approval.Version = "approved", 2
				r.Steps[1].Dependency.Ready = false
				ref, _ = CanonicalDiscoveryID(id.Scope, "public62_evidence", r.RunID+"\x1f"+r.Steps[1].StepID+"\x1fexisting_test_settled.v1")
				r.Steps[1].Receipt = &SecurityAgentPublicReceipt{Kind: "existing_test_settled.v1", Version: 1, Digest: "sha256:" + strings.Repeat("b", 64), Reference: ref}
				wire.Approvals[1].State, wire.Approvals[1].Version = "approved", 2
			}
			if !public62ValidRun(*r, id) {
				t.Fatal("invalid ordered fixture")
			}
			got, ok := orderedResourceProjection(wire, id)
			if !ok || len(got.Detail.Approvals) != 2 || got.Detail.Approvals[1].ExpectedEffect != "Run existing test" || got.Detail.Approvals[1].Version != wire.Approvals[1].Version || terminal && got.Detail.Verification != "verified" {
				t.Fatal("exact ordered pair projection refused", got, ok)
			}
		})
	}
}

func orderedResourceTriggerIdentity(kind SecurityAgentMutationKind) *SecurityAgentMutationTriggerIdentity {
	if kind == SecurityAgentMutationTrigger {
		return &SecurityAgentMutationTriggerIdentity{public62Finding, 1}
	}
	return nil
}

func TestSecurityAgentOrderedResourceMutationOwnership(t *testing.T) {
	for _, credential := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
		for _, kind := range []SecurityAgentMutationKind{SecurityAgentMutationActivate, SecurityAgentMutationTrigger} {
			for _, change := range []string{"ordered", "legacy", "private", "kind", "id", "key", "contract", "family", "missing", "oversized", "provider", "expired", "trigger-id", "trigger-version", "trigger-type", "trigger-extra", "trigger-missing"} {
				t.Run(string(credential)+"/"+string(kind)+"/"+change, func(t *testing.T) {
					id := orderedPublicIdentity()
					id.CredentialKind = credential
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					db := &orderedPublicDB{query: func(bounded context.Context, sql string, args ...any) (json.RawMessage, error) {
						if sql != securityAgentPublicSQL || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentPublic().Checksum() || args[1] != migrations.SecurityAgentPublicFingerprint() {
							t.Fatal("unreviewed classifier boundary")
						}
						if d, ok := bounded.Deadline(); !ok || time.Until(d) > 5*time.Second {
							t.Fatal("unbounded classifier")
						}
						var q map[string]any
						_ = json.Unmarshal(args[2].(json.RawMessage), &q)
						want := map[string]any{"operation": "classify_mutation", "mutation_kind": string(kind), "definition_id": public62Definition, "idempotency_key": "ordered-mutation-classify-01", "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String()}
						if kind == SecurityAgentMutationTrigger {
							want["trigger"] = map[string]any{"trigger_id": public62Finding, "trigger_version": float64(1)}
						}
						if !reflect.DeepEqual(q, want) {
							t.Fatal(q, want)
						}
						v := map[string]any{"contract_version": 62, "mutation_kind": string(kind), "definition_id": public62Definition, "idempotency_key": "ordered-mutation-classify-01", "family": "ordered_release61"}
						v["trigger"] = want["trigger"]
						switch change {
						case "legacy":
							v["family"] = "legacy_or_missing"
						case "private":
							v["actor_id"] = id.PrincipalID.String()
						case "kind":
							v["mutation_kind"] = "cancel"
						case "id":
							v["definition_id"] = public62Finding
						case "key":
							v["idempotency_key"] = "wrong-idempotency-key"
						case "contract":
							v["contract_version"] = 61
						case "family":
							v["family"] = "guess"
						case "missing":
							delete(v, "family")
						case "oversized":
							return json.RawMessage(strings.Repeat(" ", 1025)), nil
						case "provider":
							return nil, errors.New("private SQL error")
						case "expired":
							cancel()
						case "trigger-id":
							v["trigger"] = map[string]any{"trigger_id": public62Definition, "trigger_version": 1}
						case "trigger-version":
							v["trigger"] = map[string]any{"trigger_id": public62Finding, "trigger_version": 2}
						case "trigger-type":
							v["trigger"] = map[string]any{"trigger_id": public62Finding, "trigger_version": "1"}
						case "trigger-extra":
							v["trigger"] = map[string]any{"trigger_id": public62Finding, "trigger_version": 1, "actor_id": id.PrincipalID.String()}
						case "trigger-missing":
							delete(v, "trigger")
						}
						return json.Marshal(v)
					}}
					r, _ := NewSecurityAgentOwnershipResolver(db)
					got, err := r.ResolveMutation(ctx, id, kind, public62Definition, "ordered-mutation-classify-01", orderedResourceTriggerIdentity(kind))
					if change == "ordered" {
						if got != SecurityAgentFamilyOrderedRelease61 || err != nil {
							t.Fatal(got, err)
						}
					} else if change == "legacy" {
						if got != SecurityAgentFamilyLegacyOrMissing || err != nil {
							t.Fatal(got, err)
						}
					} else if got != "" || err != ErrRepositoryUnavailable {
						t.Fatal(got, err)
					}
					if db.calls != 1 {
						t.Fatal("classifier dispatched lifecycle", db.calls)
					}
				})
			}
		}
	}
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Fatal("invalid classifier request reached SQL")
		return nil, nil
	}}
	r, _ := NewSecurityAgentOwnershipResolver(db)
	for _, q := range []struct {
		kind    SecurityAgentMutationKind
		id, key string
	}{{"cancel", public62Definition, "ordered-mutation-classify-01"}, {SecurityAgentMutationActivate, "invalid", "ordered-mutation-classify-01"}, {SecurityAgentMutationTrigger, public62Definition, "short"}} {
		if _, err := r.ResolveMutation(context.Background(), orderedPublicIdentity(), q.kind, q.id, q.key, orderedResourceTriggerIdentity(q.kind)); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	if _, err := r.ResolveMutation(nil, orderedPublicIdentity(), SecurityAgentMutationActivate, public62Definition, "ordered-mutation-classify-01", nil); err != ErrRepositoryOperation {
		t.Fatal(err)
	}
	for _, trigger := range []*SecurityAgentMutationTriggerIdentity{nil, {"invalid", 1}, {public62Finding, 0}, {public62Finding, 1000001}} {
		if _, err := r.ResolveMutation(context.Background(), orderedPublicIdentity(), SecurityAgentMutationTrigger, public62Definition, "ordered-mutation-classify-01", trigger); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	if _, err := r.ResolveMutation(context.Background(), orderedPublicIdentity(), SecurityAgentMutationActivate, public62Definition, "ordered-mutation-classify-01", &SecurityAgentMutationTriggerIdentity{public62Finding, 1}); err != ErrRepositoryOperation {
		t.Fatal(err)
	}
	if db.calls != 0 {
		t.Fatal(db.calls)
	}
}
