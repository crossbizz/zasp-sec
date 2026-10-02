package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func public62FreshIdentity() RequestIdentity {
	id := orderedPublicIdentity()
	id.FreshAuthenticated = true
	id.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	return id
}
func public62DecisionFixture(id RequestIdentity, q SecurityAgentPublicDecision) map[string]any {
	s, _ := CanonicalDiscoveryID(id.Scope, "security_agent_step", q.RunID+"\x1f0")
	audit, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1fdecide\x1f"+q.IdempotencyKey)
	receipt, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1fdecide\x1f"+q.IdempotencyKey)
	return map[string]any{"contract_version": 62, "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "run_id": q.RunID, "run_state": "running", "run_version": 4, "step_id": s, "step_state": "authorized", "step_version": 2, "approval_id": q.ApprovalID, "approval_version": 2, "decision": "approved", "outcome": "approved", "audit_id": audit, "receipt_id": receipt, "replayed": false}
}
func public62DecisionInput() SecurityAgentPublicDecision {
	id := orderedPublicIdentity()
	step, _ := CanonicalDiscoveryID(id.Scope, "security_agent_step", public62Finding+"\x1f0")
	approval, _ := CanonicalDiscoveryID(id.Scope, "security_agent_ordered_approval", public62Finding+"\x1f"+step)
	return SecurityAgentPublicDecision{RunID: public62Finding, RunVersion: 3, ApprovalID: approval, ApprovalVersion: 1, Decision: "approved", IdempotencyKey: "public62-go-decision-0001"}
}

func TestSecurityAgentPublic62MutationCalls(t *testing.T) {
	id := public62FreshIdentity()
	q := public62DecisionInput()
	db := &orderedPublicDB{}
	repo, _ := NewSecurityAgentPublicRepository(db)
	for _, op := range []string{"decide", "decide", "cancel"} {
		db.query = func(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
			if statement != "SELECT zasp_ordered_public62.api($1,$2,$3::jsonb)" || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentPublic().Checksum() || args[1] != migrations.SecurityAgentPublicFingerprint() {
				t.Fatal("incorrect mutation SQL", statement, args)
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 5*time.Second {
				t.Fatal("unbounded mutation")
			}
			var got map[string]any
			if json.Unmarshal(args[2].(json.RawMessage), &got) != nil {
				t.Fatal("wire request")
			}
			want := map[string]any{"organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "operation": op, "run_id": q.RunID, "run_version": float64(3), "idempotency_key": q.IdempotencyKey}
			response := public62DecisionFixture(id, q)
			if op == "decide" {
				want["approval_id"], want["approval_version"], want["decision"], want["fresh_auth_at"] = q.ApprovalID, float64(1), q.Decision, id.FreshAuthExpiresAt.Add(-5*time.Minute).Format(time.RFC3339Nano)
			} else {
				for _, key := range []string{"approval_id", "approval_version", "decision"} {
					delete(response, key)
				}
				response["run_state"], response["step_state"], response["step_id"], response["step_version"], response["cleanup_required"], response["outcome"] = "needs_human", nil, nil, 0, false, "cancelled-request"
				response["cancellation_phase"] = "before-admission"
				response["audit_id"], _ = CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
				response["receipt_id"], _ = CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("identity or request changed", got, want)
			}
			return json.Marshal(response)
		}
		var err error
		if op == "decide" {
			_, err = repo.Decide(context.Background(), id, q)
		} else {
			_, err = repo.Cancel(context.Background(), id, SecurityAgentPublicCancellation{RunID: q.RunID, RunVersion: 3, IdempotencyKey: q.IdempotencyKey})
		}
		if err != nil {
			t.Fatal(op, err)
		}
	}
	if db.calls != 3 {
		t.Fatal("cached or repeated mutation", db.calls)
	}
}

func TestSecurityAgentPublic62MutationLocalValidation(t *testing.T) {
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Error("invalid input reached SQL")
		return nil, nil
	}}
	repo, _ := NewSecurityAgentPublicRepository(db)
	id := public62FreshIdentity()
	q := public62DecisionInput()
	for _, mutate := range []func(*SecurityAgentPublicDecision){func(q *SecurityAgentPublicDecision) { q.RunID = "" }, func(q *SecurityAgentPublicDecision) { q.ApprovalID = "bad" }, func(q *SecurityAgentPublicDecision) { q.RunVersion = 0 }, func(q *SecurityAgentPublicDecision) { q.RunVersion = 1000000 }, func(q *SecurityAgentPublicDecision) { q.ApprovalVersion = 0 }, func(q *SecurityAgentPublicDecision) { q.ApprovalVersion = 1000000 }, func(q *SecurityAgentPublicDecision) { q.Decision = "cancelled" }, func(q *SecurityAgentPublicDecision) { q.IdempotencyKey = "short" }, func(q *SecurityAgentPublicDecision) { q.IdempotencyKey = strings.Repeat("x", 129) }} {
		bad := q
		mutate(&bad)
		if _, err := repo.Decide(context.Background(), id, bad); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(*RequestIdentity){func(i *RequestIdentity) { i.FreshAuthenticated = false }, func(i *RequestIdentity) { i.FreshAuthExpiresAt = time.Time{} }, func(i *RequestIdentity) { i.FreshAuthExpiresAt = time.Now().UTC().Add(-time.Second) }, func(i *RequestIdentity) { i.FreshAuthExpiresAt = time.Now().UTC().Add(6 * time.Minute) }, func(i *RequestIdentity) {
		i.FreshAuthExpiresAt = i.FreshAuthExpiresAt.In(time.FixedZone("other", 3600))
	}, func(i *RequestIdentity) { i.CredentialKind = CredentialBearerToken }, func(i *RequestIdentity) { i.CSRFToken = "" }} {
		bad := id
		mutate(&bad)
		if _, err := repo.Decide(context.Background(), bad, q); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		if _, err := repo.Decide(ctx, id, q); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
		if _, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: q.RunID, RunVersion: 3, IdempotencyKey: q.IdempotencyKey}); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, q := range []SecurityAgentPublicCancellation{{}, {RunID: public62Finding, RunVersion: 0, IdempotencyKey: strings.Repeat("a", 16)}, {RunID: public62Finding, RunVersion: 1000000, IdempotencyKey: strings.Repeat("a", 16)}, {RunID: public62Finding, RunVersion: 1, IdempotencyKey: "short"}} {
		if _, err := repo.Cancel(context.Background(), id, q); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	if db.calls != 0 {
		t.Fatal(db.calls)
	}
}

func TestSecurityAgentPublic62MutationDecode(t *testing.T) {
	id := public62FreshIdentity()
	q := public62DecisionInput()
	db := &orderedPublicDB{}
	repo, _ := NewSecurityAgentPublicRepository(db)
	for name, change := range map[string]func(map[string]any){"private": func(v map[string]any) { v["lease_token"] = "secret" }, "scope": func(v map[string]any) { v["organization_id"] = public62Finding }, "run-version": func(v map[string]any) { v["run_version"] = 3 }, "approval-version": func(v map[string]any) { v["approval_version"] = 1 }, "decision": func(v map[string]any) { v["decision"] = "rejected" }, "outcome": func(v map[string]any) { v["outcome"] = "blocked" }, "run-state": func(v map[string]any) { v["run_state"] = "cancelled" }, "step-state": func(v map[string]any) { v["step_state"] = "executing" }, "step-version": func(v map[string]any) { v["step_version"] = 0 }, "approval": func(v map[string]any) { v["approval_id"] = public62Finding }, "audit": func(v map[string]any) { v["audit_id"] = public62Finding }, "receipt": func(v map[string]any) { v["receipt_id"] = public62Finding }, "null": func(v map[string]any) { v["replayed"] = nil }, "missing": func(v map[string]any) { delete(v, "outcome") }} {
		t.Run(name, func(t *testing.T) {
			v := public62DecisionFixture(id, q)
			change(v)
			db.query = func(context.Context, string, ...any) (json.RawMessage, error) { return json.Marshal(v) }
			got, err := repo.Decide(context.Background(), id, q)
			if err != ErrRepositoryUnavailable || got != (SecurityAgentPublicDecisionResult{}) {
				t.Fatal(got, err)
			}
		})
	}
	for _, input := range []error{errors.New("secret provider detail"), &pgconn.PgError{Code: "23505", Message: "secret"}, ErrRepositoryConflict, ErrRepositoryOperation, context.Canceled} {
		db.query = func(context.Context, string, ...any) (json.RawMessage, error) { return nil, input }
		_, err := repo.Decide(context.Background(), id, q)
		want := ErrRepositoryUnavailable
		if errors.Is(input, ErrRepositoryConflict) {
			want = ErrRepositoryConflict
		}
		if pg, ok := input.(*pgconn.PgError); ok && pg.Code == "23505" {
			want = ErrRepositoryConflict
		}
		if input == ErrRepositoryOperation {
			want = input
		}
		if err != want {
			t.Fatal(err, want)
		}
	}
}

func TestSecurityAgentPublic62DecisionStepBinding(t *testing.T) {
	id := public62FreshIdentity()
	q := public62DecisionInput()
	v := public62DecisionFixture(id, q)
	v["step_id"] = public62Definition
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return json.Marshal(v) }}
	repo, _ := NewSecurityAgentPublicRepository(db)
	if got, err := repo.Decide(context.Background(), id, q); err != ErrRepositoryUnavailable {
		t.Fatal("unrelated step accepted for approval", got, err)
	}
}

func TestSecurityAgentPublic62MutationExactStepVersion(t *testing.T) {
	id := public62FreshIdentity()
	for _, index := range []string{"0", "1"} {
		t.Run(index, func(t *testing.T) {
			q := public62DecisionInput()
			step, _ := CanonicalDiscoveryID(id.Scope, "security_agent_step", q.RunID+"\x1f"+index)
			q.ApprovalID, _ = CanonicalDiscoveryID(id.Scope, "security_agent_ordered_approval", q.RunID+"\x1f"+step)
			want := 2
			if index == "1" {
				q.RunVersion, want = 7, 3
			}
			v := public62DecisionFixture(id, q)
			v["step_id"], v["run_version"], v["step_version"] = step, q.RunVersion+1, want
			db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return json.Marshal(v) }}
			repo, _ := NewSecurityAgentPublicRepository(db)
			if _, err := repo.Decide(context.Background(), id, q); err != nil {
				t.Fatal("exact decision", err)
			}
			for _, wrong := range []int{want - 1, want + 1} {
				v["step_version"] = wrong
				if got, err := repo.Decide(context.Background(), id, q); err != ErrRepositoryUnavailable {
					t.Errorf("inexact decision version accepted: %v %v", got, err)
				}
			}
			for _, key := range []string{"approval_id", "approval_version", "decision"} {
				delete(v, key)
			}
			v["run_state"], v["step_state"], v["outcome"], v["cleanup_required"] = "cancelled", "executing", "cancelled-request", true
			v["cancellation_phase"] = "executing"
			v["audit_id"], _ = CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
			v["receipt_id"], _ = CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
			cancel := SecurityAgentPublicCancellation{RunID: q.RunID, RunVersion: q.RunVersion + 2, IdempotencyKey: q.IdempotencyKey}
			v["run_version"] = cancel.RunVersion + 1
			v["step_version"] = want + 1
			if _, err := repo.Cancel(context.Background(), id, cancel); err != nil {
				t.Fatal("exact executing cancellation", err)
			}
			v["step_version"] = want
			if got, err := repo.Cancel(context.Background(), id, cancel); err != ErrRepositoryUnavailable {
				t.Errorf("inexact cancellation version accepted: %v %v", got, err)
			}
		})
	}
}

func TestSecurityAgentPublic62CancellationDecode(t *testing.T) {
	id := orderedPublicIdentity()
	q := SecurityAgentPublicCancellation{RunID: public62Finding, RunVersion: 3, IdempotencyKey: "public62-go-cancel-0001"}
	fixture := func() map[string]any {
		step, _ := CanonicalDiscoveryID(id.Scope, "security_agent_step", q.RunID+"\x1f0")
		audit, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
		receipt, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
		return map[string]any{"contract_version": 62, "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "run_id": q.RunID, "run_version": 4, "run_state": "cancelled", "step_id": step, "step_state": "cancelled", "step_version": 2, "cleanup_required": false, "cancellation_phase": "pending-approval", "outcome": "cancelled-request", "audit_id": audit, "receipt_id": receipt, "replayed": false}
	}
	db := &orderedPublicDB{}
	repo, _ := NewSecurityAgentPublicRepository(db)
	for name, change := range map[string]func(map[string]any){"private": func(v map[string]any) { v["receipt_body"] = "secret" }, "foreign": func(v map[string]any) { v["environment_id"] = q.RunID }, "version": func(v map[string]any) { v["run_version"] = 3 }, "terminal": func(v map[string]any) { v["run_state"] = "remediated" }, "step-nil": func(v map[string]any) { v["step_id"] = nil }, "step-state-nil": func(v map[string]any) { v["step_state"] = nil }, "step-live": func(v map[string]any) { v["step_state"] = "authorized" }, "step-zero": func(v map[string]any) { v["step_version"] = 0 }, "pre-admission-cleanup": func(v map[string]any) {
		v["step_id"], v["step_state"], v["step_version"], v["cleanup_required"] = nil, nil, 0, true
	}, "missing": func(v map[string]any) { delete(v, "cleanup_required") }, "outcome": func(v map[string]any) { v["outcome"] = "approved" }, "audit": func(v map[string]any) { v["audit_id"] = q.RunID }} {
		t.Run(name, func(t *testing.T) {
			v := fixture()
			change(v)
			db.query = func(context.Context, string, ...any) (json.RawMessage, error) { return json.Marshal(v) }
			got, err := repo.Cancel(context.Background(), id, q)
			if err != ErrRepositoryUnavailable || !reflect.DeepEqual(got, SecurityAgentPublicCancellationResult{}) {
				t.Fatal(got, err)
			}
		})
	}
	for _, replay := range []bool{false, true} {
		v := fixture()
		v["replayed"] = replay
		db.query = func(context.Context, string, ...any) (json.RawMessage, error) { return json.Marshal(v) }
		got, err := repo.Cancel(context.Background(), id, q)
		if err != nil || got.Replayed != replay {
			t.Fatal(got, err)
		}
	}
	for _, patch := range []map[string]any{{"step_state": "complete"}, {"step_version": 1}, {"cancellation_phase": "authorized"}, {"cancellation_phase": "queued"}, {"cancellation_phase": "executing"}, {"cancellation_phase": "unknown"}, {"cancellation_phase": nil}} {
		v := fixture()
		for k, x := range patch {
			v[k] = x
		}
		db.query = func(context.Context, string, ...any) (json.RawMessage, error) { return json.Marshal(v) }
		if got, err := repo.Cancel(context.Background(), id, q); err != ErrRepositoryUnavailable {
			t.Fatal("impossible cancellation step accepted", got, err)
		}
	}
}

func TestSecurityAgentPublic62CancelledVersionExact(t *testing.T) {
	id := orderedPublicIdentity()
	for _, index := range []string{"0", "1"} {
		t.Run(index, func(t *testing.T) {
			q := SecurityAgentPublicCancellation{RunID: public62Finding, RunVersion: 4, IdempotencyKey: "public62-authorized-cancel-0001"}
			want := 3
			if index == "1" {
				q.RunVersion, want = 8, 4
			}
			step, _ := CanonicalDiscoveryID(id.Scope, "security_agent_step", q.RunID+"\x1f"+index)
			audit, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
			receipt, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1fcancel\x1f"+q.IdempotencyKey)
			v := map[string]any{"contract_version": 62, "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "run_id": q.RunID, "run_version": q.RunVersion + 1, "run_state": "cancelled", "step_id": step, "step_state": "cancelled", "step_version": want, "cleanup_required": index == "1", "outcome": "cancelled-request", "audit_id": audit, "receipt_id": receipt, "replayed": true}
			v["cancellation_phase"] = "authorized"
			db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return json.Marshal(v) }}
			repo, _ := NewSecurityAgentPublicRepository(db)
			if _, err := repo.Cancel(context.Background(), id, q); err != nil {
				t.Fatal("exact authorized cancellation", err)
			}
			v["step_version"] = want - 1
			if got, err := repo.Cancel(context.Background(), id, q); err != ErrRepositoryUnavailable {
				t.Fatal("authorized cancellation downgrade accepted", got, err)
			}
		})
	}
}
