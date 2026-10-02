package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// These tests control only the database boundary. The public repository,
// tracing decorator, 78 selection and response decoders are production code.
type temporalLifecycleDatabase struct {
	t         *testing.T
	present78 bool
	raw       json.RawMessage
	queries   []string
	legacy    int
}

func (d *temporalLifecycleDatabase) SchemaVersion(context.Context) (string, error) {
	return apiserver.ProductionRecoverySchemaVersion, nil
}
func (d *temporalLifecycleDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected write")
}
func (d *temporalLifecycleDatabase) SecurityAgentRunContextAvailable(context.Context) (bool, error) {
	return true, nil
}
func (d *temporalLifecycleDatabase) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	d.queries = append(d.queries, q)
	switch q {
	case "SELECT jsonb_build_object('release',zasp_recovery_execution_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_api'))":
		return json.RawMessage(`{"release":true,"principal":true}`), nil
	case "SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)":
		return json.RawMessage(fmt.Sprint(d.present78)), nil
	case "SELECT to_jsonb(zasp_temporal78.api_ready($1,$2))":
		return json.RawMessage(`true`), nil
	case "SELECT zasp_temporal78.approval($1,$2,$3,$4,$5)", "SELECT zasp_temporal78.decide_approval($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)":
		return json.RawMessage(`null`), nil // actual nonowner contract
	}
	if strings.Contains(q, "cancel") || strings.Contains(q, "approval") {
		d.legacy++
		return d.raw, nil
	}
	d.t.Fatalf("unexpected statement: %s", q)
	return nil, errors.New("unexpected statement")
}

type temporalLifecycleCapability struct {
	*temporalLifecycleDatabase
	handled bool
	err     error
	calls   []string
	ctx     context.Context
	args    []any
}

func (d *temporalLifecycleCapability) result(ctx context.Context, op string, args ...any) (json.RawMessage, bool, error) {
	d.calls = append(d.calls, op)
	d.ctx = ctx
	d.args = args
	return d.raw, d.handled, d.err
}
func (d *temporalLifecycleCapability) CancelTemporalTestRun(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.result(ctx, "cancel", args...)
}
func (d *temporalLifecycleCapability) ReadTemporalTestApproval(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.result(ctx, "read", args...)
}
func (d *temporalLifecycleCapability) DecideTemporalTestApproval(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.result(ctx, "decide", args...)
}
func (d *temporalLifecycleCapability) PageTemporalTestApprovals(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.result(ctx, "page", args...)
}

func temporalLifecycleID(n int) string { return fmt.Sprintf("pid_74000000-0000-4000-8000-%012d", n) }
func temporalLifecycleFixture(t *testing.T, op string) (apiserver.RequestIdentity, json.RawMessage, []any, func(context.Context, *apiserver.PostgresRepository, apiserver.RequestIdentity) error) {
	t.Helper()
	id := func(n int) domain.ProductID {
		v, e := domain.ParseProductID(temporalLifecycleID(n))
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	scope, e := domain.NewScope(id(1), id(2), id(3))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	identity := apiserver.RequestIdentity{Scope: scope, PrincipalID: id(4), CredentialKind: apiserver.CredentialBrowserSession, FreshAuthenticated: true, FreshAuthExpiresAt: now.Add(time.Hour)}
	args := []any{temporalLifecycleID(1), temporalLifecycleID(2), temporalLifecycleID(3)}
	detail := map[string]any{"id": temporalLifecycleID(5), "run_id": temporalLifecycleID(6), "step_id": temporalLifecycleID(7), "state": "pending", "version": 1, "expires_at": now, "evidence_summary": []string{temporalLifecycleID(8)}, "expected_effect": "Move finding to under review", "ttl_seconds": 0, "reversible": true}
	hash := "sha256:" + strings.Repeat("a", 64)
	envelope := map[string]any{"detail": detail, "context": map[string]any{"approval_id": temporalLifecycleID(5), "run_id": temporalLifecycleID(6), "step_id": temporalLifecycleID(7), "agent_id": temporalLifecycleID(9), "approval_plan_hash": hash, "plan_hash": hash, "catalog_version": "security-agent-actions-v1", "action": "update_finding_response", "authorization": "approval_required", "arguments": nil, "requester_id": temporalLifecycleID(4), "planner_receipt": nil}}
	var payload any
	var invoke func(context.Context, *apiserver.PostgresRepository, apiserver.RequestIdentity) error
	switch op {
	case "cancel":
		input := apiserver.SecurityAgentCancelRequest{RunID: temporalLifecycleID(6), IdempotencyKey: "cancel-runtime-test-0001", ExpectedVersion: 1, AuditID: temporalLifecycleID(10), CorrelationID: temporalLifecycleID(11), ReceiptID: temporalLifecycleID(12)}
		args = append(args, input.RunID, identity.PrincipalID.String(), input.IdempotencyKey, input.ExpectedVersion, input.AuditID, input.CorrelationID, input.ReceiptID)
		payload = map[string]any{"id": input.RunID, "agent_id": temporalLifecycleID(9), "state": "cancelled", "version": 2, "definition_version": 1, "evidence_ids": []string{temporalLifecycleID(8)}, "audit_id": input.AuditID, "correlation_id": input.CorrelationID, "receipt_id": input.ReceiptID, "replayed": false}
		invoke = func(ctx context.Context, r *apiserver.PostgresRepository, i apiserver.RequestIdentity) error {
			v, e := r.CancelSecurityAgentRun(ctx, i, input)
			if e == nil && (v.ID != input.RunID || v.Version != 2) {
				t.Fatal("cancel result changed")
			}
			return e
		}
	case "read":
		args = append(args, temporalLifecycleID(5), identity.PrincipalID.String())
		payload = envelope
		invoke = func(ctx context.Context, r *apiserver.PostgresRepository, i apiserver.RequestIdentity) error {
			v, e := r.GetSecurityAgentApproval(ctx, i, temporalLifecycleID(5))
			if e == nil && (v.ID != temporalLifecycleID(5) || v.Context == nil) {
				t.Fatal("read result changed")
			}
			return e
		}
	case "decide":
		input := apiserver.SecurityAgentApprovalDecisionRequest{ApprovalID: temporalLifecycleID(5), IdempotencyKey: "approval-runtime-test-0001", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: now, AuditID: temporalLifecycleID(10), CorrelationID: temporalLifecycleID(11), ReceiptID: temporalLifecycleID(12)}
		args = append(args, input.ApprovalID, identity.PrincipalID.String(), input.IdempotencyKey, input.ExpectedVersion, input.Decision, input.FreshAuthAt, input.AuditID, input.CorrelationID, input.ReceiptID)
		detail["state"] = "approved"
		detail["version"] = 2
		detail["audit_id"] = input.AuditID
		detail["correlation_id"] = input.CorrelationID
		detail["receipt_id"] = input.ReceiptID
		detail["replayed"] = false
		payload = detail
		invoke = func(ctx context.Context, r *apiserver.PostgresRepository, i apiserver.RequestIdentity) error {
			v, e := r.DecideSecurityAgentApproval(ctx, i, input)
			if e == nil && (v.ID != input.ApprovalID || v.State != "approved") {
				t.Fatal("decision result changed")
			}
			return e
		}
	case "page":
		args = append(args, "", "", nil, "", 10, identity.PrincipalID.String())
		payload = map[string]any{"items": []any{}, "next_created_at": nil, "next_id": nil}
		invoke = func(ctx context.Context, r *apiserver.PostgresRepository, i apiserver.RequestIdentity) error {
			v, e := r.ListSecurityAgentApprovals(ctx, i, apiserver.SecurityAgentApprovalPageRequest{Limit: 10})
			if e == nil && len(v.Items) != 0 {
				t.Fatal("page result changed")
			}
			return e
		}
	default:
		t.Fatal("invalid fixture operation")
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		t.Fatal(e)
	}
	return identity, raw, args, invoke
}

func TestTemporalLifecycleRuntimePublicRepository(t *testing.T) {
	for _, op := range []string{"cancel", "read", "decide", "page"} {
		for _, mode := range []string{"handled", "unhandled", "no-interface", "error-handled", "error-unhandled"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				identity, raw, wantArgs, invoke := temporalLifecycleFixture(t, op)
				base := &temporalLifecycleDatabase{t: t, raw: raw, present78: op == "read" || op == "decide"}
				cap := &temporalLifecycleCapability{temporalLifecycleDatabase: base, handled: mode == "handled" || mode == "error-handled"}
				if strings.HasPrefix(mode, "error-") {
					cap.err = apiserver.ErrRepositoryUnavailable
				}
				var next apiserver.JSONDatabase = cap
				if mode == "no-interface" {
					next = base
				}
				wrapper := &tracedJSONDatabase{next: next, metrics: newOperationalMetrics(), exporter: newStructuredSpanExporter(io.Discard)}
				repo, e := apiserver.NewSecurityAgentPostgresRepository(wrapper)
				if e != nil {
					t.Fatal(e)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				e = invoke(ctx, repo, identity)
				if cap.err != nil {
					if !errors.Is(e, cap.err) || base.legacy != 0 {
						t.Fatalf("error fell back: err=%v legacy=%d", e, base.legacy)
					}
				} else if e != nil {
					t.Fatal(e)
				}
				wantCalls := 1
				if mode == "no-interface" {
					wantCalls = 0
				}
				if len(cap.calls) != wantCalls {
					t.Fatalf("capability calls=%v, want %d; legacy=%d", cap.calls, wantCalls, base.legacy)
				}
				if wantCalls == 1 && (cap.calls[0] != op || cap.ctx != ctx || !reflect.DeepEqual(cap.args, wantArgs)) {
					t.Fatalf("forwarding changed: op=%v context=%v args=%#v want=%#v", cap.calls, cap.ctx == ctx, cap.args, wantArgs)
				}
				wantLegacy := 0
				if mode == "unhandled" || mode == "no-interface" {
					wantLegacy = 1
				}
				if base.legacy != wantLegacy {
					t.Fatalf("legacy=%d want=%d", base.legacy, wantLegacy)
				}
				if base.present78 {
					found := false
					for _, q := range base.queries {
						if strings.HasPrefix(q, "SELECT zasp_temporal78.") {
							found = true
						}
					}
					if !found {
						t.Fatal("78 nonowner probe not consumed")
					}
				}
			})
		}
	}
}

type temporalLifecycleProbe interface {
	CancelTemporalTestRun(context.Context, ...any) (json.RawMessage, bool, error)
	ReadTemporalTestApproval(context.Context, ...any) (json.RawMessage, bool, error)
	DecideTemporalTestApproval(context.Context, ...any) (json.RawMessage, bool, error)
	PageTemporalTestApprovals(context.Context, ...any) (json.RawMessage, bool, error)
}

func TestTemporalLifecycleRuntimeForwardingContract(t *testing.T) {
	base := &temporalLifecycleDatabase{t: t, raw: json.RawMessage(`{"opaque":true}`)}
	cap := &temporalLifecycleCapability{temporalLifecycleDatabase: base}
	w := &tracedJSONDatabase{next: cap}
	p, ok := any(w).(temporalLifecycleProbe)
	if !ok {
		t.Fatal("four consumed74 capabilities missing")
	}
	methods := func(p temporalLifecycleProbe) []func(context.Context, ...any) (json.RawMessage, bool, error) {
		return []func(context.Context, ...any) (json.RawMessage, bool, error){p.CancelTemporalTestRun, p.ReadTemporalTestApproval, p.DecideTemporalTestApproval, p.PageTemporalTestApprovals}
	}
	ctx := context.WithValue(context.Background(), struct{}{}, "context-identity")
	args := []any{"scope", int64(42), json.RawMessage(`{"request":true}`)}
	sentinel := errors.New("capability sentinel")
	for _, method := range methods(p) {
		for _, handled := range []bool{false, true} {
			for _, failure := range []error{nil, sentinel} {
				cap.handled = handled
				cap.err = failure
				raw, h, e := method(ctx, args...)
				if string(raw) != string(base.raw) || h != handled || e != failure || cap.ctx != ctx || !reflect.DeepEqual(cap.args, args) {
					t.Fatal("result/error/handled/context/arguments changed")
				}
			}
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var typedNil *temporalLifecycleCapability
	for _, tc := range []struct {
		name    string
		wrapper *tracedJSONDatabase
		ctx     context.Context
	}{
		{"nil wrapper", nil, ctx}, {"nil next", &tracedJSONDatabase{}, ctx}, {"typed nil", &tracedJSONDatabase{next: typedNil}, ctx}, {"nil context", w, nil}, {"cancelled", w, cancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(cap.calls)
			for _, method := range methods(any(tc.wrapper).(temporalLifecycleProbe)) {
				raw, h, e := method(tc.ctx, args...)
				if raw != nil || h || !errors.Is(e, apiserver.ErrRepositoryUnavailable) {
					t.Fatal("invalid boundary accepted")
				}
			}
			if len(cap.calls) != before {
				t.Fatal("invalid input forwarded")
			}
		})
	}
	for _, method := range methods(any(&tracedJSONDatabase{next: base}).(temporalLifecycleProbe)) {
		raw, h, e := method(ctx, args...)
		if raw != nil || h || e != nil {
			t.Fatal("absent capability changed")
		}
	}
}
