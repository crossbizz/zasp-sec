package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type humanRuntimeDatabase struct {
	existingTestCompositionDatabase
	familyCalls, admissionCalls int
	failure                     error
}

func (d *humanRuntimeDatabase) VerifySecurityAgentOrderedHTTPRelease(context.Context) error {
	return nil
}
func (d *humanRuntimeDatabase) TemporalHumanTestFamily(context.Context, apiserver.RequestIdentity, string) (bool, error) {
	d.familyCalls++
	return true, d.failure
}
func (d *humanRuntimeDatabase) RunTemporalHumanTest(_ context.Context, identity apiserver.RequestIdentity, q apiserver.SecurityAgentRunRequest) (json.RawMessage, bool, error) {
	d.admissionCalls++
	if d.failure != nil {
		return nil, true, d.failure
	}
	if identity.PrincipalID.String() != "pid_10000004-0000-4000-8000-000000000004" || q.DefinitionID != "pid_10000006-0000-4000-8000-000000000006" || q.ExpectedVersion != 4 || q.IdempotencyKey != "human76-mounted-0001" || q.TriggerVersion == nil || *q.TriggerVersion != 1 || q.TriggerSource == nil || *q.TriggerSource != "credential" {
		return nil, true, apiserver.ErrRepositoryOperation
	}
	b, err := json.Marshal(map[string]any{"id": q.RunID, "agent_id": q.DefinitionID, "state": "queued", "definition_version": q.ExpectedVersion, "version": 1, "evidence_ids": []string{q.TriggerID}, "audit_id": q.AuditID, "correlation_id": q.CorrelationID, "receipt_id": q.ReceiptID, "replayed": false})
	return b, true, err
}

// The real API mounting, middleware, tracing decorator and selected production
// handler run here. Database/session responses are controlled, not installed SQL.
// Dropping either traced capability or using a concrete handler assertion breaks it.
func TestTemporalHumanMountedProductionComposition(t *testing.T) {
	t.Setenv("HOSTNAME", "human76-mounted")
	for _, ordered := range []bool{false, true} {
		t.Run(fmt.Sprintf("ordered=%t", ordered), func(t *testing.T) {
			config := fixtureAuditExportRuntimeConfig(t)
			config.AuditExports = nil
			config.SecurityAgentOrderedHTTPEnabled = ordered
			db := &humanRuntimeDatabase{existingTestCompositionDatabase: existingTestCompositionDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view", "manage_workflows", "run_tests"}}}}
			deps, err := composeRuntimeDependenciesWithSecurityAgent(config, db, db, auditFactoryProvider())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, c := range deps.Closers {
					_ = c.Close()
				}
			}()
			for _, failure := range []error{nil, apiserver.ErrRepositoryUnavailable} {
				db.failure = failure
				before := db.admissionCalls
				body := `{"environment_id":"pid_10000003-0000-4000-8000-000000000003","trigger_kind":"finding","trigger_id":"pid_10000005-0000-4000-8000-000000000005","trigger_version":1,"trigger_source":"credential"}`
				r := publicPageRuntimeRequest(config, "/api/v1/security-agents/pid_10000006-0000-4000-8000-000000000006/runs")
				r.Method = http.MethodPost
				r.Body = io.NopCloser(strings.NewReader(body))
				r.ContentLength = int64(len(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", config.PublicOrigin)
				r.Header.Set("X-CSRF-Token", strings.Repeat("c", 32))
				r.Header.Set("Idempotency-Key", "human76-mounted-0001")
				r.Header.Set("If-Match", `"4"`)
				w := httptest.NewRecorder()
				deps.ProductHandler.ServeHTTP(w, r)
				want := http.StatusAccepted
				if failure != nil {
					want = http.StatusServiceUnavailable
				}
				if w.Code != want {
					t.Fatalf("mounted status=%d want=%d family=%d admission=%d body=%s", w.Code, want, db.familyCalls, db.admissionCalls, w.Body.String())
				}
				calls := 1
				if ordered && failure != nil {
					calls = 0
				}
				if db.admissionCalls-before != calls {
					t.Fatal("traced admission dispatch", db.admissionCalls, before, calls)
				}
			}
			if ordered && db.familyCalls != 2 || !ordered && db.familyCalls != 0 {
				t.Fatal("selected classification", db.familyCalls)
			}
		})
	}
}

func TestTemporalHumanTracingCapability(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	type family interface {
		TemporalHumanTestFamily(context.Context, apiserver.RequestIdentity, string) (bool, error)
	}
	type admission interface {
		RunTemporalHumanTest(context.Context, apiserver.RequestIdentity, apiserver.SecurityAgentRunRequest) (json.RawMessage, bool, error)
	}
	for _, db := range []*tracedJSONDatabase{nil, {}, {next: &auditExportRuntimeDatabase{}}, {next: &humanRuntimeDatabase{failure: apiserver.ErrRepositoryConflict}}} {
		f, ok := any(db).(family)
		if !ok {
			t.Fatal("tracing drops human family capability")
		}
		a, ok := any(db).(admission)
		if !ok {
			t.Fatal("tracing drops human admission capability")
		}
		for _, ctx := range []context.Context{nil, canceled, context.Background()} {
			owned, err := f.TemporalHumanTestFamily(ctx, apiserver.RequestIdentity{}, "definition")
			_, handled, runErr := a.RunTemporalHumanTest(ctx, apiserver.RequestIdentity{}, apiserver.SecurityAgentRunRequest{})
			invalid := ctx == nil || ctx.Err() != nil || db == nil || db.next == nil
			if invalid {
				if err != apiserver.ErrRepositoryUnavailable || runErr != apiserver.ErrRepositoryUnavailable {
					t.Fatal("invalid wrapper/context", err, runErr)
				}
				continue
			}
			if _, present := db.next.(*humanRuntimeDatabase); present {
				if !owned || !handled || err != apiserver.ErrRepositoryConflict || runErr != apiserver.ErrRepositoryConflict {
					t.Fatal("present authority errors lost", owned, handled, err, runErr)
				}
			} else if owned || handled || err != nil || runErr != nil {
				t.Fatal("unsupported capability changed", owned, handled, err, runErr)
			}
		}
	}
}
