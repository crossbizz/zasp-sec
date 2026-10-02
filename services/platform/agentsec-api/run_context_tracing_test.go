package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type contextCapabilityDatabase struct {
	boundaryDatabase
	available bool
	err       error
}

type contextCompositionDatabase struct {
	auditExportRuntimeDatabase
	refused bool
	reads   int
}

func (db *contextCompositionDatabase) SecurityAgentRunContextAvailable(context.Context) (bool, error) {
	if db.refused {
		return false, apiserver.ErrRepositoryUnavailable
	}
	return true, nil
}
func (db *contextCompositionDatabase) VerifySecurityAgentBudgetRelease(context.Context) error {
	if db.refused {
		return apiserver.ErrRepositoryUnavailable
	}
	return nil
}
func (db *contextCompositionDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	if query != `SELECT zasp_security_agent_run_context_v54($1,$2,$3,$4)` {
		return db.auditExportRuntimeDatabase.QueryJSON(ctx, query, args...)
	}
	if len(args) != 4 || args[0] != "pid_10000001-0000-4000-8000-000000000001" || args[1] != "pid_10000002-0000-4000-8000-000000000002" || args[2] != "pid_10000003-0000-4000-8000-000000000003" || args[3] != "pid_78000006-0000-4000-8000-000000000006" {
		return nil, apiserver.ErrRepositoryUnavailable
	}
	db.reads++
	return json.RawMessage(`{"detail":{"run":{"id":"pid_78000006-0000-4000-8000-000000000006","agent_id":"pid_78000001-0000-4000-8000-000000000001","state":"remediated","evidence_ids":["pid_78000005-0000-4000-8000-000000000005"],"definition_version":1,"version":4},"evidence_ids":["pid_78000005-0000-4000-8000-000000000005"],"plan":{"plan_hash":"sha256:` + strings.Repeat("a", 64) + `","catalog_version":"security-agent-actions-v1","expires_at":"2026-09-16T12:00:00Z","steps":[{"id":"pid_78000007-0000-4000-8000-000000000007","index":0,"action":"update_finding_response","authorization":"autonomous","state":"succeeded","version":1}]},"authorization":"authorized","approvals":[],"execution":[{"step_id":"pid_78000007-0000-4000-8000-000000000007","action":"update_finding_response","state":"succeeded","version":1}],"verification":"verified"},"context":{"trigger":{"kind":"finding","id":"pid_78000005-0000-4000-8000-000000000005","version":1},"planner_receipt":{"run_id":"pid_78000006-0000-4000-8000-000000000006","plan_hash":"sha256:` + strings.Repeat("a", 64) + `","outcome":"accepted","summary":"Review password=fixture-secret; now."}}}`), nil
}

// Actual runtime composition/middleware/decorator/repository/handler with a
// controlled SQL/session boundary. This does not claim real login or live54 DB.
func TestRunContextMountedProductionComposition(t *testing.T) {
	t.Setenv("HOSTNAME", "run-context-composition-test")
	config := fixtureAuditExportRuntimeConfig(t)
	config.AuditExports = nil
	db := &contextCompositionDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view"}}}
	deps, err := composeRuntimeDependenciesWithSecurityAgent(config, db, db, auditFactoryProvider())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, closer := range deps.Closers {
			_ = closer.Close()
		}
	}()
	for _, requested := range []bool{false, true} {
		request := publicPageRuntimeRequest(config, "/api/v1/security-agent-runs/pid_78000006-0000-4000-8000-000000000006")
		if requested {
			request.Header.Set("X-Zasp-Run-Context", "v1")
		}
		response := httptest.NewRecorder()
		deps.ProductHandler.ServeHTTP(response, request)
		var fields map[string]json.RawMessage
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &fields) != nil {
			t.Fatalf("mounted Get status=%d body=%s", response.Code, response.Body.String())
		}
		if (fields["run_context"] != nil) != requested || strings.Contains(response.Body.String(), "fixture-secret") || strings.Contains(response.Body.String(), "planner_receipt") {
			t.Fatal("mounted context negotiation/redaction failed")
		}
		if requested && !strings.Contains(string(fields["run_context"]), "password=[REDACTED]") {
			t.Fatal("mounted route omitted sanitized summary")
		}
	}
	if db.reads != 2 {
		t.Fatal("mounted route did not use scoped54 SQL", db.reads)
	}
	db.refused = true
	request := publicPageRuntimeRequest(config, "/api/v1/security-agent-runs/pid_78000006-0000-4000-8000-000000000006")
	request.Header.Set("X-Zasp-Run-Context", "v1")
	response := httptest.NewRecorder()
	deps.ProductHandler.ServeHTTP(response, request)
	if response.Code != 503 || db.reads != 2 {
		t.Fatal("mounted corrupt54 authority fell back or read data", response.Code, db.reads)
	}
}

func (db *contextCapabilityDatabase) SecurityAgentRunContextAvailable(context.Context) (bool, error) {
	return db.available, db.err
}
func (db *contextCapabilityDatabase) VerifySecurityAgentBudgetRelease(context.Context) error {
	return db.err
}

// The actual production decorator must not erase optional release authority.
func TestTracedDatabasePreservesRunContextAuthority(t *testing.T) {
	for _, tc := range []struct {
		name      string
		next      apiserver.JSONDatabase
		available bool
		wantErr   error
	}{
		{"legacy", boundaryDatabase{}, false, nil},
		{"registered54", &contextCapabilityDatabase{available: true}, true, nil},
		{"corrupt54", &contextCapabilityDatabase{err: apiserver.ErrRepositoryUnavailable}, false, apiserver.ErrRepositoryUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &tracedJSONDatabase{next: tc.next, metrics: newOperationalMetrics(), exporter: &captureSpanExporter{}}
			capability, ok := any(db).(interface {
				SecurityAgentRunContextAvailable(context.Context) (bool, error)
			})
			if !ok {
				t.Fatal("production tracing erased run-context capability")
			}
			available, err := capability.SecurityAgentRunContextAvailable(context.Background())
			if available != tc.available || !errors.Is(err, tc.wantErr) {
				t.Fatalf("available=%v error=%v", available, err)
			}
			verifier, ok := any(db).(interface{ VerifySecurityAgentBudgetRelease(context.Context) error })
			if !ok {
				t.Fatal("production tracing erased compiled-release verifier")
			}
			if err := verifier.VerifySecurityAgentBudgetRelease(context.Background()); !errors.Is(err, tc.wantErr) {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if available, err := capability.SecurityAgentRunContextAvailable(ctx); available || err == nil {
				t.Fatal("canceled capability lookup accepted")
			}
			if err := verifier.VerifySecurityAgentBudgetRelease(ctx); err == nil {
				t.Fatal("canceled release lookup accepted")
			}
		})
	}
}
