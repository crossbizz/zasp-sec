package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type existingTestCompositionDatabase struct {
	auditExportRuntimeDatabase
	refused                  bool
	writes, mutationAttempts int
}

func (db *existingTestCompositionDatabase) SecurityAgentExistingTestDefinitionsAvailable(context.Context) (bool, error) {
	if db.refused {
		return false, apiserver.ErrRepositoryUnavailable
	}
	return true, nil
}
func (db *existingTestCompositionDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	if strings.HasPrefix(query, "SELECT public.zasp_production_security_agent_existing_tests_replay_definition(") {
		if db.refused || len(args) != 9 || args[0] != "pid_10000001-0000-4000-8000-000000000001" || args[1] != "pid_10000002-0000-4000-8000-000000000002" || args[2] != "pid_10000003-0000-4000-8000-000000000003" || args[3] != "pid_10000004-0000-4000-8000-000000000004" || args[7] != migrations.ProductionSecurityAgentExistingTests().Checksum() || args[8] != migrations.SecurityAgentExistingTestsFingerprint() {
			return nil, apiserver.ErrRepositoryUnavailable
		}
		return json.RawMessage(`{"found":false}`), nil
	}
	if strings.HasPrefix(query, "SELECT public.zasp_production_security_agent_existing_tests_mutate_definition(") {
		db.mutationAttempts++
		if db.refused || len(args) != 16 || args[2] != "pid_10000001-0000-4000-8000-000000000001" || args[3] != "pid_10000002-0000-4000-8000-000000000002" || args[4] != "pid_10000003-0000-4000-8000-000000000003" || args[5] != "pid_10000004-0000-4000-8000-000000000004" || args[14] != migrations.ProductionSecurityAgentExistingTests().Checksum() || args[15] != migrations.SecurityAgentExistingTestsFingerprint() {
			return nil, apiserver.ErrRepositoryUnavailable
		}
		db.writes++
		return json.Marshal(map[string]any{"body": args[10], "version": 1, "secret_generation": 0, "audit_id": args[11], "correlation_id": args[12], "receipt_id": args[13], "replayed": false})
	}
	return db.auditExportRuntimeDatabase.QueryJSON(ctx, query, args...)
}

// Actual mounting, edge/session middleware, tracing, repository and handler.
// SQL/session rows are controlled boundaries, not real PostgreSQL or live login.
func TestExistingTestDraftMountedProductionComposition(t *testing.T) {
	t.Setenv("HOSTNAME", "existing-test-composition")
	for _, test := range []struct {
		name   string
		status int
	}{
		{"healthy", http.StatusCreated}, {"missing_permission", http.StatusForbidden}, {"wrong_csrf", http.StatusForbidden}, {"wrong_origin", http.StatusBadRequest}, {"foreign_scope", http.StatusConflict}, {"corrupt55", http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := fixtureAuditExportRuntimeConfig(t)
			config.AuditExports = nil
			db := &existingTestCompositionDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view", "manage_workflows"}}}
			deps, err := composeRuntimeDependenciesWithSecurityAgent(config, db, db, auditFactoryProvider())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, closer := range deps.Closers {
					_ = closer.Close()
				}
			}()
			body := `{"name":"Mounted pinned draft","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"max_ai_cost_nano_credits":1000000,"concurrency_limit":1,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":false,"existing_test":{"definition_id":"pid_89000012-0000-4000-8000-000000000002","definition_version":1}}`
			request := publicPageRuntimeRequest(config, "/api/v1/security-agents")
			request.Method = http.MethodPost
			request.Body = io.NopCloser(strings.NewReader(body))
			request.ContentLength = int64(len(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", config.PublicOrigin)
			request.Header.Set("X-CSRF-Token", strings.Repeat("c", 32))
			request.Header.Set("Idempotency-Key", "existing-test-mounted-0001")
			switch test.name {
			case "missing_permission":
				db.permissions = []string{"view"}
			case "wrong_csrf":
				request.Header.Set("X-CSRF-Token", "wrong")
			case "wrong_origin":
				request.Header.Set("Origin", "https://foreign.invalid")
			case "foreign_scope":
				request.Header.Set("X-Zasp-Expected-Scope", "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_89000071-0000-4000-8000-000000000001")
			case "corrupt55":
				db.refused = true
			}
			response := httptest.NewRecorder()
			deps.ProductHandler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("mounted status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
			wantWrites := 0
			if test.name == "healthy" {
				wantWrites = 1
				var result struct {
					ExistingTest struct {
						DefinitionID string `json:"definition_id"`
						Version      int    `json:"definition_version"`
					} `json:"existing_test"`
					Enabled bool `json:"enabled"`
				}
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.ExistingTest.DefinitionID != "pid_89000012-0000-4000-8000-000000000002" || result.ExistingTest.Version != 1 || result.Enabled {
					t.Fatalf("mounted draft intent changed: %s", response.Body.String())
				}
			}
			if db.writes != wantWrites || db.mutationAttempts != wantWrites {
				t.Fatalf("mounted mutation count=%d attempts=%d want=%d", db.writes, db.mutationAttempts, wantWrites)
			}
		})
	}
}

// Catalogs must traverse the same dedicated database authority as mutations.
// A generic-repository fallback silently hides the two supported templates.
func TestExistingTestCatalogMountedProductionComposition(t *testing.T) {
	t.Setenv("HOSTNAME", "existing-test-catalog-composition")
	config := fixtureAuditExportRuntimeConfig(t)
	config.AuditExports = nil
	generic := &auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view", "manage_workflows"}}
	security := &existingTestCompositionDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`)}}
	deps, err := composeRuntimeDependenciesWithSecurityAgent(config, generic, security, auditFactoryProvider())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, closer := range deps.Closers {
			_ = closer.Close()
		}
	}()
	for _, refused := range []bool{false, true, false} {
		security.refused = refused
		for _, route := range []string{"/api/v1/security-agent-templates", "/api/v1/security-actions"} {
			response := httptest.NewRecorder()
			deps.ProductHandler.ServeHTTP(response, publicPageRuntimeRequest(config, route))
			if refused {
				if response.Code != http.StatusServiceUnavailable {
					t.Fatalf("%s corrupt55 status=%d", route, response.Code)
				}
				continue
			}
			if response.Code != 200 {
				t.Fatalf("%s status=%d %s", route, response.Code, response.Body.String())
			}
			for _, action := range []string{`"run_test"`, `"rerun_test"`} {
				if !strings.Contains(response.Body.String(), action) {
					t.Fatalf("%s missing %s: %s", route, action, response.Body.String())
				}
			}
			if strings.Contains(response.Body.String(), `"start_attack_lab"`) {
				t.Fatal("unrelated unsupported action published")
			}
		}
	}
	if security.writes != 0 || security.mutationAttempts != 0 {
		t.Fatal("catalog read attempted mutation")
	}
}
