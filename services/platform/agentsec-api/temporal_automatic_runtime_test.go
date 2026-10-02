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
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type automaticMountedDatabase struct {
	existingTestCompositionDatabase
	mode          string
	currentWrites int
}

func (d *automaticMountedDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if strings.Contains(q, "to_regnamespace('zasp_temporal77')") {
		return json.RawMessage(fmt.Sprint(d.mode != "absent")), nil
	}
	if strings.Contains(q, "zasp_temporal77.api_ready") {
		if len(args) != 2 || args[0] != migrations.TemporalAutomaticSourcesChecksum() || args[1] != migrations.TemporalAutomaticSourcesFingerprint() {
			return nil, apiserver.ErrRepositoryOperation
		}
		return json.RawMessage(fmt.Sprint(d.mode == "ready")), nil
	}
	return d.existingTestCompositionDatabase.QueryJSON(ctx, q, args...)
}
func (d *automaticMountedDatabase) ReplayTemporalTestDefinition(context.Context, ...any) (json.RawMessage, bool, error) {
	return json.RawMessage(`{"found":false}`), true, nil
}
func (d *automaticMountedDatabase) MutateTemporalTestDefinition(_ context.Context, args ...any) (json.RawMessage, bool, error) {
	d.currentWrites++
	if len(args) != 14 {
		return nil, true, apiserver.ErrRepositoryOperation
	}
	b, err := json.Marshal(map[string]any{"body": args[10], "version": 1, "secret_generation": 0, "audit_id": args[11], "correlation_id": args[12], "receipt_id": args[13], "replayed": false})
	return b, true, err
}

// Actual constructor, tracing decorator, mounted HTTP and repository; only
// SQL/session IO is controlled. Dropping74 routing selects the legacy writer.
func TestAutomaticRulesMountedRollout(t *testing.T) {
	t.Setenv("HOSTNAME", "automatic77-rollout")
	for _, mode := range []string{"absent", "invalid", "ready"} {
		for _, configured := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/configured=%t", mode, configured), func(t *testing.T) {
				cfg := fixtureAuditExportRuntimeConfig(t)
				cfg.AuditExports = nil
				db := &automaticMountedDatabase{mode: mode, existingTestCompositionDatabase: existingTestCompositionDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view", "manage_workflows"}}}}
				deps, err := composeRuntimeDependenciesWithSecurityAgent(cfg, db, db, auditFactoryProvider())
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					for _, c := range deps.Closers {
						_ = c.Close()
					}
				}()
				body := `{"name":"Rollout draft","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"max_ai_cost_nano_credits":1000000,"concurrency_limit":1,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":false,"existing_test":{"definition_id":"pid_89000012-0000-4000-8000-000000000002","definition_version":1}}`
				if configured {
					body = strings.TrimSuffix(body, "}") + `,"trigger_rules":{"version":1,"mode":"manual"}}`
				}
				r := publicPageRuntimeRequest(cfg, "/api/v1/security-agents")
				r.Method = http.MethodPost
				r.Body = io.NopCloser(strings.NewReader(body))
				r.ContentLength = int64(len(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", cfg.PublicOrigin)
				r.Header.Set("X-CSRF-Token", strings.Repeat("c", 32))
				r.Header.Set("Idempotency-Key", "automatic77-mounted-"+mode)
				w := httptest.NewRecorder()
				deps.ProductHandler.ServeHTTP(w, r)
				want := http.StatusCreated
				writes := 1
				if configured && mode != "ready" {
					want = http.StatusServiceUnavailable
					writes = 0
				}
				if w.Code != want || db.currentWrites != writes || db.writes != 0 {
					t.Fatalf("status=%d want=%d current74 writes=%d want=%d legacy55 writes=%d", w.Code, want, db.currentWrites, writes, db.writes)
				}
			})
		}
	}
}
