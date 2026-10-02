package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type exportWorkflowRuntimeDatabase struct {
	*agentExportRuntimeDatabase
	definitions   bool
	definitionErr error
}

func (d *exportWorkflowRuntimeDatabase) SecurityAgentExportDefinitionsAvailable(context.Context) (bool, error) {
	return d.definitions, d.definitionErr
}

func TestExportWorkflowConfigurationIsClosed(t *testing.T) {
	for _, value := range []string{"true", "false", "1", " enabled ", "http://untrusted.invalid/readyz"} {
		env := complianceAPIEnvironment()
		env["ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW"] = value
		if _, err := loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err == nil {
			t.Fatalf("ambiguous workflow gate %q accepted", value)
		}
	}
}

// Exercise production composition and its public action response. Only SQL and
// worker service placement are controlled; no helper constructs the catalog.
func TestExportWorkflowProductionCatalogRequiresWorkersAndAdmission(t *testing.T) {
	t.Setenv("HOSTNAME", "export-workflow-runtime-test")
	for _, mode := range []string{"ready", "disabled", "admission absent", "admission drift", "worker unavailable", "missing storage"} {
		t.Run(mode, func(t *testing.T) {
			env := complianceAPIEnvironment()
			if mode != "disabled" {
				env["ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW"] = "enabled"
			}
			config, err := loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing storage" {
				config.ComplianceExports = nil
			}
			ordinary := &complianceRuntimeDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view", "manage_workflows", "view_audit", "view_compliance"}}}
			agent := &exportWorkflowRuntimeDatabase{agentExportRuntimeDatabase: &agentExportRuntimeDatabase{complianceRuntimeDatabase: *ordinary, available: true}, definitions: mode != "admission absent"}
			if mode == "admission drift" {
				agent.definitionErr = errors.New("installed workflow drift")
			}
			var unavailable atomic.Bool
			unavailable.Store(mode == "worker unavailable")
			var mu sync.Mutex
			seen := map[string]int{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen[r.Host]++
				mu.Unlock()
				if r.Method != http.MethodGet || r.URL.Path != "/readyz" || r.URL.RawQuery != "" {
					t.Errorf("invalid worker probe: %s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if unavailable.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				_, _ = w.Write([]byte("{\"status\":\"ready\"}\n"))
			}))
			defer server.Close()
			transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}}
			defer transport.CloseIdleConnections()
			deps, err := composeRuntimeDependenciesWithReadinessTransport(context.Background(), config, ordinary, agent, auditFactoryProvider(), newAuditExportStorageClients, newComplianceStorageResources, &complianceTelemetryCapture{}, transport)
			defer func() {
				for _, closer := range deps.Closers {
					_ = closer.Close()
				}
			}()
			if mode == "missing storage" {
				if err == nil || deps.ProductHandler != nil {
					t.Fatal("enabled export workflow accepted without retrieval storage")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			catalog := func() *httptest.ResponseRecorder {
				response := httptest.NewRecorder()
				deps.ProductHandler.ServeHTTP(response, publicPageRuntimeRequest(config, "/api/v1/security-actions"))
				return response
			}
			response := catalog()
			if mode == "admission drift" {
				if response.Code != http.StatusServiceUnavailable {
					t.Fatalf("drift response=%d", response.Code)
				}
				return
			}
			if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"key":"create_evidence_export"`) != (mode == "ready") {
				t.Fatalf("catalog=%d %s", response.Code, response.Body.String())
			}
			mu.Lock()
			if mode == "ready" {
				for _, host := range []string{"agentsec-security-agent:8081", "agentsec-security-agent-action:8081", "zasp-compliance-export-worker:8081", "zasp-compliance-cleanup-worker:8081"} {
					if seen[host] != 1 {
						t.Errorf("missing exact service %s: %v", host, seen)
					}
				}
				if len(seen) != 4 {
					t.Errorf("unexpected service destinations: %v", seen)
				}
			} else if (mode == "disabled" || mode == "admission absent") && len(seen) != 0 {
				t.Errorf("unavailable workflow probed workers: %v", seen)
			}
			mu.Unlock()
			if mode == "ready" {
				unavailable.Store(true)
				if next := catalog(); next.Code != http.StatusOK || strings.Contains(next.Body.String(), `"key":"create_evidence_export"`) {
					t.Fatalf("stale positive catalog: %d %s", next.Code, next.Body.String())
				}
			}
		})
	}
}
