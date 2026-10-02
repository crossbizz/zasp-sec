package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

const auditExportRuntimeGateSQL = `SELECT to_jsonb(zasp_audit_export_api_readiness($1,$2))`

type auditExportRuntimeDatabase struct {
	boundaryDatabase
	gate        json.RawMessage
	queries     []string
	afterExport context.CancelFunc
	sawExport   bool
	permissions []string
}

func (db *auditExportRuntimeDatabase) SchemaVersion(context.Context) (string, error) {
	return apiserver.ProductionRecoverySchemaVersion, nil
}
func (db *auditExportRuntimeDatabase) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	db.queries = append(db.queries, query)
	if query == `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)` {
		return json.RawMessage(`false`), nil
	}
	if query == auditExportRuntimeGateSQL {
		db.sawExport = true
		return db.gate, nil
	}
	if db.sawExport && db.afterExport != nil {
		db.afterExport()
	}
	if strings.Contains(query, "FROM zasp_product_sessions session JOIN zasp_identity_memberships") {
		permissions := db.permissions
		if permissions == nil {
			permissions = []string{"view_audit"}
		}
		return json.Marshal(map[string]any{"principal_id": "pid_10000004-0000-4000-8000-000000000004", "organization_id": "pid_10000001-0000-4000-8000-000000000001", "workspace_id": "pid_10000002-0000-4000-8000-000000000002", "environment_id": "pid_10000003-0000-4000-8000-000000000003", "permissions": permissions, "csrf_token": strings.Repeat("c", 32), "fresh_authenticated": true})
	}
	if strings.HasPrefix(query, "SELECT jsonb_build_object('correlation_id',$5::text,'principal'") {
		return json.Marshal(map[string]any{"correlation_id": args[4], "principal": map[string]any{"id": args[0], "organization_id": args[1], "organization_reference": "organization-live", "member_reference": "member-live", "role": "read_only_viewer", "active": true}})
	}
	if strings.HasPrefix(query, "SELECT jsonb_build_object('release',") {
		return json.RawMessage(`{"release":true,"principal":true}`), nil
	}
	if strings.Contains(query, "readiness(") || strings.Contains(query, "_ready(") {
		return json.RawMessage(`true`), nil
	}
	return nil, errors.New("unconfigured owned database boundary")
}

func TestAuditExportRuntimeBootstrapUsesMountedEffectivePermission(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-export-bootstrap-test")
	for _, installed := range []bool{false, true} {
		for _, permitted := range []bool{false, true} {
			config := fixtureAuditExportRuntimeConfig(t)
			if !installed {
				config.AuditExports = nil
			}
			db := &auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view"}}
			if permitted {
				db.permissions = append(db.permissions, "view_audit")
			}
			deps, err := composeRuntimeDependenciesWithSecurityAgent(config, db, db, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
				return apiserver.SessionGrant{}, errors.New("unused callback")
			}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				for _, closer := range deps.Closers {
					_ = closer.Close()
				}
			})
			response := httptest.NewRecorder()
			deps.ProductHandler.ServeHTTP(response, publicPageRuntimeRequest(config, "/api/v1/session/bootstrap"))
			var bootstrap struct {
				Capabilities []string `json:"capabilities"`
			}
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &bootstrap) != nil {
				t.Fatalf("runtime bootstrap %d %s", response.Code, response.Body.String())
			}
			if slices.Contains(bootstrap.Capabilities, "audit.exports") != (installed && permitted) || slices.Contains(bootstrap.Capabilities, "audit.read") != permitted {
				t.Fatalf("installed=%t permitted=%t capabilities=%v", installed, permitted, bootstrap.Capabilities)
			}
		}
	}
}

func TestAuditExportRuntimeCompositionLateCancellation(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-export-runtime-test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := &auditExportRuntimeDatabase{gate: json.RawMessage(`true`), afterExport: cancel}
	deps, err := composeRuntimeDependenciesWithContext(ctx, fixtureAuditExportRuntimeConfig(t), db, db, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
		return apiserver.SessionGrant{}, errors.New("no exchange")
	}))
	defer func() {
		for _, closer := range deps.Closers {
			_ = closer.Close()
		}
	}()
	if !db.sawExport || ctx.Err() == nil {
		t.Fatal("fixture did not reach post-export cancellation")
	}
	if err != errRuntimeUnavailable || deps.ProductHandler != nil || len(deps.Closers) != 0 {
		t.Fatal("canceled factory transferred resource ownership")
	}
}

func TestAuditExportRuntimeCompositionMountReadinessAndCleanup(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-export-runtime-test")
	config := fixtureAuditExportRuntimeConfig(t)
	db := &auditExportRuntimeDatabase{gate: json.RawMessage(`true`)}
	deps, err := composeRuntimeDependenciesWithSecurityAgent(config, db, db, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
		return apiserver.SessionGrant{}, errors.New("no exchange")
	}))
	if err != nil {
		t.Fatal("configured runtime unavailable", err)
	}
	defer func() {
		for _, closer := range deps.Closers {
			_ = closer.Close()
		}
	}()
	request := httptest.NewRequest(http.MethodGet, config.PublicOrigin+"/api/v1/audit-exports/pid_52000001-0000-4000-8000-000000000001", nil)
	storeFound := false
	for _, store := range deps.Stores {
		if store.Name == "aws-s3-audit-exports" && store.Durable {
			storeFound = true
		}
	}
	if !storeFound {
		t.Fatal("configured runtime omitted export storage dependency")
	}
	request.RemoteAddr = "10.20.0.10:443"
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	request.Header.Set("X-Forwarded-Host", request.Host)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Port", "443")
	request.Header.Set("X-Zasp-Expected-Scope", "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003")
	request.AddCookie(&http.Cookie{Name: "__Host-zasp_session", Value: "owned-runtime-session"})
	response := httptest.NewRecorder()
	deps.ProductHandler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("mounted route did not reach refused database boundary: %d", response.Code)
	}
	if !strings.Contains(deps.Metrics.Prometheus(), `route="/api/v1/audit-exports/:resource"`) {
		t.Fatal("actual runtime export request was not classified")
	}
	found := false
	for _, query := range db.queries {
		if strings.HasPrefix(query, "SELECT zasp_audit_export_get(") {
			found = true
		}
	}
	if !found {
		t.Fatal("configured runtime did not select export route/repository")
	}
	db.queries = nil
	db.gate = json.RawMessage(`false`)
	if deps.ReadinessCheck(context.Background()) == nil || len(db.queries) != 1 || db.queries[0] != auditExportRuntimeGateSQL {
		t.Fatal("warmed runtime skipped export readiness")
	}
	var transports []*http.Transport
	for _, closer := range deps.Closers {
		if value, ok := closer.(transportCloser); ok {
			transports = append(transports, value.transport)
		}
	}
	// Secrets, connector HTTP, exports, and reference AWS are independently owned.
	if len(transports) != 4 {
		t.Fatal("export transport not owned by runtime", len(transports))
	}
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()
	client := &http.Client{Transport: transports[2], Timeout: time.Second}
	read, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, read.Body)
	_ = read.Body.Close()
	for _, closer := range deps.Closers {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime cleanup left export connection open")
	}
}

func TestAuditExportRuntimeCompositionRequiresExportAuthority(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-export-runtime-test")
	config := fixtureAuditExportRuntimeConfig(t)
	for _, gate := range []string{`false`, `null`, `{"ready":true}`} {
		db := &auditExportRuntimeDatabase{gate: json.RawMessage(gate)}
		dependencies, err := composeRuntimeDependenciesWithSecurityAgent(config, db, db, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
			return apiserver.SessionGrant{}, errors.New("no identity exchange during construction")
		}))
		if err == nil {
			for _, closer := range dependencies.Closers {
				_ = closer.Close()
			}
			t.Fatal("configured export silently bypassed capability refusal")
		}
		found := false
		for _, query := range db.queries {
			if query == auditExportRuntimeGateSQL {
				found = true
			}
		}
		if !found {
			t.Fatal("construction failed before reaching the export gate", db.queries)
		}
	}
}

func TestAuditExportRuntimeAbsentConfigurationDoesNotClaimStorage(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-export-runtime-test")
	config := fixtureAuditExportRuntimeConfig(t)
	config.AuditExports = nil
	db := &auditExportRuntimeDatabase{gate: json.RawMessage(`false`)}
	deps, err := composeRuntimeDependenciesWithSecurityAgent(config, db, db, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
		return apiserver.SessionGrant{}, errors.New("no exchange")
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, closer := range deps.Closers {
			_ = closer.Close()
		}
	}()
	for _, store := range deps.Stores {
		if store.Name == "aws-s3-audit-exports" {
			t.Fatal("disabled exports claimed storage")
		}
	}
	for _, query := range db.queries {
		if query == auditExportRuntimeGateSQL {
			t.Fatal("disabled exports requested schema52 authority")
		}
	}
}
