package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

func TestP7ProductionCompositionRejectsMissingEnforcement(t *testing.T) {
	t.Setenv("HOSTNAME", "authorization-runtime-test")
	env := complianceAPIEnvironment()
	c, err := loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	c.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-test", TaskQueue: "agent-test", DiscoveryTaskQueue: "discovery-test", FGAURL: "http://127.0.0.1:8088", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/tmp/authorization-fixture-token", Timeout: time.Second}
	if !validRuntimeConfig(c) {
		t.Fatal("invalid fixture config")
	}
	db := &complianceRuntimeDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view", "manage_workflows", "view_audit", "view_compliance"}}}
	agent := &agentExportRuntimeDatabase{complianceRuntimeDatabase: *db, available: true}
	d, err := composeRuntimeDependenciesWithReadinessTransport(context.Background(), c, db, agent, auditFactoryProvider(), newAuditExportStorageClients, newComplianceStorageResources, io.Discard, nil)
	defer func() {
		for _, closer := range d.Closers {
			_ = closer.Close()
		}
	}()
	if err == nil || d.ProductHandler != nil {
		t.Fatal("enabled production composition accepted missing current database and authorizer")
	}
}

type p7CurrentRuntimeDatabase struct{ apiserver.JSONDatabase }

func (*p7CurrentRuntimeDatabase) CurrentAuthorizationRequired() bool { return true }
// This router/authorization fixture has no installed cleanup-recovery profile.
// Report that absence explicitly rather than omitting the required capability.
func (*p7CurrentRuntimeDatabase) SingleTestRecoveryAvailable(context.Context) (bool, error) {
	return false, nil
}
func (d *p7CurrentRuntimeDatabase) SecurityAgentExportsAvailable(ctx context.Context) (bool, error) {
	if source, ok := d.JSONDatabase.(interface {
		SecurityAgentExportsAvailable(context.Context) (bool, error)
	}); ok {
		return source.SecurityAgentExportsAvailable(ctx)
	}
	return false, nil
}
func (*p7CurrentRuntimeDatabase) CurrentAuthorizationSourceReady(context.Context, int, string, string) (bool, error) {
	return true, nil
}
func (d *p7CurrentRuntimeDatabase) QueryJSON(ctx context.Context, q string, a ...any) (json.RawMessage, error) {
	if strings.HasPrefix(q, "SELECT jsonb_build_object('credential_id',s.session_id") {
		return json.Marshal(map[string]any{"credential_id": "owned-session", "principal_id": "pid_10000004-0000-4000-8000-000000000004", "organization_id": "pid_10000001-0000-4000-8000-000000000001", "workspace_id": "pid_10000002-0000-4000-8000-000000000002", "environment_id": "pid_10000003-0000-4000-8000-000000000003", "permissions": []string{}, "csrf_token": strings.Repeat("c", 32), "fresh_authenticated": true})
	}
	return d.JSONDatabase.QueryJSON(ctx, q, a...)
}

type p7RuntimeDeny struct {
	err        error
	operations []string
}

func (a *p7RuntimeDeny) Authorize(_ context.Context, i apiserver.RequestIdentity, c apiserver.CredentialBinding, r apiserver.RoutedOperation) (apiserver.RequestAuthorization, error) {
	if c.ID != "owned-session" || c.Digest == ([32]byte{}) || len(i.Permissions) != 0 {
		return apiserver.RequestAuthorization{}, authorization.ErrInvalid
	}
	a.operations = append(a.operations, r.OperationID)
	return apiserver.RequestAuthorization{}, a.err
}

func TestP7ProductionCompositionInjectsEveryRouter(t *testing.T) {
	t.Setenv("HOSTNAME", "authorization-runtime-test")
	env := complianceAPIEnvironment()
	c, err := loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	c.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-test", TaskQueue: "agent-test", DiscoveryTaskQueue: "discovery-test", FGAURL: "http://127.0.0.1:8088", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/tmp/authorization-fixture-token", Timeout: time.Second}
	base := &complianceRuntimeDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`)}}
	agentBase := &agentExportRuntimeDatabase{complianceRuntimeDatabase: *base, available: true}
	db := &p7CurrentRuntimeDatabase{base}
	agent := &p7CurrentRuntimeDatabase{agentBase}
	a := &p7RuntimeDeny{err: apiserver.ErrAuthorizationDenied}
	d, err := composeRuntimeDependenciesWithReadinessTransport(context.Background(), c, db, agent, auditFactoryProvider(), newAuditExportStorageClients, newComplianceStorageResources, io.Discard, nil, a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, closer := range d.Closers {
			_ = closer.Close()
		}
	}()
	for _, tc := range []struct{ path, operation string }{
		{"/api/v1/sensors", "listSensors"},
		{"/api/v1/compliance/evidence", "listComplianceEvidence"},
		{"/api/v1/audit-exports/pid_20000001-0000-4000-8000-000000000001", "getAuditExport"},
		{"/api/v1/security-agent-runs/pid_20000002-0000-4000-8000-000000000002/steps/pid_20000003-0000-4000-8000-000000000003/export", "getSecurityAgentExport"},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			for _, failure := range []struct {
				err    error
				status int
			}{{apiserver.ErrAuthorizationDenied, 403}, {authorization.ErrUnavailable, 503}, {authorization.ErrConflict, 409}} {
				a.err = failure.err
				before := len(a.operations)
				w := httptest.NewRecorder()
				d.ProductHandler.ServeHTTP(w, publicPageRuntimeRequest(c, tc.path))
				if w.Code != failure.status || len(a.operations) != before+1 || a.operations[len(a.operations)-1] != tc.operation {
					t.Fatalf("authorizer bypassed status=%d operations=%v body=%s", w.Code, a.operations, w.Body.String())
				}
			}
		})
	}
}
