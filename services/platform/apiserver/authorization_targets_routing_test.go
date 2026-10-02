package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type authorizationRoutingRow func(...any) error

func (row authorizationRoutingRow) Scan(values ...any) error { return row(values...) }

type authorizationRoutingDriver struct {
	t       *testing.T
	rows    map[string][]authorizationRoutingRecord
	err     map[string]error
	queries []string
}

type authorizationRoutingRecord struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	Version      int64  `json:"version"`
	SourceID     string `json:"source_id,omitempty"`
}

func (driver *authorizationRoutingDriver) QueryRow(_ context.Context, query string, arguments ...any) PostgresRow {
	driver.t.Helper()
	if query != postgresAuthorizationResolveSQL || len(arguments) != 6 {
		driver.t.Fatalf("unexpected authorization query: query=%q arguments=%d", query, len(arguments))
	}
	kind, ok := arguments[3].(string)
	if !ok {
		driver.t.Fatal("authorization kind was not a string")
	}
	driver.queries = append(driver.queries, kind)
	return authorizationRoutingRow(func(values ...any) error {
		if len(values) != 1 {
			return errors.New("unexpected scan destination")
		}
		if err := driver.err[kind]; err != nil {
			return err
		}
		rows := driver.rows[kind]
		if rows == nil {
			rows = []authorizationRoutingRecord{}
		}
		payload, err := json.Marshal(rows)
		if err != nil {
			return err
		}
		destination, ok := values[0].(*[]byte)
		if !ok {
			return errors.New("unexpected scan type")
		}
		*destination = payload
		return nil
	})
}

func (*authorizationRoutingDriver) Exec(context.Context, string, ...any) error { return nil }
func (*authorizationRoutingDriver) Close() error                               { return nil }

func authorizationRoutingDatabase(t *testing.T, rows map[string][]authorizationRoutingRecord) (*PostgresJSONDatabase, *authorizationRoutingDriver) {
	t.Helper()
	driver := &authorizationRoutingDriver{t: t, rows: rows, err: map[string]error{}}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	return database, driver
}

func authorizationRoutingRecordFor(identity RequestIdentity, kind, id string, version int64) authorizationRoutingRecord {
	return authorizationRoutingRecord{
		Organization: identity.Scope.OrganizationID().String(),
		Workspace:    identity.Scope.WorkspaceID().String(),
		Environment:  identity.Scope.EnvironmentID().String(),
		Kind:         kind,
		ID:           id,
		Version:      version,
		SourceID:     id,
	}
}

func TestP7AuthorizationResolverRoutesClosedSecurityAgentKinds(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	findingID := "pid_91000001-0000-4000-8000-000000000001"
	runID := "pid_91000002-0000-4000-8000-000000000002"
	auditID := "pid_91000003-0000-4000-8000-000000000003"
	mainDatabase, main := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{
		"finding": {authorizationRoutingRecordFor(identity, "finding", findingID, 4)},
	})
	securityDatabase, security := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{
		"security_agent":          {authorizationRoutingRecordFor(identity, "security_agent", runID, 7)},
		"security_agent_approval": {authorizationRoutingRecordFor(identity, "security_agent_approval", runID, 7)},
		"security_agent_run":      {authorizationRoutingRecordFor(identity, "security_agent_run", runID, 7)},
		"security_agent_audit":    {authorizationRoutingRecordFor(identity, "security_agent_run", runID, 7)},
	})
	resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, securityDatabase)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, operation, parameter, wantKind string
		wantMain, wantSecurity               int
	}{
		{"main finding", "getFinding", findingID, "finding", 1, 0},
		{"security run", "getSingleTestCleanupRecovery", runID, "security_agent_run", 0, 1},
		{"security definition", "getSecurityAgent", runID, "security_agent", 0, 1},
		{"security approval", "getSecurityAgentApproval", runID, "security_agent_approval", 0, 1},
		{"security audit parent", "getSecurityAgentAuditEvent", auditID, "security_agent_run", 0, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			main.queries = nil
			security.queries = nil
			parameters := map[string]string{"id": test.parameter}
			targets, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: test.operation, PathParameters: parameters})
			if err != nil || len(targets.Targets) != 1 || targets.Targets[0].Kind != test.wantKind {
				t.Fatalf("targets=%+v error=%v", targets, err)
			}
			if len(main.queries) != test.wantMain || len(security.queries) != test.wantSecurity {
				t.Fatalf("main queries=%v security queries=%v", main.queries, security.queries)
			}
		})
	}
}

func TestP7AuthorizationResolverMergesParentAndWildcardAuthorities(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	findingID := "pid_92000001-0000-4000-8000-000000000001"
	runID := "pid_92000002-0000-4000-8000-000000000002"
	receiptID := "pid_92000003-0000-4000-8000-000000000003"
	finding := authorizationRoutingRecordFor(identity, "finding", findingID, 2)
	run := authorizationRoutingRecordFor(identity, "security_agent_run", runID, 3)
	mainDatabase, main := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{
		"*":                {finding},
		"workflow_receipt": nil,
		"audit_event":      {finding},
	})
	securityDatabase, security := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{
		"*":                {finding, run},
		"workflow_receipt": {run},
		"audit_event":      {run},
	})
	resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, securityDatabase)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, operation string
		parameters      map[string]string
		want            []string
	}{
		{"wildcard", "getHomeSummary", nil, []string{"finding", "security_agent_run"}},
		{"workflow parent", "acknowledgeWorkflowMutationReceipt", map[string]string{"id": receiptID}, []string{"security_agent_run"}},
		{"organization audit collection", "listAuditEvents", nil, []string{"finding", "security_agent_run"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			main.queries = nil
			security.queries = nil
			targets, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: test.operation, PathParameters: test.parameters})
			if err != nil || !targets.Complete || targets.Collection != (test.operation != "acknowledgeWorkflowMutationReceipt") || len(targets.Targets) != len(test.want) {
				t.Fatalf("targets=%+v error=%v", targets, err)
			}
			for index, kind := range test.want {
				if targets.Targets[index].Kind != kind {
					t.Fatalf("target %d kind=%q want=%q", index, targets.Targets[index].Kind, kind)
				}
			}
			if len(main.queries) != 1 || len(security.queries) != 1 {
				t.Fatalf("main queries=%v security queries=%v", main.queries, security.queries)
			}
		})
	}
}

func TestP7AuthorizationResolverDualAuthorityFailsClosed(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	findingID := "pid_93000001-0000-4000-8000-000000000001"
	finding := authorizationRoutingRecordFor(identity, "finding", findingID, 2)
	mainDatabase, main := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"*": {finding}})
	securityDatabase, security := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"*": {finding}})
	resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, securityDatabase)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("conflicting duplicate", func(t *testing.T) {
		conflict := finding
		conflict.Version++
		security.rows["*"] = []authorizationRoutingRecord{conflict}
		if _, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "getHomeSummary"}); !errors.Is(err, authorization.ErrUnavailable) {
			t.Fatalf("conflicting duplicate error=%v", err)
		}
	})
	t.Run("secondary error", func(t *testing.T) {
		security.rows["*"] = []authorizationRoutingRecord{finding}
		security.err["*"] = errors.New("secondary unavailable")
		if _, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "getHomeSummary"}); err == nil {
			t.Fatalf("secondary error=%v", err)
		}
		delete(security.err, "*")
	})
	t.Run("merged bound", func(t *testing.T) {
		main.rows["*"] = make([]authorizationRoutingRecord, 5001)
		security.rows["*"] = make([]authorizationRoutingRecord, 5000)
		for index := range main.rows["*"] {
			main.rows["*"][index] = authorizationRoutingRecordFor(identity, "finding", fmt.Sprintf("pid_94%06x-0000-4000-8000-%012d", index, index), 1)
		}
		for index := range security.rows["*"] {
			security.rows["*"][index] = authorizationRoutingRecordFor(identity, "security_agent_run", fmt.Sprintf("pid_95%06x-0000-4000-8000-%012d", index, index), 1)
		}
		if _, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "getHomeSummary"}); !errors.Is(err, authorization.ErrUnavailable) {
			t.Fatalf("merged bound error=%v", err)
		}
	})
	t.Run("missing secondary", func(t *testing.T) {
		if _, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, nil); !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatalf("missing secondary error=%v", err)
		}
	})
}

func TestP7AuthorizationResolverIsolationAndConflicts(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	base := authorizationRoutingRecordFor(identity, "finding", "pid_93000001-0000-4000-8000-000000000001", 2)
	for _, field := range []string{"organization", "workspace", "environment", "source", "version"} {
		t.Run(field, func(t *testing.T) {
			other := base
			switch field {
			case "organization":
				other.Organization = "pid_99000001-0000-4000-8000-000000000001"
			case "workspace":
				other.Workspace = "pid_99000002-0000-4000-8000-000000000002"
			case "environment":
				other.Environment = "pid_99000003-0000-4000-8000-000000000003"
			case "source":
				other.SourceID = "different-source"
			case "version":
				other.Version++
			}
			main, _ := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"*": {base}})
			secondary, _ := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"*": {other}})
			resolver, _ := NewPostgresAuthorizationResolverWithSecurityAgent(main, secondary)
			got, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "globalSearch"})
			if err == nil || len(got.Targets) != 0 || got.Complete {
				t.Fatal("conflicting/foreign target produced a partial grant", got, err)
			}
		})
	}
	main, mainDriver := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"finding": {base}})
	secondary, securityDriver := authorizationRoutingDatabase(t, nil)
	resolver, _ := NewPostgresAuthorizationResolverWithSecurityAgent(main, secondary)
	if _, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "unknown-operation"}); err == nil || len(mainDriver.queries)+len(securityDriver.queries) != 0 {
		t.Fatal("unknown operation queried a database")
	}
	if err := secondary.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "getSecurityAgentRun", PathParameters: map[string]string{"id": base.ID}}); err == nil || got.Complete || len(mainDriver.queries) != 0 {
		t.Fatal("closed security authority fell back to main")
	}
	legacy, _ := NewPostgresAuthorizationResolver(main)
	if got, err := legacy.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": base.ID}}); err != nil || len(got.Targets) != 1 {
		t.Fatal("single-database resolver changed", err)
	}
}
