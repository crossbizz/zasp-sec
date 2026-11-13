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

// A proof names only the targets that the database executing its fenced
// statement resolved. The product database serves the mixed and stored-parent
// collections, so their candidates come from it alone, even where the Security
// Agent database could add Temporal-owned runs: the fence re-reads every
// target on the executing session and would refuse a run it cannot see.
func TestAuthorizationResolverNamesOnlyTargetsOfTheExecutingDatabase(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	findingID := "pid_92000001-0000-4000-8000-000000000001"
	runID := "pid_92000002-0000-4000-8000-000000000002"
	approvalID := "pid_92000004-0000-4000-8000-000000000004"
	receiptID := "pid_92000003-0000-4000-8000-000000000003"
	finding := authorizationRoutingRecordFor(identity, "finding", findingID, 2)
	run := authorizationRoutingRecordFor(identity, "security_agent_run", runID, 3)
	approval := authorizationRoutingRecordFor(identity, "security_agent_approval", approvalID, 5)
	environment := authorizationRoutingRecordFor(identity, "environment", identity.Scope.EnvironmentID().String(), 1)
	mainDatabase, main := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{
		"*":                {finding},
		"workflow_receipt": {finding},
		"audit_event":      {finding},
		"environment":      {environment},
	})
	securityDatabase, security := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{
		"*":                       {finding, run},
		"workflow_receipt":        {run},
		"audit_event":             {run},
		"security_agent_run":      {run},
		"security_agent_approval": {approval},
		"environment":             {environment},
	})
	resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, securityDatabase)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, operation string
		parameters      map[string]string
		collection      bool
	}{
		{"home", "getHomeSummary", nil, true},
		{"search", "globalSearch", nil, true},
		{"receipt parent", "acknowledgeWorkflowMutationReceipt", map[string]string{"id": receiptID}, false},
		{"receipts", "listWorkflowMutationReceipts", nil, true},
		{"audit collection", "listAuditEvents", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			main.queries, security.queries = nil, nil
			targets, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: test.operation, PathParameters: test.parameters})
			if err != nil || !targets.Complete || targets.Collection != test.collection || len(targets.Targets) != 1 || targets.Targets[0].Kind != "finding" || targets.Targets[0].ID != findingID {
				t.Fatalf("targets=%+v error=%v", targets, err)
			}
			if len(main.queries) != 1 || len(security.queries) != 0 {
				t.Fatalf("main queries=%v security queries=%v", main.queries, security.queries)
			}
		})
	}

	// The Security Agent counts of the home summary are a statement of the
	// Security Agent database with a proof of its own: its runs and approvals,
	// resolved there, and nothing from the product database.
	t.Run("security agent home", func(t *testing.T) {
		main.queries, security.queries = nil, nil
		targets, err := resolver.ResolveAuthorization(withSecurityAgentAuthorization(context.Background()), identity, RoutedOperation{OperationID: "getHomeSummary"})
		if err != nil || !targets.Complete || !targets.Collection || len(targets.Targets) != 2 || targets.Targets[0].ID != runID || targets.Targets[1].ID != approvalID {
			t.Fatalf("targets=%+v error=%v", targets, err)
		}
		if len(main.queries) != 0 || len(security.queries) != 2 || security.queries[0] != "security_agent_run" || security.queries[1] != "security_agent_approval" {
			t.Fatalf("main queries=%v security queries=%v", main.queries, security.queries)
		}
	})
	// The Environment whose view decision that proof also carries is read on
	// the same database.
	t.Run("security agent environment", func(t *testing.T) {
		main.queries, security.queries = nil, nil
		targets, err := resolver.ResolveAuthorization(withSecurityAgentAuthorization(context.Background()), identity, RoutedOperation{OperationID: "getEnvironment", PathParameters: map[string]string{"id": identity.Scope.EnvironmentID().String()}})
		if err != nil || len(targets.Targets) != 1 || targets.Targets[0].Kind != "environment" || len(main.queries) != 0 || len(security.queries) != 1 {
			t.Fatalf("targets=%+v error=%v main=%v security=%v", targets, err, main.queries, security.queries)
		}
	})
}

func TestAuthorizationResolverSecurityAgentStatementFailsClosed(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	run := authorizationRoutingRecordFor(identity, "security_agent_run", "pid_93000002-0000-4000-8000-000000000002", 2)
	mainDatabase, main := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"*": {authorizationRoutingRecordFor(identity, "finding", "pid_93000001-0000-4000-8000-000000000001", 2)}})
	securityDatabase, security := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"security_agent_run": {run}})
	resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, securityDatabase)
	if err != nil {
		t.Fatal(err)
	}
	selected := withSecurityAgentAuthorization(context.Background())

	t.Run("either kind unavailable", func(t *testing.T) {
		for _, kind := range []string{"security_agent_run", "security_agent_approval"} {
			security.err[kind] = errors.New("candidate source unavailable")
			if got, err := resolver.ResolveAuthorization(selected, identity, RoutedOperation{OperationID: "getHomeSummary"}); err == nil || got.Complete || len(got.Targets) != 0 {
				t.Fatalf("%s failure admitted a partial candidate set: %+v %v", kind, got, err)
			}
			delete(security.err, kind)
		}
	})
	t.Run("a security agent failure does not fail the product statement", func(t *testing.T) {
		security.err["security_agent_run"] = errors.New("candidate source unavailable")
		got, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "getHomeSummary"})
		if err != nil || len(got.Targets) != 1 || got.Targets[0].Kind != "finding" {
			t.Fatalf("product candidates=%+v error=%v", got, err)
		}
		delete(security.err, "security_agent_run")
	})
	t.Run("bound", func(t *testing.T) {
		security.rows["security_agent_run"] = make([]authorizationRoutingRecord, 5001)
		security.rows["security_agent_approval"] = make([]authorizationRoutingRecord, 5000)
		for index := range security.rows["security_agent_run"] {
			security.rows["security_agent_run"][index] = authorizationRoutingRecordFor(identity, "security_agent_run", fmt.Sprintf("pid_94%06x-0000-4000-8000-%012d", index, index), 1)
		}
		for index := range security.rows["security_agent_approval"] {
			security.rows["security_agent_approval"][index] = authorizationRoutingRecordFor(identity, "security_agent_approval", fmt.Sprintf("pid_95%06x-0000-4000-8000-%012d", index, index), 1)
		}
		if _, err := resolver.ResolveAuthorization(selected, identity, RoutedOperation{OperationID: "getHomeSummary"}); !errors.Is(err, authorization.ErrUnavailable) {
			t.Fatalf("bound error=%v", err)
		}
	})
	t.Run("a foreign kind from the security agent database", func(t *testing.T) {
		security.rows["security_agent_run"] = []authorizationRoutingRecord{authorizationRoutingRecordFor(identity, "finding", "pid_93000001-0000-4000-8000-000000000001", 2)}
		security.rows["security_agent_approval"] = nil
		if got, err := resolver.ResolveAuthorization(selected, identity, RoutedOperation{OperationID: "getHomeSummary"}); err == nil || len(got.Targets) != 0 {
			t.Fatalf("foreign kind admitted: %+v %v", got, err)
		}
	})
	t.Run("missing secondary", func(t *testing.T) {
		if _, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, nil); !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatalf("missing secondary error=%v", err)
		}
	})
	if len(main.queries) != 1 {
		t.Fatalf("product database queries=%v", main.queries)
	}
}

func TestP7AuthorizationResolverIsolationAndConflicts(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	base := authorizationRoutingRecordFor(identity, "finding", "pid_93000001-0000-4000-8000-000000000001", 2)
	// A target of another Organization is refused whichever database names it.
	foreign := base
	foreign.Organization = "pid_99000001-0000-4000-8000-000000000001"
	for name, selected := range map[string]context.Context{"product": context.Background(), "security agent": withSecurityAgentAuthorization(context.Background())} {
		t.Run("foreign organization/"+name, func(t *testing.T) {
			foreignRun := foreign
			foreignRun.Kind = "security_agent_run"
			main, _ := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"*": {foreign}})
			secondary, _ := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"security_agent_run": {foreignRun}})
			resolver, _ := NewPostgresAuthorizationResolverWithSecurityAgent(main, secondary)
			got, err := resolver.ResolveAuthorization(selected, identity, RoutedOperation{OperationID: "getHomeSummary"})
			if err == nil || len(got.Targets) != 0 || got.Complete {
				t.Fatal("foreign target produced a grant", got, err)
			}
		})
	}
	// A candidate only the other database names is not part of the proof and
	// cannot conflict with it.
	t.Run("other database is not consulted", func(t *testing.T) {
		other := base
		other.Version++
		main, _ := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"*": {base}})
		secondary, secondaryDriver := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{"*": {other}})
		resolver, _ := NewPostgresAuthorizationResolverWithSecurityAgent(main, secondary)
		got, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: "globalSearch"})
		if err != nil || len(got.Targets) != 1 || got.Targets[0].Version != base.Version || len(secondaryDriver.queries) != 0 {
			t.Fatal("search candidates did not come from the product database alone", got, err, secondaryDriver.queries)
		}
	})
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
