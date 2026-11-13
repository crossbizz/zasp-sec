package apiserver

import (
	"context"
	"errors"
	"testing"
)

// The mixed and stored-parent collections are statements of the product
// database. Their candidates are read there only: a failing or slow Security
// Agent database neither adds a target to their proof nor refuses them.
func TestAuthorizationResolverReadsMixedCollectionsOnTheProductDatabase(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	finding := authorizationRoutingRecordFor(identity, "finding", "pid_92000001-0000-4000-8000-000000000001", 4)
	run := authorizationRoutingRecordFor(identity, "security_agent_run", "pid_92000002-0000-4000-8000-000000000002", 7)
	for _, operation := range []string{"getHomeSummary", "globalSearch", "listAuditEvents", "listComplianceControls", "listComplianceEvidence", "listWorkflowMutationReceipts"} {
		t.Run(operation, func(t *testing.T) {
			policy, err := authorizationTargetPolicy(operation)
			if err != nil {
				t.Fatal(err)
			}
			mainDatabase, main := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{policy.Kind: {finding}})
			securityDatabase, security := authorizationRoutingDatabase(t, map[string][]authorizationRoutingRecord{policy.Kind: {finding, run}})
			security.err[policy.Kind] = errors.New("candidate source unavailable")
			resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, securityDatabase)
			if err != nil {
				t.Fatal(err)
			}
			got, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: operation})
			if err != nil || !got.Complete || !got.Collection || len(got.Targets) != 1 || got.Targets[0].ID != finding.ID {
				t.Fatalf("candidates=%#v error=%v", got, err)
			}
			if len(main.queries) != 1 || len(security.queries) != 0 {
				t.Fatalf("main queries=%v security queries=%v", main.queries, security.queries)
			}
			main.err[policy.Kind] = errors.New("candidate source unavailable")
			if got, err := resolver.ResolveAuthorization(context.Background(), identity, RoutedOperation{OperationID: operation}); err == nil || got.Complete || len(got.Targets) != 0 {
				t.Fatalf("partial candidate set admitted: %#v %v", got, err)
			}
		})
	}
}
