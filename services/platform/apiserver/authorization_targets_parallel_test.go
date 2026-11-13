package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// A driver whose resolve read completes only once its peer database's read is
// in flight too, so a sequential resolver cannot finish.
type authorizationMeetingDriver struct {
	rows          []authorizationRoutingRecord
	failure       error
	arrived, peer chan struct{}
}

func (driver *authorizationMeetingDriver) QueryRow(ctx context.Context, query string, _ ...any) PostgresRow {
	return authorizationRoutingRow(func(values ...any) error {
		if query != postgresAuthorizationResolveSQL || len(values) != 1 {
			return errors.New("unexpected authorization query")
		}
		close(driver.arrived)
		select {
		case <-driver.peer:
		case <-ctx.Done():
			return ctx.Err()
		}
		if driver.failure != nil {
			return driver.failure
		}
		payload, err := json.Marshal(driver.rows)
		if err != nil {
			return err
		}
		*values[0].(*[]byte) = payload
		return nil
	})
}
func (*authorizationMeetingDriver) Exec(context.Context, string, ...any) error { return nil }
func (*authorizationMeetingDriver) Close() error                               { return nil }

func authorizationMeetingResolver(t *testing.T, main, security []authorizationRoutingRecord, mainFailure, securityFailure error) *PostgresAuthorizationResolver {
	t.Helper()
	first, second := make(chan struct{}), make(chan struct{})
	mainDatabase, err := NewPostgresJSONDatabase(&authorizationMeetingDriver{rows: main, failure: mainFailure, arrived: first, peer: second})
	if err != nil {
		t.Fatal(err)
	}
	securityDatabase, err := NewPostgresJSONDatabase(&authorizationMeetingDriver{rows: security, failure: securityFailure, arrived: second, peer: first})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(mainDatabase, securityDatabase)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

// Mixed parent collections read both candidate sets at once. The merged set,
// its main-first order and the all-or-nothing failure contract are unchanged.
func TestAuthorizationResolverReadsMixedCollectionsConcurrently(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	finding := authorizationRoutingRecordFor(identity, "finding", "pid_92000001-0000-4000-8000-000000000001", 4)
	run := authorizationRoutingRecordFor(identity, "security_agent_run", "pid_92000002-0000-4000-8000-000000000002", 7)
	for _, operation := range []string{"getHomeSummary", "globalSearch", "listAuditEvents", "listComplianceControls", "listComplianceEvidence", "listWorkflowMutationReceipts"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resolver := authorizationMeetingResolver(t, []authorizationRoutingRecord{finding, run}, []authorizationRoutingRecord{run}, nil, nil)
			got, err := resolver.ResolveAuthorization(ctx, identity, RoutedOperation{OperationID: operation})
			if err != nil {
				t.Fatalf("mixed collection was not read concurrently: %v", err)
			}
			if !got.Complete || !got.Collection || len(got.Targets) != 2 || got.Targets[0].ID != finding.ID || got.Targets[1].ID != run.ID {
				t.Fatalf("merged candidates changed: %#v", got)
			}
		})
	}
	unavailable := errors.New("candidate source unavailable")
	for name, failures := range map[string][2]error{"main": {unavailable, nil}, "security agent": {nil, unavailable}, "both": {unavailable, unavailable}} {
		t.Run("failure "+name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resolver := authorizationMeetingResolver(t, []authorizationRoutingRecord{finding}, []authorizationRoutingRecord{run}, failures[0], failures[1])
			got, err := resolver.ResolveAuthorization(ctx, identity, RoutedOperation{OperationID: "getHomeSummary"})
			if err == nil || got.Complete || len(got.Targets) != 0 {
				t.Fatalf("partial candidate set admitted: %#v %v", got, err)
			}
		})
	}
	t.Run("conflicting duplicate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		other := run
		other.Version++
		resolver := authorizationMeetingResolver(t, []authorizationRoutingRecord{run}, []authorizationRoutingRecord{other}, nil, nil)
		got, err := resolver.ResolveAuthorization(ctx, identity, RoutedOperation{OperationID: "getHomeSummary"})
		if err == nil || got.Complete || len(got.Targets) != 0 {
			t.Fatalf("conflicting candidates admitted: %#v %v", got, err)
		}
	})
}
