package main

import (
	"context"
	"errors"
	"testing"
)

type auditRunContextDatabase struct {
	*auditExportWorkerDatabase
	releaseErr error
	lookup     func()
}

func (d *auditRunContextDatabase) SecurityAgentRunContextAvailable(context.Context) (bool, error) {
	if d.lookup != nil {
		d.lookup()
	}
	return true, d.releaseErr
}

func TestAuditExportRunContextCompletedObserverPreservesTrust(t *testing.T) {
	database := &auditRunContextDatabase{auditExportWorkerDatabase: &auditExportWorkerDatabase{}, releaseErr: errors.New("untrusted54")}
	observer := &auditExportCompletedDatabase{base: database}
	if _, err := newPostgresAuditExportAuthority(observer, auditExportWorkerPolicyFixture()); err == nil {
		t.Fatal("completed-worker observer hid failed54 trust")
	}
	if len(database.queries) != 0 {
		t.Fatal("untrusted observer reached SQL")
	}
}

func TestAuditExportRunContextLookupFailure(t *testing.T) {
	for _, failure := range []string{"panic", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			database := &auditRunContextDatabase{auditExportWorkerDatabase: &auditExportWorkerDatabase{}}
			database.lookup = func() {
				if failure == "panic" {
					panic("lookup failed")
				}
				cancel()
			}
			if _, err := newPostgresAuditExportAuthorityContext(ctx, database, auditExportWorkerPolicyFixture()); err == nil {
				t.Fatal("failed lookup created executor")
			}
			if _, err := newPostgresAuditExportOutboxAuthorityContext(ctx, database); err == nil {
				t.Fatal("failed lookup created outbox")
			}
			if len(database.queries) != 0 {
				t.Fatal("failed lookup reached SQL")
			}
		})
	}
}

// Removing the uncached54 trust check must fail both warmed authority paths.
func TestAuditExportRunContextTrustChanges(t *testing.T) {
	for _, role := range []string{"executor", "outbox"} {
		t.Run(role, func(t *testing.T) {
			database := &auditRunContextDatabase{auditExportWorkerDatabase: &auditExportWorkerDatabase{}}
			var ready func(context.Context) error
			if role == "executor" {
				authority, err := newPostgresAuditExportAuthority(database, auditExportWorkerPolicyFixture())
				if err != nil {
					t.Fatal(err)
				}
				ready = authority.Ready
			} else {
				authority, err := newPostgresAuditExportOutboxAuthority(database)
				if err != nil {
					t.Fatal(err)
				}
				ready = authority.Ready
			}
			if err := ready(context.Background()); err != nil {
				t.Fatal(err)
			}
			before := len(database.queries)
			database.releaseErr = errors.New("untrusted54")
			if err := ready(context.Background()); err == nil {
				t.Fatal("untrusted54 readiness accepted")
			}
			if len(database.queries) != before {
				t.Fatal("untrusted54 reached legacy SQL readiness")
			}
		})
	}
}
