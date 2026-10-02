package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type authorizationWorkerProfileRunner struct {
	*scriptedMigrationRunner
	calls int
}

func (r *authorizationWorkerProfileRunner) UpProductionAuthorizationWorkerProfile(context.Context) error {
	r.calls++
	return nil
}

// Missing explicit dispatch or accepting a numbered80 database must fail this
// consumer contract. Installation checks the catalog, not unfinished runtime readiness.
func TestAuthorizationWorkerProfileCommand(t *testing.T) {
	args := []string{"up-authorization-worker-profile"}
	if !isForwardMigration(args) || isForwardMigration([]string{args[0], "extra"}) {
		t.Fatal("explicit worker profile command missing or accepts extra arguments")
	}
	base := &authorizationWorkerProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
	q := &releaseReadinessQueryer{}
	registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q, registration: discoveryPrincipalRegistration{migration: "profile_operator"}}
	for i := 0; i < 2; i++ {
		if err := runReleaseMigration(context.Background(), registered, args); err != nil || base.calls != i+1 {
			t.Fatalf("dispatch/replay calls=%d error=%v", base.calls, err)
		}
	}
	for _, version := range []int64{60, 78, 79, 80} {
		base.version = version
		if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, migrations.ErrInvalidState) || base.calls != 2 {
			t.Fatalf("noncanonical dispatch version=%d calls=%d error=%v", version, base.calls, err)
		}
	}
	base.version = 61
	registered.queryer = &releaseReadinessQueryer{failAt: 1}
	if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, errReleasePrincipalRegistration) || base.calls != 2 {
		t.Fatalf("unregistered authority reached installer: %v", err)
	}
	q = &releaseReadinessQueryer{}
	if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{migration: "profile_operator"}, args); err != nil || len(q.statements) != 1 || !strings.Contains(q.statements[0], "zasp_authorization80_worker.catalog_ready()") || strings.Contains(q.statements[0], "runtime_ready()") || !strings.Contains(q.statements[0], "zasp_authorization80_temporal.ready()") {
		t.Fatalf("incorrect post-install gate: %v %v", q.statements, err)
	}
	for _, databaseError := range []bool{false, true} {
		if err := registerForwardRelease(context.Background(), &releaseReadinessQueryer{failAt: 1, queryError: databaseError}, discoveryPrincipalRegistration{}, args); !errors.Is(err, errReleasePrincipalRegistration) {
			t.Fatalf("post-install failure escaped: %v", err)
		}
	}
}
