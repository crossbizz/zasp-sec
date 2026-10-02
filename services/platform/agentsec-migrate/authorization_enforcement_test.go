package main

import (
	"context"
	"testing"
)

type authorizationEnforcementRunner struct {
	*scriptedMigrationRunner
	calls int
}

func (r *authorizationEnforcementRunner) UpProductionAuthorizationEnforcement(context.Context) error {
	r.calls++
	return nil
}

func TestAuthorizationEnforcementCommand(t *testing.T) {
	args := []string{"up-authorization-enforcement"}
	if !isForwardMigration(args) || isForwardMigration(append(args, "extra")) {
		t.Fatal("authorization enforcement command is not registered")
	}
	base := &authorizationEnforcementRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
	registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{}}
	if err := runReleaseMigration(context.Background(), registered, args); err != nil || base.calls != 1 {
		t.Fatalf("authorization enforcement dispatch: calls=%d err=%v", base.calls, err)
	}
	if err := registerForwardRelease(context.Background(), &releaseReadinessQueryer{}, discoveryPrincipalRegistration{}, args); err != nil {
		t.Fatal(err)
	}
}
