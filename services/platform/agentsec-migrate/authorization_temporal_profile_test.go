package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type authorizationTemporalProfileRunner struct {
	*scriptedMigrationRunner
	calls int
}

func (r *authorizationTemporalProfileRunner) UpProductionAuthorizationTemporalProfile(context.Context) error {
	r.calls++
	return nil
}

func TestAuthorizationTemporalProfileCommand(t *testing.T) {
	args := []string{"up-authorization-temporal-profile"}
	if !isForwardMigration(args) || isForwardMigration([]string{args[0], "extra"}) {
		t.Fatal("explicit composed command missing or accepts extra arguments")
	}
	base := &authorizationTemporalProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
	registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{}}
	if err := runReleaseMigration(context.Background(), registered, args); err != nil || base.calls != 1 {
		t.Fatalf("composed dispatch calls=%d error=%v", base.calls, err)
	}
	if err := registerForwardRelease(context.Background(), &releaseReadinessQueryer{}, discoveryPrincipalRegistration{}, args); err != nil {
		t.Fatal(err)
	}
	base.version = 60
	if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, migrations.ErrInvalidState) || base.calls != 1 {
		t.Fatalf("noncanonical composed dispatch calls=%d error=%v", base.calls, err)
	}
}
