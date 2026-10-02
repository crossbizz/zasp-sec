package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

type authorizationProjectionRunner struct {
	*scriptedMigrationRunner
	calls int
}

func (r *authorizationProjectionRunner) UpProductionAuthorizationProjection(context.Context) error {
	r.calls++
	return nil
}
func TestAuthorizationProjectionCommand(t *testing.T) {
	args := []string{"up-authorization-projection"}
	if !isForwardMigration(args) || isForwardMigration(append(args, "extra")) {
		t.Fatal("projection command registration classification")
	}
	for _, version := range []int64{24, 25, 60, 61, 62} {
		base := &authorizationProjectionRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: version}}
		q := &releaseReadinessQueryer{}
		registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q}
		err := runReleaseMigration(context.Background(), registered, args)
		if version < 25 || version > 61 {
			if !errors.Is(err, migrations.ErrInvalidState) || base.calls != 0 {
				t.Fatal("invalid predecessor installed projection")
			}
			continue
		}
		if err != nil || base.calls != 1 {
			t.Fatal("registered projection command unavailable", version, err)
		}
		if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, args); err != nil {
			t.Fatal(err)
		}
	}
	base := &authorizationProjectionRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 25}}
	failed := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{failAt: 1}}
	if err := runReleaseMigration(context.Background(), failed, args); !errors.Is(err, errReleasePrincipalRegistration) || base.calls != 0 {
		t.Fatal("wrong authority crossed installation barrier", err)
	}
}
