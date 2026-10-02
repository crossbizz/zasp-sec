package main

import (
	"context"
	"testing"
)

type identityProfileCommandRunner struct {
	*scriptedMigrationRunner
	base, composed int
}

func (r *identityProfileCommandRunner) UpProductionAuthorizationIdentityProfile(context.Context) error {
	r.base++
	return nil
}
func (r *identityProfileCommandRunner) UpProductionAuthorizationTemporalIdentityProfile(context.Context) error {
	r.composed++
	return nil
}

func TestIdentityProfileCommands(t *testing.T) {
	for _, command := range []string{"up-authorization-identity-profile", "up-authorization-temporal-identity-profile"} {
		t.Run(command, func(t *testing.T) {
			if !isForwardMigration([]string{command}) || isForwardMigration([]string{command, "extra"}) {
				t.Error("identity command classification rejected")
			}
			base := &identityProfileCommandRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
			registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{}}
			if err := runReleaseMigration(context.Background(), registered, []string{command}); err != nil || base.base+base.composed != 1 {
				t.Errorf("identity dispatch base=%d composed=%d error=%v", base.base, base.composed, err)
			}
		})
	}
}
