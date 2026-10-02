package main

import (
	"context"
	"testing"
)

type auditProfileCommandRunner struct {
	*scriptedMigrationRunner
	base, composed int
}

func (r *auditProfileCommandRunner) UpProductionAuthorizationAuditProfile(context.Context) error {
	r.base++
	return nil
}
func (r *auditProfileCommandRunner) UpProductionAuthorizationTemporalAuditProfile(context.Context) error {
	r.composed++
	return nil
}

func TestAuthorizationAuditProfileCommands(t *testing.T) {
	for _, command := range []string{"up-authorization-audit-profile", "up-authorization-temporal-audit-profile"} {
		t.Run(command, func(t *testing.T) {
			if !isForwardMigration([]string{command}) || isForwardMigration([]string{command, "extra"}) {
				t.Error("guarded command missing or accepts extra arguments")
			}
			base := &auditProfileCommandRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
			registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{}}
			if err := runReleaseMigration(context.Background(), registered, []string{command}); err != nil || base.base+base.composed != 1 {
				t.Fatalf("guarded dispatch base=%d composed=%d error=%v", base.base, base.composed, err)
			}
		})
	}
}
