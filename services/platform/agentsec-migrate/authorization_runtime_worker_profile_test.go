package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

// Add the new finite adapter while preserving the original diagnostic roster,
// terminal causes and fixture bytes. No production fallback is introduced.
func (r *innerDiagnosticRunner) UpProductionAuthorizationWorkerAuditProfile(ctx context.Context) error {
	return r.install(ctx, "up-authorization-worker-profile")
}

type auditWorkerDispatchFixture struct {
	*authorizationWorkerProfileRunner
	auditCalls int
	auditError error
}

func (r *auditWorkerDispatchFixture) UpProductionAuthorizationWorkerAuditProfile(context.Context) error {
	r.auditCalls++
	return r.auditError
}
func TestAuthorizationRuntimeWorkerSelectsExplicitAuditRecipe(t *testing.T) {
	cause := errors.New("owned audit refusal")
	base := &auditWorkerDispatchFixture{authorizationWorkerProfileRunner: &authorizationWorkerProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}, auditError: cause}
	registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{}, registration: discoveryPrincipalRegistration{migration: "fixture_operator"}}
	if err := runReleaseMigration(context.Background(), authorizationRuntimeWorkerRunner{registered}, []string{"up-authorization-worker-profile"}); !errors.Is(err, cause) || base.auditCalls != 1 || base.calls != 0 {
		t.Fatal("composite did not preserve exact audited installer refusal")
	}
	if err := runReleaseMigration(context.Background(), registered, []string{"up-authorization-worker-profile"}); err != nil || base.calls != 1 || base.auditCalls != 1 {
		t.Fatal("standalone worker recipe changed")
	}
	registered.releaseMigrationRunner = base.authorizationWorkerProfileRunner
	if err := runReleaseMigration(context.Background(), authorizationRuntimeWorkerRunner{registered}, []string{"up-authorization-worker-profile"}); !errors.Is(err, migrations.ErrInvalidState) || base.calls != 1 {
		t.Fatal("composite fell back to legacy recipe")
	}
	registered.releaseMigrationRunner = base
	registered.queryer = &releaseReadinessQueryer{failAt: 1}
	if err := runReleaseMigration(context.Background(), authorizationRuntimeWorkerRunner{registered}, []string{"up-authorization-worker-profile"}); !errors.Is(err, errReleasePrincipalRegistration) || base.auditCalls != 1 {
		t.Fatal("unregistered operator reached audit installer")
	}
}
