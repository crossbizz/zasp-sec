package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type authorizationInventoryProfileRunner struct {
	*scriptedMigrationRunner
	calls int
	err   error
}

func (r *authorizationInventoryProfileRunner) UpProductionAuthorizationInventoryProfile(context.Context) error {
	r.calls++
	return r.err
}

func TestAuthorizationInventoryProfileCommandDispatch(t *testing.T) {
	args := []string{"up-authorization-inventory-profile"}
	if !isForwardMigration(args) || !authorizationProfileCommand(args[0]) || isForwardMigration([]string{args[0], "extra"}) {
		t.Fatal("inventory command missing registered profile dispatch or accepts extra arguments")
	}
	base := &authorizationInventoryProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
	q := &releaseReadinessQueryer{}
	registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q, registration: discoveryPrincipalRegistration{migration: "inventory_operator"}}
	for i := 0; i < 2; i++ {
		if err := runReleaseMigration(context.Background(), registered, args); err != nil || base.calls != i+1 {
			t.Fatalf("inventory dispatch/replay calls=%d error=%v", base.calls, err)
		}
	}
	if len(q.statements) != 2 || len(base.events) != 2 {
		t.Fatalf("inventory installation composed unrelated migrations: queries=%v events=%v", q.statements, base.events)
	}
	base.err = migrations.ErrInvalidState
	if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, migrations.ErrInvalidState) || base.calls != 3 {
		t.Fatalf("installer ancestry/profile refusal escaped: calls=%d error=%v", base.calls, err)
	}
}

func TestAuthorizationInventoryProfileCommandRejectsNoncanonicalAndUnregisteredCallers(t *testing.T) {
	args := []string{"up-authorization-inventory-profile"}
	for _, version := range []int64{0, 14, 60, 62, 78, 79, 80} {
		base := &authorizationInventoryProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: version}}
		q := &releaseReadinessQueryer{}
		registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q}
		if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, migrations.ErrInvalidState) || base.calls != 0 || len(q.statements) != 0 {
			t.Fatalf("noncanonical version=%d reached installer: calls=%d queries=%v error=%v", version, base.calls, q.statements, err)
		}
	}
	for _, databaseError := range []bool{false, true} {
		base := &authorizationInventoryProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
		registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{failAt: 1, queryError: databaseError}}
		if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, errReleasePrincipalRegistration) || base.calls != 0 {
			t.Fatalf("unregistered caller reached installer: calls=%d error=%v", base.calls, err)
		}
	}
	unsupported := &registeredReleaseMigrationRunner{releaseMigrationRunner: &scriptedMigrationRunner{version: 61}, queryer: &releaseReadinessQueryer{}}
	if err := runReleaseMigration(context.Background(), unsupported, args); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("missing installer accepted: %v", err)
	}
	base := &authorizationInventoryProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
	if err := runReleaseMigration(context.Background(), base, []string{args[0], "extra"}); !errors.Is(err, errInvalidMigrationCommand) || base.calls != 0 {
		t.Fatalf("extra arguments reached installer: %v", err)
	}
}

func TestAuthorizationInventoryProfileRegistrationPinsInstalledCatalog(t *testing.T) {
	args := []string{"up-authorization-inventory-profile"}
	registration := discoveryPrincipalRegistration{migration: "inventory_operator"}
	q := &releaseReadinessQueryer{}
	if err := registerForwardRelease(context.Background(), q, registration, args); err != nil {
		t.Fatal(err)
	}
	want := []string{`SELECT session_user=$1 AND zasp_authorization79.operator()`, migrations.AuthorizationInventoryInstallerReadySourceSQL()}
	if !reflect.DeepEqual(q.statements, want) || !reflect.DeepEqual(q.arguments, [][]any{{registration.migration}, nil}) {
		t.Fatalf("inventory registration changed fixed principal/source pins: statements=%v arguments=%v", q.statements, q.arguments)
	}
	if !strings.Contains(q.statements[1], migrations.AuthorizationInventoryProfileChecksum()) || strings.Contains(q.statements[1], " AND zasp_authorization80_inventory.api_ready()") || strings.Contains(q.statements[1], "zasp_temporal") {
		t.Fatal("installer readiness lacks profile checksum or requires unrelated runtime principal")
	}
	// False covers an absent or drifted profile; database errors must fail closed
	// at the same boundary without falling back to numbered migration readiness.
	for _, failAt := range []int{1, 2} {
		for _, databaseError := range []bool{false, true} {
			q := &releaseReadinessQueryer{failAt: failAt, queryError: databaseError}
			if err := registerForwardRelease(context.Background(), q, registration, args); !errors.Is(err, errReleasePrincipalRegistration) || len(q.statements) != failAt {
				t.Fatalf("principal/profile refusal escaped: failure=%d queryError=%t statements=%v error=%v", failAt, databaseError, q.statements, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, invalid := range []context.Context{nil, ctx} {
		q := &releaseReadinessQueryer{}
		if err := registerForwardRelease(invalid, q, registration, args); !errors.Is(err, errReleasePrincipalRegistration) || len(q.statements) != 0 {
			t.Fatalf("invalid context reached profile registration: %v", err)
		}
	}
}
