package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"reflect"
	"testing"
	"time"
)

type recoveryMigrationRunner struct {
	*scriptedMigrationRunner
	calls int
}

func (r *recoveryMigrationRunner) UpProductionTemporalSingleRecovery(context.Context) error {
	r.calls++
	return nil
}
func TestSingleTestRecoveryInstallerRouting(t *testing.T) {
	args := []string{"up-temporal-single-recovery"}
	if !isForwardMigration(args) || isForwardMigration(append(args, "extra")) {
		t.Fatal("fixed recovery command missing")
	}
	r := &recoveryMigrationRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
	registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: r, queryer: &releaseReadinessQueryer{}, registration: discoveryPrincipalRegistration{migration: "profile_operator"}}
	if err := runReleaseMigration(context.Background(), registered, args); err != nil || r.calls != 1 {
		t.Fatalf("dispatch: %v calls=%d", err, r.calls)
	}
	metadata := migrations.ProductionTemporalSingleRecoveryMetadata()
	q := &releaseReadinessQueryer{}
	if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{migration: "profile_operator"}, args); err != nil {
		t.Fatal("forward readiness", err)
	}
	if !reflect.DeepEqual(q.statements, []string{migrations.TemporalSingleRecoveryReadySourceSQL, `SELECT session_user=$1 AND zasp_temporal_single_recovery.ready($2)`}) || !reflect.DeepEqual(q.arguments, [][]any{{metadata.ReadyBodyDigest}, {"profile_operator", metadata.Checksum}}) {
		t.Fatalf("forward recovery metadata changed: %v %v", q.statements, q.arguments)
	}
	for _, tc := range []releaseReadinessQueryer{{failAt: 1}, {failAt: 1, queryError: true}, {failAt: 2}, {failAt: 2, queryError: true}} {
		probe := tc
		if err := registerForwardRelease(context.Background(), &probe, discoveryPrincipalRegistration{migration: "profile_operator"}, args); !errors.Is(err, errReleasePrincipalRegistration) || len(probe.statements) != probe.failAt {
			t.Fatalf("forward readiness failure escaped: %#v err=%v", tc, err)
		}
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	q = &releaseReadinessQueryer{}
	if err := registerForwardRelease(canceled, q, discoveryPrincipalRegistration{migration: "profile_operator"}, args); !errors.Is(err, errReleasePrincipalRegistration) || len(q.statements) != 0 {
		t.Fatal("canceled forward readiness reached database", err)
	}
	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q = &releaseReadinessQueryer{}
	if err := registerForwardRelease(parent, q, discoveryPrincipalRegistration{migration: "profile_operator"}, args); err != nil {
		t.Fatal("bounded forward readiness", err)
	}
	parentDeadline, _ := parent.Deadline()
	for _, call := range q.contexts {
		deadline, ok := call.Deadline()
		if !ok || !deadline.Equal(parentDeadline) {
			t.Fatal("forward readiness changed caller deadline")
		}
	}
	r.version = 80
	if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, migrations.ErrInvalidState) || r.calls != 1 {
		t.Fatal("numbered80 accepted", err)
	}
}
