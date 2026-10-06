package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type temporalChecksumQueryer struct {
	statement string
	arguments []any
}

func (q *temporalChecksumQueryer) QueryRow(_ context.Context, statement string, args ...any) pgx.Row {
	q.statement, q.arguments = statement, append([]any(nil), args...)
	return scriptedPrincipalRow{value: true}
}

// Readiness requires only the source identity. Constructing the ancestor SQL
// graph here wastes hundreds of megabytes and exhausts the composite deadline.
func TestTemporalForwardReadinessDoesNotBuildAncestorSQL(t *testing.T) {
	base, err := os.ReadFile("../migrations/sql/0067_production_temporal_domain.base.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../migrations/sql/0067_production_temporal_domain.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append(append(base, 0), up...))
	q := &temporalChecksumQueryer{}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{migration: "fixture_operator"}, []string{"up-temporal-domain"})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if q.statement != "SELECT session_user=$1 AND zasp_temporal67.ready($2,$3)" || !reflect.DeepEqual(q.arguments, []any{"fixture_operator", fmt.Sprintf("%x", digest), migrations.TemporalDomainFingerprint()}) {
		t.Fatal("forward readiness lost its exact session or source identity")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4<<20 {
		t.Fatalf("checksum-only readiness built ancestor SQL: allocated %d bytes", allocated)
	}
}

// Vectors independently derived from the original unbound SQL and fragments.
func TestTemporalForwardReadinessSourceIdentities(t *testing.T) {
	for _, tc := range []struct {
		version                        int
		command, checksum, fingerprint string
	}{
		{67, "up-temporal-domain", "b0ce6cf26b4b5f7e909f2e8e8ba5fdc987318efb21878c503117b4583b1544a8", migrations.TemporalDomainFingerprint()},
		{68, "up-temporal-executor", "bf5f2b8a2578c8d3c43b8edd0590c55a5eb7c48b178cca310e0ebadfc90e8eed", migrations.TemporalExecutorFingerprint()},
		{69, "up-temporal-workflow", "a8bc2bda275a2715eb3a56ce6f154d14ae960b463c89c07e80546fdbc9dfa7b9", migrations.TemporalWorkflowFingerprint()},
		{70, "up-temporal-compatibility", "64e6bae3878ee548084f91f5ef2a6cf866105d2973594d8fe7d0a45cff032988", migrations.TemporalCompatibilityFingerprint()},
		{71, "up-temporal-legacy-tests", "4ab3a167a76f1296c385b36330f83180fe2eedb7233f49377073248bac3f1ec8", migrations.TemporalLegacyTestsFingerprint()},
		{72, "up-temporal-discovery", "e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940", migrations.TemporalDiscoveryFingerprint()},
		{73, "up-temporal-admission", "d2b10f7a97ee8cbc23ccacce852845ce20625851a93428013b0c83f799838556", migrations.TemporalAdmissionFingerprint()},
		{74, "up-temporal-test-executor", "6ecde7cb0053af3378f47aef84ecbe99ca31d9cdced9fbe6d0dc64ee7e01b39e", migrations.TemporalTestExecutorFingerprint()},
		{75, "up-temporal-test-selector", "27c65026b98f6c7d68620eea2d174db0eebf68cea40c49094350878e185b5371", migrations.TemporalTestSelectorFingerprint()},
		{76, "up-temporal-human-admission", "57cc7f96f487b7f172502c7dea30eccd0244ad14437a747c32a6d05ecdb3b107", migrations.TemporalHumanAdmissionFingerprint()},
	} {
		t.Run(tc.command, func(t *testing.T) {
			q := &temporalChecksumQueryer{}
			if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{migration: "fixture_operator"}, []string{tc.command}); err != nil {
				t.Fatal(err)
			}
			wantStatement := fmt.Sprintf("SELECT session_user=$1 AND zasp_temporal%d.ready($2,$3)", tc.version)
			if q.statement != wantStatement || !reflect.DeepEqual(q.arguments, []any{"fixture_operator", tc.checksum, tc.fingerprint}) {
				t.Fatal("readiness source identity or principal changed")
			}
		})
	}
}
