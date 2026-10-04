package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"reflect"
	"strings"
	"testing"
)

// Only finite dependency adapters are fake: the real shipped composite planner,
// registered principal barriers, runReleaseMigration switch and forward-readiness
// dispatcher are consumed unchanged. These tests do not connect a database.
var innerDiagnosticSteps = []string{"up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response", "up-authorization-temporal-identity-profile", "up-authorization-worker-profile"}

type innerDiagnosticRunner struct {
	*scriptedMigrationRunner
	failStep, failStage string
	cause               error
	events              []string
	pending             string
}

func (r *innerDiagnosticRunner) install(ctx context.Context, step string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.events = append(r.events, "install:"+step)
	if r.failStep == step && r.failStage == "install" {
		return r.cause
	}
	r.version = 61
	r.pending = step
	return nil
}
func (r *innerDiagnosticRunner) UpProductionTemporalDomain(ctx context.Context) error {
	return r.install(ctx, "up-temporal-domain")
}
func (r *innerDiagnosticRunner) UpProductionTemporalExecutor(ctx context.Context) error {
	return r.install(ctx, "up-temporal-executor")
}
func (r *innerDiagnosticRunner) UpProductionTemporalWorkflow(ctx context.Context) error {
	return r.install(ctx, "up-temporal-workflow")
}
func (r *innerDiagnosticRunner) UpProductionTemporalCompatibility(ctx context.Context) error {
	return r.install(ctx, "up-temporal-compatibility")
}
func (r *innerDiagnosticRunner) UpProductionTemporalLegacyTests(ctx context.Context) error {
	return r.install(ctx, "up-temporal-legacy-tests")
}
func (r *innerDiagnosticRunner) UpProductionTemporalDiscovery(ctx context.Context) error {
	return r.install(ctx, "up-temporal-discovery")
}
func (r *innerDiagnosticRunner) UpProductionTemporalAdmission(ctx context.Context) error {
	return r.install(ctx, "up-temporal-admission")
}
func (r *innerDiagnosticRunner) UpProductionTemporalTestExecutor(ctx context.Context) error {
	return r.install(ctx, "up-temporal-test-executor")
}
func (r *innerDiagnosticRunner) UpProductionTemporalTestSelector(ctx context.Context) error {
	return r.install(ctx, "up-temporal-test-selector")
}
func (r *innerDiagnosticRunner) UpProductionTemporalHumanAdmission(ctx context.Context) error {
	return r.install(ctx, "up-temporal-human-admission")
}
func (r *innerDiagnosticRunner) UpProductionTemporalAutomaticSources(ctx context.Context) error {
	return r.install(ctx, "up-temporal-automatic-sources")
}
func (r *innerDiagnosticRunner) UpProductionTemporalFindingResponse(ctx context.Context) error {
	return r.install(ctx, "up-temporal-finding-response")
}
func (r *innerDiagnosticRunner) UpProductionAuthorizationTemporalIdentityProfile(ctx context.Context) error {
	return r.install(ctx, "up-authorization-temporal-identity-profile")
}
func (r *innerDiagnosticRunner) UpProductionAuthorizationWorkerProfile(ctx context.Context) error {
	return r.install(ctx, "up-authorization-worker-profile")
}

type innerDiagnosticQueryer struct{ runner *innerDiagnosticRunner }
type innerDiagnosticRow struct {
	ready      bool
	namespaces bool
}

func (q *innerDiagnosticQueryer) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "array_agg(nspname") {
		return innerDiagnosticRow{namespaces: true}
	}
	r := q.runner
	if r.pending != "" {
		step := r.pending
		r.pending = ""
		r.events = append(r.events, "forward-readiness:"+step)
		return innerDiagnosticRow{ready: !(r.failStep == step && r.failStage == "forward-readiness")}
	}
	return innerDiagnosticRow{ready: true}
}
func (r innerDiagnosticRow) Scan(args ...any) error {
	if len(args) != 1 {
		return errors.New("finite row shape mismatch")
	}
	if r.namespaces {
		value, ok := args[0].(*[]string)
		if !ok {
			return errors.New("finite namespace target mismatch")
		}
		*value = []string{}
		return nil
	}
	value, ok := args[0].(*bool)
	if !ok {
		return errors.New("finite readiness target mismatch")
	}
	*value = r.ready
	return nil
}
func innerDiagnosticFixture(step, stage string) (*registeredReleaseMigrationRunner, *innerDiagnosticRunner) {
	base := &innerDiagnosticRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}, failStep: step, failStage: stage, cause: errors.New("fixture-private-cause")}
	return &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &innerDiagnosticQueryer{runner: base}, registration: discoveryPrincipalRegistration{migration: "fixture_operator"}}, base
}
func TestAuthorizationRuntimeProfileInnerFailureDiagnostic(t *testing.T) {
	for index, step := range innerDiagnosticSteps {
		for _, stage := range []string{"install", "forward-readiness"} {
			t.Run(step+"/"+stage, func(t *testing.T) {
				runner, base := innerDiagnosticFixture(step, stage)
				// Reach the actual original CLI command switch, not a diagnostic-only helper.
				err := runReleaseMigration(context.Background(), runner, []string{"up-authorization-runtime-profile"})
				cause := base.cause
				if stage == "forward-readiness" {
					cause = errReleasePrincipalRegistration
				}
				if !errors.Is(err, cause) {
					t.Fatal("original terminal refusal identity lost")
				}
				wantEvents := []string{}
				for _, previous := range innerDiagnosticSteps[:index] {
					wantEvents = append(wantEvents, "install:"+previous, "forward-readiness:"+previous)
				}
				wantEvents = append(wantEvents, "install:"+step)
				if stage == "forward-readiness" {
					wantEvents = append(wantEvents, "forward-readiness:"+step)
				}
				if !reflect.DeepEqual(base.events, wantEvents) {
					t.Fatal("actual composite crossed or reordered a terminal boundary")
				}
				want := "authorization runtime profile refused: step=" + step + " stage=" + stage
				if err == nil || err.Error() != want {
					t.Fatal("closed inner step/stage diagnostic absent")
				}
				for _, format := range []string{"%v", "%#v", "%+#v"} {
					value := fmt.Sprintf(format, err)
					if value != want || strings.Contains(value, "fixture-private-cause") {
						t.Fatal("diagnostic formatting disclosed a cause or nonclosed content")
					}
				}
			})
		}
	}
}
func TestAuthorizationRuntimeProfileInnerSuccessOrder(t *testing.T) {
	runner, base := innerDiagnosticFixture("", "")
	if err := runReleaseMigration(context.Background(), runner, []string{"up-authorization-runtime-profile"}); err != nil {
		t.Fatal("finite actual composite success refused")
	}
	want := []string{}
	for _, step := range innerDiagnosticSteps {
		want = append(want, "install:"+step, "forward-readiness:"+step)
	}
	if !reflect.DeepEqual(base.events, want) {
		t.Fatal("actual complete fourteen-step order changed")
	}
}
