package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTemporalTestSelectorInstalledReleasePostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	for _, command := range []string{"up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor"} {
		if err := runReleaseMigration(f.ctx, f.registered, []string{command}); err != nil {
			t.Fatal(command, err)
		}
	}
	wrong := *f.registered
	wrong.registration.api = f.registration.discovery
	if err := runReleaseMigration(f.ctx, &wrong, []string{"up-temporal-test-selector"}); err == nil {
		t.Fatal("wrong registration installed selector")
	}
	for i := 0; i < 2; i++ {
		if err := runReleaseMigration(f.ctx, f.registered, []string{"up-temporal-test-selector"}); err != nil {
			t.Fatal("actual selector CLI", i, err)
		}
		if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-temporal-test-selector"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []string{`GRANT EXECUTE ON FUNCTION zasp_temporal75.admit(jsonb) TO PUBLIC`, `ALTER TABLE zasp_temporal75.configuration NO FORCE ROW LEVEL SECURITY`, `ALTER TABLE zasp_temporal75.configuration DISABLE TRIGGER immutable`, `ALTER TABLE public.zasp_security_agent_runs DISABLE TRIGGER zasp_temporal75_owner`, `DROP POLICY zasp_temporal75_owner ON public.zasp_security_agent_runs`, `ALTER TABLE zasp_temporal75.admissions DISABLE TRIGGER immutable`} {
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(f.ctx, change); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal75.current_ready()`).Scan(&ready); err != nil || ready {
			t.Fatal("selector catalog drift accepted", change, ready, err)
		}
		if err := tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Execute the shipped consumer with the actual compiled CLI and fixture
	// registration. A descriptor-only deployment test cannot satisfy this proof.
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	build := exec.CommandContext(f.ctx, "go", "build", "-o", binary, ".")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("CLI build: %v %s", err, output)
	}
	r := f.registration
	environment := append(os.Environ(), postgresDSNEnvironment+"="+f.owner.Config().ConnString(), migrationTimeoutEnvironment+"=30s")
	for _, b := range [][2]string{{migrationPrincipalEnvironment, r.migration}, {discoveryAPIPrincipalEnvironment, r.api}, {discoveryWorkerPrincipalEnvironment, r.discovery}, {runtimeIngestPrincipalEnvironment, r.ingest}, {runtimeWorkerPrincipalEnvironment, r.runtime}, {outboxWorkerPrincipalEnvironment, r.outbox}, {runtimeGatewayPrincipalEnvironment, r.gateway}, {discoverySchedulerPrincipalEnvironment, r.scheduler}, {projectionRiskPrincipalEnvironment, r.projectionRisk}, {projectionGraphPrincipalEnvironment, r.projectionGraph}, {projectionSearchPrincipalEnvironment, r.projectionSearch}, {runtimeCoordinatorPrincipalEnvironment, r.runtimeCoordinator}, {runtimeArchivePrincipalEnvironment, r.runtimeArchive}, {runtimeIndexPrincipalEnvironment, r.runtimeIndex}, {runtimeCorrelationPrincipalEnvironment, r.runtimeCorrelation}, {runtimeProjectionPrincipalEnvironment, r.runtimeProjection}, {gatewayControlPrincipalEnvironment, r.gatewayControl}, {securityAgentAPIPrincipalEnvironment, r.securityAgentAPI}, {securityAgentWorkerPrincipalEnvironment, r.securityAgentWorker}, {securityAgentActionPrincipalEnvironment, r.securityAgentAction}, {redTeamWorkerPrincipalEnvironment, r.redTeamWorker}, {redTeamOutboxPrincipalEnvironment, r.redTeamOutbox}, {redTeamAdapterPrincipalEnvironment, r.redTeamAdapter}, {attackLabControllerPrincipalEnvironment, r.attackLabController}, {attackLabOutboxPrincipalEnvironment, r.attackLabOutbox}, {attackLabProxyPrincipalEnvironment, r.attackLabProxy}, {recoveryWorkerPrincipalEnvironment, r.recoveryWorker}, {recoveryOutboxPrincipalEnvironment, r.recoveryOutbox}, {policyDeploymentPrincipalEnvironment, r.policyDeployment}} {
		environment = append(environment, b[0]+"="+b[1])
	}
	for attempt := 0; attempt < 2; attempt++ {
		command := exec.CommandContext(f.ctx, "node", "../../../deploy/production/temporal-test-selector.mjs", binary, "../../../deploy/production/temporal-test-selector.config.json")
		command.Env = environment
		command.WaitDelay = 5 * time.Second
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("shipped selector consumer %d: %v %s", attempt, err, output)
		}
	}
	var installed bool
	if err := f.owner.QueryRow(f.ctx, `SELECT count(*)=1 AND bool_and(revision=1 AND schema_version=1 AND cadence_seconds=1 AND enabled) FROM zasp_temporal75.configuration`).Scan(&installed); err != nil || !installed {
		t.Fatal("shipped1s desired configuration", installed, err)
	}
	for _, raw := range []string{"", `{"revision":2,"cadence_seconds":1.5,"enabled":true}`} {
		command := exec.CommandContext(f.ctx, binary, "configure-temporal-test-selector")
		command.Env = append(environment, "ZASP_TEST_SELECTOR_CONFIGURATION="+raw)
		command.WaitDelay = 5 * time.Second
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("invalid CLI configuration accepted: %s", output)
		}
	}
	t.Log("actual shipped deployment consumer joined both CLI commands; exact1s configuration replayed; missing/fractional CLI configuration refused")
}
