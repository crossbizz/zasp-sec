package main

import (
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"os"
	"os/exec"
	"testing"
)

func TestTemporalOutboxShippedCommandPostgres(t *testing.T) {
	f := newScheduleReplayFixture(t)
	if err := runReleaseMigration(f.ctx, f.registered, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	// Exercise main's environment loading and real registered wrapper against
	// the disposable database, not only the Runner extension method.
	r := f.registration
	command := exec.CommandContext(f.ctx, "go", "run", ".", "up-temporal-outbox")
	command.Env = append(os.Environ(), postgresDSNEnvironment+"="+f.owner.Config().ConnString(), migrationTimeoutEnvironment+"=30s")
	for _, binding := range [][2]string{
		{migrationPrincipalEnvironment, r.migration}, {discoveryAPIPrincipalEnvironment, r.api}, {discoveryWorkerPrincipalEnvironment, r.discovery}, {runtimeIngestPrincipalEnvironment, r.ingest}, {runtimeWorkerPrincipalEnvironment, r.runtime}, {outboxWorkerPrincipalEnvironment, r.outbox}, {runtimeGatewayPrincipalEnvironment, r.gateway}, {discoverySchedulerPrincipalEnvironment, r.scheduler}, {projectionRiskPrincipalEnvironment, r.projectionRisk}, {projectionGraphPrincipalEnvironment, r.projectionGraph}, {projectionSearchPrincipalEnvironment, r.projectionSearch},
		{runtimeCoordinatorPrincipalEnvironment, r.runtimeCoordinator}, {runtimeArchivePrincipalEnvironment, r.runtimeArchive}, {runtimeIndexPrincipalEnvironment, r.runtimeIndex}, {runtimeCorrelationPrincipalEnvironment, r.runtimeCorrelation}, {runtimeProjectionPrincipalEnvironment, r.runtimeProjection}, {gatewayControlPrincipalEnvironment, r.gatewayControl}, {securityAgentAPIPrincipalEnvironment, r.securityAgentAPI}, {securityAgentWorkerPrincipalEnvironment, r.securityAgentWorker}, {securityAgentActionPrincipalEnvironment, r.securityAgentAction},
		{redTeamWorkerPrincipalEnvironment, r.redTeamWorker}, {redTeamOutboxPrincipalEnvironment, r.redTeamOutbox}, {redTeamAdapterPrincipalEnvironment, r.redTeamAdapter}, {attackLabControllerPrincipalEnvironment, r.attackLabController}, {attackLabOutboxPrincipalEnvironment, r.attackLabOutbox}, {attackLabProxyPrincipalEnvironment, r.attackLabProxy}, {recoveryWorkerPrincipalEnvironment, r.recoveryWorker}, {recoveryOutboxPrincipalEnvironment, r.recoveryOutbox}, {policyDeploymentPrincipalEnvironment, r.policyDeployment},
	} {
		command.Env = append(command.Env, binding[0]+"="+binding[1])
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("shipped CLI failed: %v %s", err, output)
	}
	for i := 0; i < 2; i++ {
		if err := runReleaseMigration(f.ctx, f.registered, []string{"up-temporal-outbox"}); err != nil {
			t.Fatal("shipped outbox dispatch", err)
		}
		if !isForwardMigration([]string{"up-temporal-outbox"}) {
			t.Fatal("command bypassed registration")
		}
		if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-temporal-outbox"}); err != nil {
			t.Fatal("outbox registration", err)
		}
	}
	var ready bool
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_temporal65.ready($1,$2)`, migrations.ProductionTemporalOutbox().Checksum(), migrations.TemporalOutboxFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("registered command not ready", ready, err)
	}
	if version, err := f.runner.Version(f.ctx); err != nil || version != 60 {
		t.Fatal("canonical predecessor changed", version, err)
	}
	for _, mutation := range []string{`UPDATE zasp_temporal65.registration SET predecessor='ordered62'`, `ALTER TABLE zasp_security_agent_request_receipts DISABLE TRIGGER zasp_temporal65_capture`} {
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(f.ctx, mutation); err != nil {
			t.Fatal(err)
		}
		if err = tx.QueryRow(f.ctx, `SELECT zasp_temporal65.ready($1,$2)`, migrations.ProductionTemporalOutbox().Checksum(), migrations.TemporalOutboxFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatal("drift accepted", ready, err)
		}
		if err = tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	var granted bool
	if err := f.owner.QueryRow(f.ctx, `SELECT has_table_privilege('zasp_security_agent_api','zasp_temporal65.commands','UPDATE') OR has_table_privilege('zasp_security_agent_worker','zasp_temporal65.commands','UPDATE') OR has_function_privilege('zasp_security_agent_api','zasp_temporal65.ack(text,text,text,text,text)','EXECUTE')`).Scan(&granted); err != nil || granted {
		t.Fatal("runtime can bypass owner fence", granted, err)
	}
}
