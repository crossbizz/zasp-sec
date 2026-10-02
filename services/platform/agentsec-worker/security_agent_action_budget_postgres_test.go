package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This instrument delays delivery only, preserving actual SQL and errors.
// It observes a heartbeat after Store has committed, before process sees stop.
type actionBudgetCommittedAuthority struct {
	*apiserver.SecurityAgentActionRepository
	committed, heartbeated                         chan struct{}
	heartbeatOnce                                  sync.Once
	heartbeats, heartbeatFailures, reads, finishes atomic.Int32
	lastStoreErr, lastHeartbeatErr                 error
	heartbeatEntered                               chan struct{}
	enteredOnce                                    sync.Once
	unboundedHeartbeats                            atomic.Int32
}

func (a *actionBudgetCommittedAuthority) StoreTemporaryPolicyTarget(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, worker, lease string, envelope apiserver.TemporaryPolicyTargetEnvelope) error {
	err := a.SecurityAgentActionRepository.StoreTemporaryPolicyTarget(ctx, claim, worker, lease, envelope)
	a.lastStoreErr = err
	if a.committed != nil {
		close(a.committed)
		if errors.Is(err, apiserver.ErrSecurityAgentBudgetStopped) {
			waitFor := a.heartbeated
			if a.heartbeatEntered != nil {
				waitFor = a.heartbeatEntered
			}
			select {
			case <-waitFor:
			case <-ctx.Done():
			}
		}
	}
	return err
}

func (a *actionBudgetCommittedAuthority) HeartbeatTemporaryPolicyEffect(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, worker, lease string, seconds int) error {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
		a.unboundedHeartbeats.Add(1)
	}
	if a.committed != nil {
		select {
		case <-a.committed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if a.heartbeatEntered != nil {
		a.enteredOnce.Do(func() { close(a.heartbeatEntered) })
		// Model an in-flight heartbeat whose database work finishes after Store
		// returns. Cancellation must not manufacture failure of a committed stop.
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
		}
	}
	err := a.SecurityAgentActionRepository.HeartbeatTemporaryPolicyEffect(ctx, claim, worker, lease, seconds)
	a.lastHeartbeatErr = err
	a.heartbeats.Add(1)
	if err != nil {
		a.heartbeatFailures.Add(1)
	}
	if a.heartbeated != nil {
		a.heartbeatOnce.Do(func() { close(a.heartbeated) })
	}
	return err
}

func (a *actionBudgetCommittedAuthority) ReadTemporaryPolicyTarget(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, target apiserver.TemporaryPolicyTarget) (apiserver.TemporaryPolicyTargetEnvelope, error) {
	a.reads.Add(1)
	return a.SecurityAgentActionRepository.ReadTemporaryPolicyTarget(ctx, claim, target)
}

func (a *actionBudgetCommittedAuthority) FinishTemporaryPolicyEffect(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, worker, lease, digest, outcome, audit string) (apiserver.TemporaryPolicyFinishResult, error) {
	a.finishes.Add(1)
	return a.SecurityAgentActionRepository.FinishTemporaryPolicyEffect(ctx, claim, worker, lease, digest, outcome, audit)
}

func TestSecurityAgentActionBudgetOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_ACTION_BUDGET_TEST_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned action budget database")
	}
	mode := os.Getenv("ZASP_ACTION_BUDGET_TEST_MODE")
	if mode != "expired" && mode != "fresh" && mode != "heartbeat" && mode != "inflight_heartbeat" {
		t.Fatal("unknown scenario")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid owned database configuration")
	}
	local := func(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
	if !local(config.Host) || config.User != "zasp_e2e" || config.Database != "postgres" {
		t.Fatal("requires owned loopback fixture")
	}
	for _, fallback := range config.Fallbacks {
		if !local(fallback.Host) {
			t.Fatal("nonlocal fallback refused")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	var version int64
	if err := owner.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&version); err != nil || version != 53 {
		t.Fatalf("composed action worker requires registered release53: version=%d err=%v", version, err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE ROLE budget_action_composed_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`)
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_security_agent_register_action_principal(session_user,'budget_action_composed_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("register=%v err=%v", ready, err)
	}
	databaseFor := func(user string) apiserver.JSONDatabase {
		t.Helper()
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.User(user)
		return combinedE2ERecoveryDatabase(t, ctx, u.String())
	}
	plannerDatabase := databaseFor("security_agent_v33_worker_login")
	planner, err := apiserver.NewSecurityAgentWorkerRepository(plannerDatabase)
	if err != nil {
		t.Fatal(err)
	}
	actionDatabase := databaseFor("budget_action_composed_login")
	action, err := apiserver.NewSecurityAgentActionRepository(actionDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if err := planner.Ready(ctx); err != nil {
		t.Fatal("migrated planner readiness", err)
	}
	if err := action.Ready(ctx); err != nil {
		t.Fatal("migrated action readiness", err)
	}
	const org = "pid_6a000001-0000-4000-8000-000000000001"
	const ws = "pid_6a000002-0000-4000-8000-000000000002"
	const env = "pid_6a000003-0000-4000-8000-000000000003"
	const device = "pid_6a000060-0000-4000-8000-000000000060"
	const enrollment = "pid_6a000061-0000-4000-8000-000000000061"
	const credential = "pid_6a000062-0000-4000-8000-000000000062"
	exec(`UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, org)
	exec(`INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Budget test gateway','active')`, org, ws, env, device)
	exec(`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,'runtime-gateway-enroll',decode(repeat('01',16),'hex'),decode(repeat('02',32),'hex'),clock_timestamp()+interval '1 hour')`, org, ws, env, enrollment, device)
	exec(`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$5,$6,decode(repeat('03',32),'hex'),'runtime-gateway','ref:gateway/public/gateway-device-key-01',decode(repeat('04',32),'hex'),clock_timestamp()+interval '1 hour',1,1,'gateway-device-key-01','Ed25519',clock_timestamp())`, org, ws, env, credential, device, enrollment)
	const worker, lease = "budget-composed-planner", "budget-composed-planner-lease"
	if count, err := planner.ScheduleSecurityAgentTriggers(ctx, worker, 1); err != nil || count != 1 {
		t.Fatalf("schedule=%d err=%v", count, err)
	}
	claimRun := func() apiserver.SecurityAgentRunClaim {
		t.Helper()
		claims, err := planner.ClaimSecurityAgentRuns(ctx, worker, lease, 60, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claims=%d err=%v", len(claims), err)
		}
		return claims[0]
	}
	current := claimRun()
	if result, err := planner.PrepareSecurityAgentRun(ctx, current, worker, lease, "pid_6a000030-0000-4000-8000-000000000030", time.Now().UTC().Add(10*time.Minute), "pid_6a000031-0000-4000-8000-000000000031", "pid_6a000032-0000-4000-8000-000000000032"); err != nil || result.State != "waiting_approval" {
		t.Fatalf("prepare=%+v err=%v", result, err)
	}
	// Fixture approval is not fresh-auth API acceptance.
	exec(`UPDATE zasp_security_agent_approvals SET state='approved',approver_id='pid_6a000033-0000-4000-8000-000000000033',fresh_auth_at=clock_timestamp(),decided_at=clock_timestamp(),version=version+1 WHERE organization_id=$1`, org)
	exec(`UPDATE zasp_security_agent_steps SET state='authorized',version=version+1 WHERE organization_id=$1`, org)
	exec(`UPDATE zasp_security_agent_runs SET state='queued',version=version+1 WHERE organization_id=$1`, org)
	current = claimRun()
	if result, err := planner.ExecuteSecurityAgentRun(ctx, current, worker, lease, "pid_6a000034-0000-4000-8000-000000000034", "pid_6a000035-0000-4000-8000-000000000035"); err != nil || result.State != "running" {
		t.Fatalf("dispatch=%+v err=%v", result, err)
	}
	const actionWorker, actionLease = "budget-composed-action", "budget-composed-action-lease"
	effects, err := action.ClaimTemporaryPolicyEffects(ctx, actionWorker, actionLease, 60, 1)
	if err != nil || len(effects) != 1 || effects[0].Phase != "apply" || len(effects[0].Targets) != 1 {
		t.Fatalf("effects=%+v err=%v", effects, err)
	}
	if mode != "fresh" {
		exec(`UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, org)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := 0
	instrument := &actionBudgetCommittedAuthority{SecurityAgentActionRepository: action}
	if mode == "heartbeat" || mode == "inflight_heartbeat" {
		instrument.committed = make(chan struct{})
		instrument.heartbeated = make(chan struct{})
	}
	if mode == "inflight_heartbeat" {
		instrument.heartbeatEntered = make(chan struct{})
	}
	var generationBefore, generationAfter int64
	if err := owner.QueryRow(ctx, `SELECT sum(desired_generation)::bigint FROM zasp_policy_deployment_work WHERE organization_id=$1`, org).Scan(&generationBefore); err != nil {
		t.Fatal(err)
	}
	processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{
		Authority: instrument, WorkerID: actionWorker, LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, KeyID: "gateway-key-01", PrivateKey: key,
		Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return actionLease, nil }, NewProductID: func() (string, error) { ids++; id, err := domain.NewProductID(); return id.String(), err },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	err = processor.process(ctx, effects[0], actionLease)
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	if mode != "fresh" && (err != nil || ids != 0 || instrument.reads.Load() != 0 || instrument.finishes.Load() != 0) {
		t.Fatalf("stopped processor err=%v ids=%d store=%v heartbeat=%v heartbeats=%d failures=%d reads=%d finishes=%d", err, ids, instrument.lastStoreErr, instrument.lastHeartbeatErr, instrument.heartbeats.Load(), instrument.heartbeatFailures.Load(), instrument.reads.Load(), instrument.finishes.Load())
	}
	// No deployment worker runs in this fixture. Fresh apply must enqueue and
	// reach finish, whose lack of delivered generation remains a real failure.
	if mode == "fresh" && (err != errWorkerExecution || ids != 2 || instrument.reads.Load() != 1 || instrument.finishes.Load() < 1) {
		t.Fatalf("fresh processor err=%v ids=%d", err, ids)
	}
	if (mode == "heartbeat" || mode == "inflight_heartbeat") && (instrument.heartbeats.Load() < 1 || instrument.heartbeatFailures.Load() != 0) {
		t.Fatalf("post-commit heartbeats=%d failures=%d", instrument.heartbeats.Load(), instrument.heartbeatFailures.Load())
	}
	if mode == "inflight_heartbeat" && instrument.unboundedHeartbeats.Load() != 0 {
		t.Fatal("in-flight heartbeat join lacks its own bounded context")
	}
	if err := owner.QueryRow(ctx, `SELECT sum(desired_generation)::bigint FROM zasp_policy_deployment_work WHERE organization_id=$1`, org).Scan(&generationAfter); err != nil {
		t.Fatal(err)
	}
	wantDelta := int64(0)
	if mode == "fresh" {
		wantDelta = 1
	}
	if generationAfter-generationBefore != wantDelta {
		t.Fatalf("generation=%d->%d want delta=%d", generationBefore, generationAfter, wantDelta)
	}
	t.Logf("owned action processor joined: mode=%s ids=%d heartbeats=%d heartbeat_failures=%d reads=%d finishes=%d generation=%d->%d", mode, ids, instrument.heartbeats.Load(), instrument.heartbeatFailures.Load(), instrument.reads.Load(), instrument.finishes.Load(), generationBefore, generationAfter)
}
