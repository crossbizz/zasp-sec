package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Root composes this after the real API admission test against the same owned
// completed-invocation fixture. It runs the actual captured product, not a
// cleanup interface mock. The accepted current-ready/capture gate is mandatory.
func TestSingleTestRecoveryConnectedTemporal(t *testing.T) {
	dsn := os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_OWNER_DSN")
	if dsn == "" {
		t.Skip("reviewed successor and connected native recovery fixture required")
	}
	endpoint, namespace := os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_TEMPORAL"), os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_NAMESPACE")
	if err := singleRecoveryNativeEndpoint(endpoint, namespace); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.ConnConfig.Host) == nil || !net.ParseIP(cfg.ConnConfig.Host).IsLoopback() {
		t.Fatal("owned loopback fixture required")
	}
	owner, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("owner pool")
	}
	defer owner.Close()
	run := os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_RUN")
	if !validRecoveryProductID(run) {
		t.Fatal("original run required")
	}
	contentionApplication := singleRecoveryContentionApplication(run)
	contentionTrace := newRecoveryContentionQueryTrace()
	poolFor := func(login string) *pgxpool.Pool {
		p := cfg.Copy()
		p.ConnConfig.User = login
		p.ConnConfig.RuntimeParams["application_name"] = contentionApplication
		if login == "worker_test_compensation" {
			p.ConnConfig.Tracer = recoveryContentionPGXTracer(p.ConnConfig.Tracer, contentionTrace)
		}
		p.MaxConns = 4 // All three real callers must reach SQL, not queue for a pool slot.
		db, err := pgxpool.NewWithConfig(ctx, p)
		if err != nil {
			t.Fatal("registered fixture pool")
		}
		t.Cleanup(db.Close)
		return db
	}
	var ref orchestration.SingleTestRecoveryRef
	var raw, inputBody, manifestRaw []byte
	if err := owner.QueryRow(ctx, `SELECT zasp_temporal_single_recovery.reference(c),i.body,i.manifest FROM zasp_temporal_single_recovery.commands c JOIN zasp_temporal74.test_inputs i USING(organization_id,workspace_id,environment_id,run_id) WHERE c.run_id=$1`, run).Scan(&raw, &inputBody, &manifestRaw); err != nil || json.Unmarshal(raw, &ref) != nil {
		t.Fatal("durable API command and captured input required")
	}
	var manifest apiserver.RedTeamArtifactReference
	if json.Unmarshal(manifestRaw, &manifest) != nil {
		t.Fatal("captured input manifest")
	}
	product, journal, driver, forbidden, command, receiptCalls := newRecoveryNativeComposition(t, ctx, poolFor("worker_test_executor"), poolFor("worker_test_compensation"), poolFor("ordered_test_red_adapter"), ref.Start, inputBody, manifest)
	for _, db := range []apiserver.JSONDatabase{product.executor, product.compensation} {
		if installed, err := singleRecoveryRuntimeAvailable(ctx, db); err != nil || !installed {
			t.Fatal("reviewed native source prerequisite")
		}
	}
	if journal.Ready(ctx) != nil {
		t.Fatal("captured journal prerequisite")
	}
	recovered, err := product.SingleTestRecoveryProduct()
	if err != nil {
		t.Fatal(err)
	}
	// This fixture must enter through a real stopped, already-sent original:
	// admission has bound its immutable stop while invocation evidence is still
	// unknown. A pre-completed happy fixture cannot satisfy this regression.
	var stoppedUnknown bool
	if err = owner.QueryRow(ctx, `SELECT c.command#>>'{stop_binding,kind}'='stop' AND EXISTS(SELECT 1 FROM zasp_temporal74.invocations j JOIN zasp_temporal74.run_owners x ON(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id)=(j.organization_id,j.workspace_id,j.environment_id,j.test_run_id) WHERE x.run_id=c.run_id AND j.state='started') FROM zasp_temporal_single_recovery.commands c WHERE c.run_id=$1`, run).Scan(&stoppedUnknown); err != nil || !stoppedUnknown {
		t.Fatal("stopped unknown-debt fixture required")
	}
	debtSQL := `SELECT jsonb_build_object('unresolved',zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id),'capacity',zasp_temporal74.capacity(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,''),'reservations',(SELECT jsonb_agg(to_jsonb(p) ORDER BY attempt) FROM zasp_temporal74.provider_reservations p WHERE p.run_id=x.run_id),'budget',(SELECT to_jsonb(b) FROM public.zasp_security_agent_run_budgets b WHERE b.run_id=x.run_id),'stop',(SELECT to_jsonb(s) FROM zasp_temporal74.stops s WHERE s.run_id=x.run_id),'completion_count',(SELECT count(*) FROM zasp_temporal_single_recovery.completion_receipts c WHERE c.run_id=x.run_id)) FROM zasp_temporal74.run_owners x WHERE x.run_id=$1`
	var debtBefore, debtAfter []byte
	if err = owner.QueryRow(ctx, debtSQL, run).Scan(&debtBefore); err != nil {
		t.Fatal("debt baseline")
	}
	if err = recovered.Step(ctx, ref); !errors.Is(err, orchestration.ErrCleanupPending) {
		t.Fatal("unknown evidence did not preserve pending debt", err)
	}
	if err = owner.QueryRow(ctx, debtSQL, run).Scan(&debtAfter); err != nil || !bytes.Equal(debtBefore, debtAfter) || command.calls != 0 || forbidden.calls.Load() != 0 || driver.puts != 0 {
		t.Fatal("unknown evidence changed debt/capacity or sent IO")
	}
	identitySQL := `SELECT jsonb_build_object('command',to_jsonb(c),'owner',to_jsonb(x),'invocations',(SELECT jsonb_agg(jsonb_build_object('child',j.test_run_id,'category',j.category,'effect_key',j.effect_key,'request_digest',encode(j.request_digest,'hex'),'target_resolution',j.target_resolution) ORDER BY j.category) FROM zasp_temporal74.invocations j WHERE(j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id))) FROM zasp_temporal_single_recovery.commands c JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) WHERE c.run_id=$1`
	var identityBefore, identityAfter []byte
	if err = owner.QueryRow(ctx, identitySQL, run).Scan(&identityBefore); err != nil {
		t.Fatal("immutable identity baseline")
	}
	contend := func(pending bool) {
		t.Helper()
		phase := "settle"
		if pending {
			phase = "pending"
		}
		contentionTrace.reset(phase)
		barrier, e := owner.Begin(ctx)
		if e != nil {
			t.Fatal("contention barrier transaction")
		}
		defer func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			_ = barrier.Rollback(cleanup)
		}()
		if _, e = barrier.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, ref.Start.Ref.OrganizationID); e != nil {
			t.Fatal("contention lock")
		}
		callers := [3]func(context.Context) error{
			func(call context.Context) error {
				return contentionTrace.caller(call, phase, "cleanup", func(tagged context.Context) error {
					return product.SingleTestProduct().Cleanup(tagged, orchestration.CleanupRequest{Start: ref.Start, Reason: "workflow_cancelled"})
				})
			},
			func(call context.Context) error {
				return contentionTrace.caller(call, phase, "step", func(tagged context.Context) error {
					return recovered.Step(tagged, ref)
				})
			},
			func(call context.Context) error {
				return contentionTrace.caller(call, phase, "finish", func(tagged context.Context) error {
					raw, e := temporalQuery(tagged, product.compensation, singleRecoveryFinishSQL, ref)
					if e != nil {
						return recoveryWorkerError(e)
					}
					var result struct {
						Complete  bool                                `json:"complete"`
						Reference orchestration.SingleTestRecoveryRef `json:"reference"`
					}
					if decodeStrictWorkerJSON(raw, &result) != nil || result.Reference != ref {
						return orchestration.ErrConflict
					}
					if !result.Complete {
						return orchestration.ErrCleanupPending
					}
					return nil
				})
			},
		}
		boundary := newRecoveryContentionBoundary()
		results, e := runRecoveryContention(ctx, callers, func(wait context.Context) error {
			return waitRecoverySQLContention(wait, owner, barrier.Conn().PgConn().PID(), run, contentionApplication)
		}, barrier.Rollback, &boundary)
		contentionTrace.log(t, phase)
		t.Log(boundary.line(phase))
		settleContinuation := continueSingleRecoverySettleAfterContention(pending, ctx, boundary, results, e)
		if e != nil && !settleContinuation {
			t.Fatal("pre-settlement contention barrier or join", e)
		}
		for i, result := range results {
			if pending {
				if !errors.Is(result, orchestration.ErrCleanupPending) {
					t.Fatal("unknown-evidence caller did not remain pending", i, result)
				}
			} else if !settleContinuation && result != nil && !errors.Is(result, orchestration.ErrCleanupPending) && !errors.Is(result, orchestration.ErrUnavailable) {
				t.Fatal("first-settlement caller was not complete or retryable", i, result)
			}
		}
		if err = owner.QueryRow(ctx, identitySQL, run).Scan(&identityAfter); err != nil || !bytes.Equal(identityBefore, identityAfter) {
			t.Fatal("contention changed immutable identity")
		}
		if forbidden.calls.Load() != 0 {
			t.Fatal("contention attempted fresh provider/target authorization")
		}
	}
	// Prove all three operations contend in SQL while the debt is unknown.
	// Each must return pending without manufacturing a child or completion.
	contend(true)
	if err = owner.QueryRow(ctx, debtSQL, run).Scan(&debtAfter); err != nil || !bytes.Equal(debtBefore, debtAfter) || command.calls != 0 || driver.puts != 0 {
		t.Fatal("contended unknown evidence changed debt/capacity or sent IO")
	}
	// Record controlled late observations through the actual compensation
	// journal. These are test evidence, not real target protection claims.
	rows, err := owner.Query(ctx, `SELECT j.test_run_id,j.category,j.effect_key,encode(j.request_digest,'hex'),j.target_resolution->'binding',zasp_sa_multistep_prior.test_prompt(j.category) FROM zasp_temporal74.invocations j JOIN zasp_temporal74.run_owners x ON(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id)=(j.organization_id,j.workspace_id,j.environment_id,j.test_run_id) WHERE x.run_id=$1 AND j.state='started' ORDER BY j.category`, run)
	if err != nil {
		t.Fatal("late observation source")
	}
	type late struct {
		child, category, key, digest, input string
		binding                             redteamadapter.TargetBinding
	}
	var lateRows []late
	for rows.Next() {
		var v late
		var binding []byte
		if rows.Scan(&v.child, &v.category, &v.key, &v.digest, &binding, &v.input) != nil || json.Unmarshal(binding, &v.binding) != nil {
			rows.Close()
			t.Fatal("late observation shape")
		}
		lateRows = append(lateRows, v)
	}
	rows.Close()
	if rows.Err() != nil || len(lateRows) == 0 {
		t.Fatal("late observation roster")
	}
	scope, _ := temporalScope(ref.Start)
	protected := true
	for _, v := range lateRows {
		request := redteamadapter.JournalRequest{Invocation: redteamadapter.Invocation{Scope: scope, RunID: v.child, Category: v.category, Binding: v.binding, Input: v.input}, EffectKey: v.key, RequestDigest: v.digest}
		observation := redteamadapter.InvocationObservation{HTTPStatus: 200, ResponseDigest: strings.Repeat("a", 64), Protected: &protected, CredentialVersionDigest: strings.Repeat("b", 64)}
		if err = journal.Complete(ctx, request, 1, observation); err != nil {
			t.Fatal("native late observation recording", err)
		}
		if err = journal.Complete(ctx, request, 1, observation); err != nil {
			t.Fatal("duplicate late observation", err)
		}
	}
	var original []byte
	if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(i) ORDER BY category) FROM zasp_temporal74.invocations i WHERE test_run_id=(SELECT test_run_id FROM zasp_temporal74.run_owners WHERE run_id=$1)`, run).Scan(&original); err != nil {
		t.Fatal("native invocation baseline")
	}
	// This is the first settlement, not the settled replay below: the barrier
	// observes all three actual lock waiters and zero child/parent/completion
	// receipts before releasing the existing organization fence.
	contend(false)
	// The original workflow is deliberately absent in this fresh namespace.
	temporalClient, err := client.DialContext(ctx, client.Options{HostPort: endpoint, Namespace: namespace})
	if err != nil {
		t.Fatal("namespace client")
	}
	defer temporalClient.Close()
	observer, _ := orchestration.NewSingleTestOriginalObserver(temporalClient, 5*time.Second)
	observation, err := observer.ObserveOriginal(ctx, ref.Start)
	if err != nil || observation.Status != "absent" {
		t.Fatal("missing original history fixture")
	}
	activities := &orchestration.SingleTestRecoveryActivities{Product: recovered}
	w := worker.New(temporalClient, namespace, worker.Options{WorkerStopTimeout: 10 * time.Second})
	w.RegisterWorkflow(orchestration.SingleTestOperatorCleanupWorkflow)
	w.RegisterActivityWithOptions(activities.Step, activity.RegisterOptions{Name: "SingleOperatorCleanup"})
	if err := w.Start(); err != nil {
		t.Fatal("recovery worker")
	}
	defer w.Stop()
	defer activities.Close(ctx)
	engine, _ := orchestration.NewTemporalEngine(temporalClient, namespace, 5*time.Second)
	relay, relayObservation := observeSingleTestRecoveryRelay(product.executor, engine.StartSingleTestRecovery)
	if err := relay.RunOnce(ctx); err != nil {
		t.Log(relayObservation.summary(err))
		t.Fatal("durable command relay", err)
	}
	wid, _ := orchestration.SingleTestRecoveryWorkflowID(ref)
	if err := temporalClient.GetWorkflow(ctx, wid, "").Get(ctx, nil); err != nil {
		t.Fatal("actual cleanup workflow", err)
	}
	proofSQL := `SELECT jsonb_build_object('child',(SELECT to_jsonb(c) FROM zasp_temporal74.child_receipts c WHERE c.run_id=$1),'parent',(SELECT to_jsonb(p) FROM zasp_temporal74.parent_receipts p WHERE p.run_id=$1),'completion',(SELECT to_jsonb(c) FROM zasp_temporal_single_recovery.completion_receipts c WHERE c.run_id=$1))`
	var firstProof, repeatedProof []byte
	if err = owner.QueryRow(ctx, proofSQL, run).Scan(&firstProof); err != nil {
		t.Fatal("first committed receipt/artifact identity")
	}
	if err := engine.StartSingleTestRecovery(ctx, ref); err != nil {
		t.Fatal("same immutable command duplicate", err)
	}
	if err := recovered.Step(ctx, ref); err != nil {
		t.Fatal("receipt-safe repeated cleanup", err)
	}
	// Old and new owners can safely repeat cleanup after the late receipt. The
	// SQL parent fence, not process exclusivity, protects one completion.
	startTogether := make(chan struct{})
	results := make(chan error, 3)
	go func() {
		<-startTogether
		results <- product.SingleTestProduct().Cleanup(ctx, orchestration.CleanupRequest{Start: ref.Start, Reason: "workflow_cancelled"})
	}()
	go func() { <-startTogether; results <- recovered.Step(ctx, ref) }()
	go func() {
		<-startTogether
		_, e := temporalQuery(ctx, product.compensation, singleRecoveryFinishSQL, ref)
		results <- e
	}()
	close(startTogether)
	for n := 0; n < 3; n++ {
		if e := <-results; e != nil {
			t.Fatal("concurrent settled cleanup", e)
		}
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal_single_recovery.commands WHERE run_id=$1) AND(SELECT count(*)=1 FROM zasp_temporal_single_recovery.completion_receipts WHERE run_id=$1) AND(SELECT count(*)=1 FROM zasp_temporal74.child_receipts WHERE run_id=$1) AND(SELECT count(*)=1 FROM zasp_temporal74.parent_receipts WHERE run_id=$1) AND NOT(SELECT zasp_temporal74.unresolved(organization_id,workspace_id,environment_id,run_id) FROM zasp_temporal74.run_owners WHERE run_id=$1) AND(SELECT count(*)=1 FROM zasp_temporal_single_recovery.deliveries WHERE run_id=$1 AND accepted_at IS NOT NULL) AND(SELECT jsonb_agg(to_jsonb(i) ORDER BY category)=$2::jsonb FROM zasp_temporal74.invocations i WHERE test_run_id=(SELECT test_run_id FROM zasp_temporal74.run_owners WHERE run_id=$1))`, run, original).Scan(&exact); err != nil || !exact {
		t.Fatal("native idempotency or invocation preservation")
	}
	if err = owner.QueryRow(ctx, proofSQL, run).Scan(&repeatedProof); err != nil || !bytes.Equal(firstProof, repeatedProof) {
		t.Fatal("settled replay changed receipt or artifact identity")
	}
	var input redTeamRunnerInput
	_ = json.Unmarshal(inputBody, &input)
	// At most two contending reconstructions and one workflow retry may read
	// already-completed receipts. None may acquire a fresh send permit. The
	// immutable output is stored once even if its identical put is replayed.
	if forbidden.calls.Load() != 0 || command.calls < 1 || command.calls > 3 || receiptCalls.Load() < int32(len(input.Categories)) || receiptCalls.Load() > int32(3*len(input.Categories)) || driver.puts != 1 {
		t.Fatal("recovery created fresh target IO")
	}
	if err = owner.QueryRow(ctx, identitySQL, run).Scan(&identityAfter); err != nil || !bytes.Equal(identityBefore, identityAfter) {
		t.Fatal("final recovery changed immutable identity")
	}
	// Attack the real stored evidence in rollback-only transactions. Immutable
	// storage may reject the mutation itself; otherwise the successor validator
	// must refuse it. Neither result is called proof of a general tree adapter.
	for _, mutation := range []string{
		`UPDATE public.zasp_security_agent_runs SET last_error_code='forged' WHERE run_id=$1`,
		`UPDATE public.zasp_security_agent_runs SET state='remediated' WHERE run_id=$1`,
		`UPDATE zasp_temporal74.effects SET effect_key=effect_key||'-forged' WHERE run_id=$1`,
		`UPDATE zasp_temporal74.parent_receipts SET receipt=jsonb_set(receipt,'{reason}','"forged"') WHERE run_id=$1`,
	} {
		tx, e := owner.Begin(ctx)
		if e != nil {
			t.Fatal("negative proof transaction")
		}
		_, e = tx.Exec(ctx, mutation, run)
		if e == nil {
			var ignored []byte
			e = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_stop_evidence(organization_id,workspace_id,environment_id,run_id) FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&ignored)
		}
		_ = tx.Rollback(ctx)
		if e == nil {
			t.Fatal("forged settled successor accepted")
		}
	}
	// Even a syntactically valid foreign digest cannot write progress for the
	// retained command, nor add another completion on the native boundary.
	forged := ref
	forged.CommandDigest = strings.Repeat("0", 64)
	if err = recovered.Step(ctx, forged); err == nil {
		t.Fatal("forged command accepted")
	}
	if err = recovered.Step(ctx, ref); err != nil {
		t.Fatal("valid command damaged by forgery")
	}
	t.Log("real durable relay/Temporal/indirect captured Cleanup/native receipt; controlled target fixture, no new provider sends; authorized API readback is the final connected phase")
}

func singleRecoveryNativeEndpoint(endpoint, namespace string) error {
	host, port, err := net.SplitHostPort(endpoint)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || host != "127.0.0.1" || n < 1 || n > 65535 || strconv.Itoa(n) != port || !strings.HasPrefix(namespace, "zasp-single-recovery-") || len(namespace) <= len("zasp-single-recovery-") || len(namespace) > 80 {
		return fmt.Errorf("owned recovery Temporal endpoint required")
	}
	for _, c := range namespace {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("owned recovery namespace rejected")
		}
	}
	return nil
}
