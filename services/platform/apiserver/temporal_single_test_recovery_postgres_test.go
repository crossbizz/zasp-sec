package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This consumes a root-provisioned current-authority fixture, never creates an
// allow-valued readiness substitute. Run admit, then the worker Temporal test,
// then readback against the same fixture. No provider calls belong to this gate.
func TestSingleTestRecoveryConnectedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_OWNER_DSN")
	if dsn == "" {
		t.Skip("reviewed additive source/capture successor and owned native fixture required")
	}
	runSingleTestRecoveryConnectedPostgres(t, singleRecoveryAPIInput{DSN: dsn, Phase: os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_PHASE"), Run: os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_RUN"), ForwardRun: os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_FORWARD_RUN"), BrowserSession: os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_BROWSER_SESSION")})
}

type singleRecoveryAPIInput struct {
	DSN, Phase, Run, ForwardRun, BrowserSession string
	Observer                                    orchestration.SingleTestOriginalObserver
	Reconcile                                   func(context.Context) error
}

func singleRecoveryNativeIdentitySurfaces(identity, recovery *PostgresJSONDatabase) (*PostgresRepository, *PostgresAuthorizationResolver, error) {
	repository, err := NewPostgresRepository(identity)
	if err != nil {
		return nil, nil, err
	}
	resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(identity, recovery)
	if err != nil {
		return nil, nil, err
	}
	return repository, resolver, nil
}

func singleRecoveryNativeIdentityPoolConfig(base *pgxpool.Config, login string) *pgxpool.Config {
	identity := base.Copy()
	identity.ConnConfig.User = login
	identity.MaxConns = 2
	return identity
}

func singleRecoveryNativeProjectionPool(identity, _ *pgxpool.Pool) *pgxpool.Pool { return identity }

type singleRecoveryNativePoolDriver struct{ pool *pgxpool.Pool }

func (d *singleRecoveryNativePoolDriver) QueryRow(ctx context.Context, query string, args ...any) PostgresRow {
	return d.pool.QueryRow(ctx, query, args...)
}
func (d *singleRecoveryNativePoolDriver) Exec(ctx context.Context, query string, args ...any) error {
	_, err := d.pool.Exec(ctx, query, args...)
	return err
}
func (d *singleRecoveryNativePoolDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	return d.pool.Begin(ctx)
}
func (*singleRecoveryNativePoolDriver) Close() error { return nil }

func runSingleTestRecoveryConnectedPostgres(t *testing.T, input singleRecoveryAPIInput) {
	dsn, phase := input.DSN, input.Phase
	if phase != "admit" && phase != "readback" {
		t.Fatal("explicit native phase required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.ConnConfig.Host) == nil || !net.ParseIP(cfg.ConnConfig.Host).IsLoopback() {
		t.Fatal("owned loopback fixture required")
	}
	owner, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("owner connection")
	}
	defer owner.Close()
	run := input.Run
	if !validProductID(run) {
		t.Fatal("original run required")
	}
	var identityLogin, recoveryLogin string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM public.zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_api'`).Scan(&identityLogin); err != nil {
		t.Fatal("registered identity API principal")
	}
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM public.zasp_security_agent_principal_bindings WHERE authority_role='zasp_security_agent_api'`).Scan(&recoveryLogin); err != nil {
		t.Fatal("registered recovery API principal")
	}
	identityPool, err := pgxpool.NewWithConfig(ctx, singleRecoveryNativeIdentityPoolConfig(cfg, identityLogin))
	if err != nil {
		t.Fatal("identity API pool")
	}
	defer identityPool.Close()
	identityDatabase, _ := NewPostgresJSONDatabase(&singleRecoveryNativePoolDriver{pool: identityPool})
	if identityDatabase.RequireCurrentAuthorization() != nil {
		t.Fatal("current identity authorization")
	}
	recoveryConfig := cfg.ConnConfig.Copy()
	recoveryConfig.User = recoveryLogin
	recoveryAPI, err := pgx.ConnectConfig(ctx, recoveryConfig)
	if err != nil {
		t.Fatal("recovery API connection")
	}
	defer recoveryAPI.Close(ctx)
	requestDriver, requestDiagnostic := wrapSingleRecoveryRequestDiagnosticDriver(&authorizationConnectionDriver{conn: recoveryAPI})
	capabilityDriver, capabilityDiagnostic := wrapSingleRecoveryCapabilityDiagnosticDriver(requestDriver)
	recoveryDatabase, _ := NewPostgresJSONDatabase(capabilityDriver)
	if recoveryDatabase.RequireCurrentAuthorization() != nil {
		t.Fatal("current recovery authorization")
	}
	if available, err := recoveryDatabase.SingleTestRecoveryAvailable(ctx); err != nil || !available {
		t.Fatal("reviewed source readiness prerequisite", capabilityDiagnostic.summary())
	}
	repository, resolver, err := singleRecoveryNativeIdentitySurfaces(identityDatabase, recoveryDatabase)
	if err != nil {
		t.Fatal("current repository")
	}
	id, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: input.BrowserSession})
	if err != nil {
		t.Fatal("current fixture browser identity")
	}
	projection, err := authorization.NewPostgresProjectionRepository(singleRecoveryNativeProjectionPool(identityPool, owner))
	if err != nil {
		t.Fatal("projection reader")
	}
	revision, err := projection.Revision(ctx, id.Scope.OrganizationID().String())
	if err != nil {
		t.Fatal("current revision")
	}
	// Controlled Check result; native fence still validates the registered key,
	// revision, current browser membership and exact resolved target/version.
	revoked := false
	checker := authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: !revoked && (q.ResourceID == run || q.ResourceID == id.Scope.EnvironmentID().String()), ModelID: revision.ModelID}, nil
	})
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: revision.StoreID, ModelID: revision.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	observations := 0
	running := false
	observer := recoveryObserverFunc(func(observeCtx context.Context, q orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error) {
		observations++
		if running {
			return orchestration.SingleTestOriginalObservation{}, orchestration.ErrConflict
		}
		if input.Observer != nil {
			return input.Observer.ObserveOriginal(observeCtx, q)
		}
		wid, _ := orchestration.SingleTestWorkflowID(q.Ref)
		return orchestration.SingleTestOriginalObservation{WorkflowID: wid, Status: "absent", ObservedAt: time.Now().UTC()}, nil
	})
	authority, _ := NewSingleTestRecoveryRepository(recoveryDatabase, &singleRecoveryDiagnosticObserver{delegate: observer, diagnostic: requestDiagnostic})
	diagnosticAuthority := &singleRecoveryDiagnosticAuthority{delegate: authority, diagnostic: requestDiagnostic}
	handler, _ := NewSingleTestRecoveryHTTPHandler(diagnosticAuthority)
	request := func(op, method, body, key string, version int64) *httptest.ResponseRecorder {
		t.Helper()
		if input.Reconcile != nil {
			if err := input.Reconcile(ctx); err != nil {
				t.Fatal("controlled current projection delivery")
			}
		}
		route := RoutedOperation{OperationID: op, PathParameters: map[string]string{"id": run}}
		grant, diagnostic, err := singleRecoveryAuthorizeDiagnostic(ctx, authorizer, id, id.credentialBinding, route)
		if err != nil {
			t.Fatal("current scoped authorization", diagnostic)
		}
		r := workflowRequest(t, id, testCorrelationID, op, route.PathParameters, method, "/api/v1/security-agent-runs/"+run+"/cleanup-recovery", body)
		r = r.WithContext(context.WithValue(r.Context(), requestAuthorizationContextKey{}, grant))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("If-Match", strconv.Quote(strconv.FormatInt(version, 10)))
		r.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		requestDiagnostic.reset()
		handler.ServeHTTP(response, r)
		return response
	}
	read := request("getSingleTestCleanupRecovery", http.MethodGet, "", "", 0)
	var view SingleTestRecoveryView
	if read.Code != 200 || recoveryDecode(read.Body.Bytes(), 16384, &view) != nil || observations != 0 {
		t.Fatal("authorized original readback")
	}
	if phase == "readback" {
		if view.Status != "complete" || view.Completion == nil || view.Completion.EvidenceKind == "already_complete" {
			t.Fatal("native completion missing")
		}
		return
	}
	if view.Status != "not_requested" {
		t.Fatal("fresh recovery fixture required")
	}
	// Exercise ancestry before disclosure against actual rows. Some corruptions
	// are already impossible under immutable storage; successful mutations must
	// still be rejected by the new owner validator. Every attempt rolls back.
	for _, mutation := range []string{
		`UPDATE public.zasp_security_agent_runs SET definition_version=definition_version+1 WHERE run_id=$1`,
		`UPDATE public.zasp_security_agent_definition_versions h SET definition=jsonb_set(h.definition,'{allowed_actions}','["forged"]') FROM zasp_temporal74.run_owners x WHERE x.run_id=$1 AND(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version)`,
		`UPDATE public.zasp_security_agent_definition_versions h SET definition_digest=decode(repeat('0',64),'hex') FROM zasp_temporal74.run_owners x WHERE x.run_id=$1 AND(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version)`,
		`UPDATE zasp_temporal74.run_owners SET step_id='pid_90000000-0000-4000-8000-000000000001' WHERE run_id=$1`,
		`UPDATE zasp_temporal74.run_owners SET test_run_id='pid_90000000-0000-4000-8000-000000000002' WHERE run_id=$1`,
	} {
		tx, e := owner.Begin(ctx)
		if e != nil {
			t.Fatal("ancestry negative transaction")
		}
		_, e = tx.Exec(ctx, mutation, run)
		if e == nil {
			var ignored []byte
			e = tx.QueryRow(ctx, `SELECT to_jsonb(zasp_temporal_single_recovery.owner(jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_version',x.definition_version,'input_digest',x.input_digest))) FROM zasp_temporal74.run_owners x WHERE x.run_id=$1`, run).Scan(&ignored)
		}
		_ = tx.Rollback(ctx)
		if e == nil {
			t.Fatal("altered original ancestry accepted")
		}
	}
	// A second real, still-authorized reserved-effect fixture proves that a
	// forward decision prepared before the stop cannot cross the committed stop.
	forwardRun := input.ForwardRun
	if !validProductID(forwardRun) || forwardRun == run {
		t.Fatal("separate reserved forward-race fixture required")
	}
	originalRun := run
	run = forwardRun
	forwardViewResponse := request("getSingleTestCleanupRecovery", http.MethodGet, "", "", 0)
	var forwardView SingleTestRecoveryView
	if forwardViewResponse.Code != 200 || recoveryDecode(forwardViewResponse.Body.Bytes(), 16384, &forwardView) != nil || forwardView.Status != "not_requested" {
		t.Fatal("forward original identity")
	}
	var forwardRequest []byte
	var reserved bool
	if err = owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'step_id',x.step_id,'generation',1,'operation','start','payload','{}'::jsonb),f.state='reserved' FROM zasp_temporal74.run_owners x JOIN zasp_temporal74.effects f USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE x.run_id=$1`, run).Scan(&forwardRequest, &reserved); err != nil || !reserved {
		t.Fatal("reserved captured forward fixture")
	}
	forwardCfg := cfg.Copy()
	forwardCfg.ConnConfig.User = "worker_test_executor"
	forwardPool, err := pgxpool.NewWithConfig(ctx, forwardCfg)
	if err != nil {
		t.Fatal("forward fixture connection")
	}
	defer forwardPool.Close()
	forwardKey, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
	forwardChecker := authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: q.OrganizationID == id.Scope.OrganizationID().String(), ModelID: revision.ModelID}, nil
	})
	forwardExecutor, err := authorization.NewWorkerExecutor(forwardPool, forwardChecker, revision.StoreID, revision.ModelID, forwardKey)
	if err != nil {
		t.Fatal("forward executor")
	}
	preparedAt := time.Now()
	decision, err := forwardExecutor.Authorize(ctx, "test74.effect.start", forwardRequest)
	if err != nil {
		t.Fatal("pre-stop forward decision")
	}
	forwardBody, _ := json.Marshal(map[string]any{"definition_version": forwardView.RequestIdentity.DefinitionVersion, "input_digest": forwardView.RequestIdentity.InputDigest, "diagnostic": "history_unavailable", "stop_original": true})
	if response := request("requestSingleTestCleanupRecovery", http.MethodPost, string(forwardBody), "single-recovery-forward-race", forwardView.ParentVersion); response.Code != 202 {
		t.Fatal("forward-race stop admission", response.Code, requestDiagnostic.summary(response.Code))
	}
	// A rejection caused only by the 30-second attestation expiry would not
	// prove the committed stop fence. Keep a conservative freshness margin.
	if time.Since(preparedAt) >= 25*time.Second {
		t.Fatal("forward decision expired before race observation")
	}
	if _, err = forwardExecutor.Execute(ctx, decision); err == nil {
		t.Fatal("prepared forward proof survived committed stop")
	}
	var noSend bool
	if err = owner.QueryRow(ctx, `SELECT f.state='reserved' AND f.started_at IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.invocations j WHERE j.test_run_id=x.test_run_id) AND (SELECT count(*)=1 FROM zasp_temporal_single_recovery.commands c WHERE c.run_id=x.run_id) FROM zasp_temporal74.run_owners x JOIN zasp_temporal74.effects f USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE x.run_id=$1`, run).Scan(&noSend); err != nil || !noSend {
		t.Fatal("stop race created a send or duplicate command")
	}
	run = originalRun
	// These are real two-session lock regressions, not simulated repository
	// errors. The API keeps its current fence while refusing inverse waits.
	for _, lockSQL := range []string{
		`SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||organization_id,0)) FROM public.zasp_security_agent_runs WHERE run_id=$1`,
		`SELECT run_id FROM public.zasp_security_agent_runs WHERE run_id=$1 FOR SHARE`,
	} {
		blocker, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal("lock fixture")
		}
		if _, err = blocker.Exec(ctx, lockSQL, run); err != nil {
			_ = blocker.Rollback(ctx)
			t.Fatal("lock prerequisite")
		}
		started := time.Now()
		busy := request("getSingleTestCleanupRecovery", http.MethodGet, "", "", 0)
		_ = blocker.Rollback(ctx)
		if busy.Code != http.StatusServiceUnavailable || time.Since(started) > 5*time.Second {
			t.Fatal("fenced read waited in inverse lock order", busy.Code)
		}
	}
	body, _ := json.Marshal(map[string]any{"definition_version": view.RequestIdentity.DefinitionVersion, "input_digest": view.RequestIdentity.InputDigest, "diagnostic": "history_unavailable", "stop_original": true})
	running = true
	if response := request("requestSingleTestCleanupRecovery", http.MethodPost, string(body), "single-recovery-native-running", view.ParentVersion); response.Code != 409 {
		t.Fatal("running original admitted")
	}
	running = false
	if response := request("requestSingleTestCleanupRecovery", http.MethodPost, string(body), "single-recovery-native-stale", view.ParentVersion+1); response.Code != 409 {
		t.Fatal("stale version admitted")
	}
	foreign := strings.Replace(string(body), view.RequestIdentity.InputDigest, strings.Repeat("0", 64), 1)
	if response := request("requestSingleTestCleanupRecovery", http.MethodPost, foreign, "single-recovery-native-digest", view.ParentVersion); response.Code < 400 {
		t.Fatal("substituted digest admitted")
	}
	accepted := request("requestSingleTestCleanupRecovery", http.MethodPost, string(body), "single-recovery-native-command", view.ParentVersion)
	if accepted.Code != 202 {
		t.Fatal("native stop/command acceptance", accepted.Code)
	}
	count := observations
	if replay := request("requestSingleTestCleanupRecovery", http.MethodPost, string(body), "single-recovery-native-command", view.ParentVersion); replay.Code != 200 || observations != count {
		t.Fatal("duplicate replay changed command or described original")
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal_single_recovery.commands WHERE run_id=$1) AND(SELECT count(*)=1 FROM zasp_temporal_single_recovery.deliveries WHERE run_id=$1 AND accepted_at IS NULL) AND(SELECT count(*)=0 FROM zasp_temporal_single_recovery.completion_receipts WHERE run_id=$1) AND(SELECT state='cancelled' FROM public.zasp_security_agent_runs WHERE run_id=$1)`, run).Scan(&exact); err != nil || !exact {
		t.Fatal("native durable stop/outbox cardinality")
	}
	// Obtain a genuine scoped Check before revocation, then make its consuming
	// SQL fence wait behind that uncommitted membership change. It must reread
	// after the wait, refuse disclosure, and leave the command untouched.
	route := RoutedOperation{OperationID: "getSingleTestCleanupRecovery", PathParameters: map[string]string{"id": run}}
	grant, err := authorizer.Authorize(ctx, id, id.credentialBinding, route)
	if err != nil {
		t.Fatal("pre-revocation Check")
	}
	blocker, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal("revocation transaction")
	}
	defer blocker.Rollback(context.Background())
	if _, err = blocker.Exec(ctx, `UPDATE public.zasp_identity_memberships SET active=false WHERE(organization_id,principal_id)=($1,$2)`, id.Scope.OrganizationID().String(), id.PrincipalID.String()); err != nil {
		t.Fatal("native revocation")
	}
	r := workflowRequest(t, id, testCorrelationID, route.OperationID, route.PathParameters, http.MethodGet, "/api/v1/security-agent-runs/"+run+"/cleanup-recovery", "")
	r = r.WithContext(context.WithValue(r.Context(), requestAuthorizationContextKey{}, grant))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { response := httptest.NewRecorder(); handler.ServeHTTP(response, r); done <- response }()
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	waiting := false
	for waitCtx.Err() == nil {
		if err = owner.QueryRow(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, recoveryAPI.PgConn().PID()).Scan(&waiting); err != nil {
			break
		}
		if waiting {
			break
		}
		select {
		case <-waitCtx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	waitCancel()
	if !waiting {
		_ = blocker.Rollback(ctx)
		<-done
		t.Fatal("revocation wait not observed")
	}
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal("revocation commit")
	}
	denied := <-done
	if denied.Code < 400 || strings.Contains(denied.Body.String(), view.RequestIdentity.InputDigest) {
		t.Fatal("stale Check disclosed original identity", denied.Code)
	}
	// The fixture is owned; restore only the one membership changed above.
	if _, err = owner.Exec(ctx, `UPDATE public.zasp_identity_memberships SET active=true WHERE(organization_id,principal_id)=($1,$2)`, id.Scope.OrganizationID().String(), id.PrincipalID.String()); err != nil {
		t.Fatal("fixture membership restoration")
	}
	revoked = true
	if _, err := authorizer.Authorize(ctx, id, id.credentialBinding, RoutedOperation{OperationID: "getSingleTestCleanupRecovery", PathParameters: map[string]string{"id": run}}); err == nil {
		t.Fatal("revoked read exposed identity")
	}
	t.Log("actual HTTP/current native SQL; controlled Check and absent-history observation; real Temporal and cleanup remain the separate connected worker phase")
}
