package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// The migration parent owns PostgreSQL and admission history. This child adds
// the actual checked HTTP API, official FGA projection, and worker consumer.
func TestP7Discovery72CurrentAPIAndWorker(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_DISCOVERY_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned migration parent required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	var o, w, e, p, integration, apiLogin, outbox string
	if err = owner.QueryRow(ctx, `SELECT organization_id,workspace_id,environment_id,grantor_id,integration_id FROM zasp_authorization80_worker.discovery_associations WHERE job_id='pid_72008005-0000-4000-8000-000000000005'`).Scan(&o, &w, &e, &p, &integration); err != nil {
		t.Fatal(err)
	}
	for role, target := range map[string]*string{"zasp_discovery_api": &apiLogin, "zasp_outbox_worker": &outbox} {
		if err = owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role=$1`, role).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	client, pins := newAuthorizationProjectionFGA(t, func(next http.RoundTripper) http.RoundTripper {
		return discoveryProjectionHTTPDiagnostic{t: t, next: next}
	})
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.User = outbox
	pc.ConnConfig.Tracer = discoveryProjectionSQLDiagnostic{t: t}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, err := authorization.NewPostgresProjectionRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, o, pins.StoreID, pins.ModelID); err != nil {
		t.Fatal(err)
	}
	reconcile := func() {
		t.Helper()
		if result, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !result.Applied {
			t.Fatalf("discovery projection applied=%t error=%v", result.Applied, err)
		}
	}
	human := authorizationFixtureAttestor(t)
	if _, err = owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, human.Version(), human.Verifier()); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []authorization.WorkerPurpose{authorization.WorkerForward, authorization.CapturedCompensation} {
		seed := byte(41)
		if purpose == authorization.CapturedCompensation {
			seed = 73
		}
		key, _ := authorization.NewWorkerKey(purpose, bytes.Repeat([]byte{seed}, 32))
		if _, err = owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(purpose), key.Version(), key.Verifier()); err != nil {
			t.Fatal(err)
		}
	}
	schedulePhase := os.Getenv("ZASP_P7_DISCOVERY_SCHEDULE_PHASE")
	if schedulePhase != "" && schedulePhase != "1" && schedulePhase != "2" {
		t.Fatal("unknown owned schedule phase")
	}
	sessionToken, sessionID := "discovery72-owned-session", "session-discovery72-owned"
	if schedulePhase != "" {
		sessionToken += "-schedule-" + schedulePhase
		sessionID += "-schedule-" + schedulePhase
	}
	if _, err = owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest($5::text,'sha256'),$6,$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e, sessionToken, sessionID); err != nil {
		t.Fatal(err)
	}
	apiCfg := cfg.Copy()
	apiCfg.User = apiLogin
	api, err := pgx.ConnectConfig(ctx, apiCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	driver := &discoveryHumanDriver{authorizationConnectionDriver: authorizationConnectionDriver{conn: api}, t: t, key: human}
	db, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: sessionToken})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := NewDiscoveryRepositoryForAuthority(db, DiscoveryDatabaseAuthorityAPI)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewDiscoveryPublicHTTPHandler(discovery, bytes.Repeat([]byte{1}, 32), DiscoveryPublicHandlerConfig{ParserVersion: "parser_v1", ToolVersion: "tool_v1", NewProductID: newWorkflowProductID})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewPostgresAuthorizationResolver(db)
	if err != nil {
		t.Fatal(err)
	}
	var operations []Operation
	for _, id := range []string{"syncIntegration", "putIntegrationSchedule", "deleteIntegrationSchedule"} {
		policy, _ := authorization.LookupOperation(id)
		operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: id, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: human}
	call := func(operation, key, body string, version int64) *httptest.ResponseRecorder {
		t.Helper()
		policy, _ := authorization.LookupOperation(operation)
		path := strings.ReplaceAll(policy.Path, "{id}", integration)
		r := httptest.NewRequest(policy.Method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("If-Match", fmt.Sprintf(`"%d"`, version))
		r.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		r.Header.Set("Origin", "https://console.example")
		r.Header.Set("X-CSRF-Token", identity.CSRFToken)
		r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: sessionToken})
		current := context.WithValue(ctx, identityContextKey{}, identity)
		current = context.WithValue(current, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
		current = context.WithValue(current, correlationContextKey{}, integrationClientCorrelation(key))
		out := httptest.NewRecorder()
		router.ServeHTTP(out, r.WithContext(current))
		return out
	}
	requestForKey := func(key string) json.RawMessage {
		t.Helper()
		var request json.RawMessage
		if err = owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'job_id',r.job_id,'integration_id',r.integration_id,'input_digest',encode(r.request_digest,'hex'),'deadline',r.deadline,'grantor_id',a.grantor_id) FROM zasp_temporal72.runs r JOIN zasp_authorization80_worker.discovery_associations a USING(organization_id,workspace_id,environment_id,job_id) JOIN zasp_discovery_syncs s ON(s.organization_id,s.workspace_id,s.environment_id,s.id)=(r.organization_id,r.workspace_id,r.environment_id,r.sync_id) WHERE s.idempotency_key=$1`, key).Scan(&request); err != nil {
			t.Fatal(err)
		}
		return request
	}
	runWorker := func(name string, request json.RawMessage) {
		t.Helper()
		rawPins, _ := json.Marshal(pins)
		childPackage := "./agentsec-worker"
		if name == "TestP7Discovery72DirectNativeAuthorityExpiry" {
			childPackage = "./authorization"
		}
		child := exec.CommandContext(ctx, "go", "test", childPackage, "-run", "^"+name+"$", "-count=1", "-v", "-timeout=6m")
		child.Dir = ".."
		child.Env = append(os.Environ(), "ZASP_P7_DISCOVERY_OWNER_DSN="+dsn, "ZASP_P7_DISCOVERY_FGA_CONFIG="+string(rawPins), "ZASP_P7_DISCOVERY_REQUEST="+string(request))
		output, childErr := child.CombinedOutput()
		t.Log(string(output))
		if childErr != nil || !strings.Contains(string(output), "--- PASS: "+name) {
			t.Fatal("discovery worker consumer", name, childErr)
		}
	}
	reconcile()
	// Verify every real constructor dependency before the human contention and
	// expiry matrix. This retained capture is fixture input, not HTTP evidence.
	runWorker("TestP7Discovery72ProductMachinePreflight", requestForKey("worker-discovery-manual-0001"))
	if os.Getenv("ZASP_P7_DISCOVERY_BOUNDARIES_ONLY") == "1" {
		for _, boundary := range []struct{ name, key string }{
			{"TestP7Discovery72PerSendRevokeNative", "discovery72-boundary-denied-0001"},
			{"TestP7Discovery72LostResponseNative", "discovery72-boundary-unknown-0001"},
		} {
			if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2`, o, p); err != nil {
				t.Fatal(err)
			}
			reconcile()
			admitted := call("syncIntegration", boundary.key, `{}`, 1)
			if admitted.Code != http.StatusAccepted {
				t.Fatalf("boundary admission %s: %d %s", boundary.name, admitted.Code, admitted.Body.String())
			}
			reconcile()
			runWorker(boundary.name, requestForKey(boundary.key))
		}
		return
	}
	if schedulePhase != "" {
		discovery72ScheduledPhase(t, ctx, owner, schedulePhase, o, w, e, p, integration, call, reconcile, runWorker, requestForKey)
		return
	}
	if os.Getenv("ZASP_P7_DISCOVERY_LOCK_WAIT") == "1" || os.Getenv("ZASP_P7_DISCOVERY_EXPIRY_ONLY") == "1" {
		runWorker("TestP7Discovery72ProofLockWaitNative", requestForKey("worker-discovery-manual-0001"))
	}
	if os.Getenv("ZASP_P7_DISCOVERY_EXPIRY_ONLY") == "1" || os.Getenv("ZASP_P7_DISCOVERY_DIRECT_NATIVE_ONLY") == "1" {
		// Persist expiry before admission; capture must derive it from the real
		// credential. Never alter immutable authorization association rows.
		if _, err = owner.Exec(ctx, `INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,expires_at) VALUES($1,$2,$3,'pid_72008025-0000-4000-8000-000000000025',$4,'aws','aws_external_id','ref:aws/external-id/customer-0001',1,clock_timestamp()+interval '120 seconds')`, o, w, e, integration); err != nil {
			t.Fatal("owned expiring credential prerequisite", err)
		}
		reconcile()
		admitted := call("syncIntegration", "discovery72-http-expiry-0001", `{}`, 1)
		if admitted.Code != http.StatusAccepted {
			t.Fatalf("checked expiry admission=%d body=%s", admitted.Code, admitted.Body.String())
		}
		reconcile()
		consumer := "TestP7Discovery72AuthorityLockWaitNative"
		if os.Getenv("ZASP_P7_DISCOVERY_DIRECT_NATIVE_ONLY") == "1" {
			consumer = "TestP7Discovery72DirectNativeAuthorityExpiry"
		}
		runWorker(consumer, requestForKey("discovery72-http-expiry-0001"))
		return
	}
	for _, mode := range []string{"wrong-actor", "wrong-target", "wrong-operation", "forged-marker", "raw-audit-capture", "rollback-after-mutation"} {
		driver.mode, driver.nativeCode, driver.nativeSuccess = mode, "", false
		key := "discovery72-http-denied-" + mode
		denied := call("syncIntegration", key, `{}`, 1)
		if denied.Code < 400 || mode != "rollback-after-mutation" && driver.nativeCode != "42501" || mode == "rollback-after-mutation" && !driver.nativeSuccess {
			t.Fatalf("native human control %s: status=%d SQLSTATE=%s", mode, denied.Code, driver.nativeCode)
		}
		var residue int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_idempotency WHERE idempotency_key=$1)+(SELECT count(*) FROM zasp_discovery_syncs WHERE idempotency_key=$1)+(SELECT count(*) FROM zasp_workflow_audit WHERE audit_id=$2)`, key, driver.auditID).Scan(&residue); err != nil || residue != 0 {
			t.Fatal("human rejection/rollback left capture or receipt", mode, residue, err)
		}
	}
	driver.mode = ""
	// A real checked schedule update holds org first. While its transaction is
	// paused after fence, a real registered scheduler must wait on that org,
	// leaving the schedule free for the HTTP mutation to finish.
	enabled := call("putIntegrationSchedule", "discovery72-schedule-enabled-0001", `{"cadence_seconds":300,"state":"enabled"}`, 2)
	if enabled.Code != http.StatusOK {
		t.Fatalf("checked schedule enable=%d body=%s", enabled.Code, enabled.Body.String())
	}
	reconcile()
	var scheduleID, schedulerLogin string
	var scheduleVersion int64
	var nominal time.Time
	if err := owner.QueryRow(ctx, `SELECT id,version,anchor FROM zasp_temporal72.schedules WHERE (organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4)`, o, w, e, integration).Scan(&scheduleID, &scheduleVersion, &nominal); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_temporal72.principals WHERE authority_role='zasp_discovery_scheduler'`).Scan(&schedulerLogin); err != nil {
		t.Fatal(err)
	}
	schedulerConfig := cfg.Copy()
	schedulerConfig.User = schedulerLogin
	scheduler, err := pgx.ConnectConfig(ctx, schedulerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Close(context.Background())
	scheduledDone := make(chan error, 1)
	driver.beforeNative = func(ctx context.Context, _ pgx.Tx) error {
		go func() {
			var response json.RawMessage
			scheduledDone <- scheduler.QueryRow(ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,$6,$7)`, o, w, e, scheduleID, integration, scheduleVersion, nominal).Scan(&response)
		}()
		discoveryWaitLock(t, ctx, owner, int32(scheduler.PgConn().PID()), "transactionid")
		return nil
	}
	disabled := call("putIntegrationSchedule", "discovery72-schedule-disabled-0001", `{"cadence_seconds":300,"state":"disabled"}`, scheduleVersion)
	if disabled.Code != http.StatusOK {
		t.Fatalf("contended schedule update=%d body=%s", disabled.Code, disabled.Body.String())
	}
	var scheduledError *pgconn.PgError
	if err := <-scheduledDone; !errors.As(err, &scheduledError) || scheduledError.Code != "42501" {
		t.Fatal("scheduler missed changed version after org wait", err)
	}
	reconcile()
	first := call("syncIntegration", "discovery72-http-manual-0001", `{}`, 1)
	if first.Code != http.StatusAccepted {
		t.Fatalf("checked manual admission status=%d body=%s", first.Code, first.Body.String())
	}
	reconcile()
	replay := call("syncIntegration", "discovery72-http-manual-0001", `{}`, 1)
	if replay.Code != http.StatusAccepted || !bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatalf("HTTP replay status=%d equal=%t", replay.Code, bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()))
	}
	// Hold the original replay advisory lock after the real checked request
	// has been signed. The test shortens only that genuine proof's lifetime;
	// native fence and invocation entry still run normally before the wait.
	waitTx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer waitTx.Rollback(context.Background())
	if _, err = waitTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1::text,$2::text,$3::text,$4::text,'syncIntegration','discovery72-http-manual-0001'),0))`, o, w, e, p); err != nil {
		t.Fatal(err)
	}
	driver.mode, driver.nativeCode, driver.shortExpiry = "expiry-replay", "", make(chan time.Time, 1)
	replayDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { replayDone <- call("syncIntegration", "discovery72-http-manual-0001", `{}`, 1) }()
	var expires time.Time
	select {
	case expires = <-driver.shortExpiry:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	discoveryWaitLock(t, ctx, waitTx, int32(api.PgConn().PID()), "advisory")
	if delay := time.Until(expires.Add(100 * time.Millisecond)); delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := waitTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	expired := <-replayDone
	if expired.Code < 400 || driver.nativeCode != "42501" {
		t.Fatalf("expired replay escaped post-wait fence: status=%d code=%s", expired.Code, driver.nativeCode)
	}
	driver.mode = ""
	validReplay := call("syncIntegration", "discovery72-http-manual-0001", `{}`, 1)
	if validReplay.Code != http.StatusAccepted || !bytes.Equal(first.Body.Bytes(), validReplay.Body.Bytes()) {
		t.Fatal("expired replay changed the original immutable receipt")
	}
	runWorker("TestP7Discovery72ProductMachineNative", requestForKey("discovery72-http-manual-0001"))
}

// These faults enter only after the actual HTTP authorizer and Go statement
// selector. The registered API then consumes its real sealed SQL context.
type discoveryHumanDriver struct {
	authorizationConnectionDriver
	t                         *testing.T
	key                       *authorization.AttestationKey
	mode, nativeCode, auditID string
	nativeSuccess             bool
	beforeNative              func(context.Context, pgx.Tx) error
	shortExpiry               chan time.Time
}

func (d *discoveryHumanDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	return &discoveryHumanTx{Tx: tx, driver: d}, nil
}

type discoveryHumanTx struct {
	pgx.Tx
	driver *discoveryHumanDriver
}

func (tx *discoveryHumanTx) Exec(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	if tx.driver.mode == "expiry-replay" && q == `SELECT zasp_authorization80.fence($1::text)` {
		var envelope struct {
			Body []byte `json:"body"`
		}
		var claims map[string]json.RawMessage
		if json.Unmarshal([]byte(args[0].(string)), &envelope) != nil || json.Unmarshal(envelope.Body, &claims) != nil {
			return pgconn.CommandTag{}, errors.New("owned proof decode")
		}
		expires := time.Now().Add(12 * time.Second)
		claims["expires_at"], _ = json.Marshal(expires.UnixMilli())
		payload, _ := json.Marshal(claims)
		proof, err := tx.driver.key.Sign(payload)
		if err != nil {
			return pgconn.CommandTag{}, err
		}
		args = []any{string(proof)}
		tx.driver.shortExpiry <- expires
	}
	return tx.Tx.Exec(ctx, q, args...)
}

func (tx *discoveryHumanTx) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	if strings.HasPrefix(q, "SELECT zasp_temporal72.public_") {
		if before := tx.driver.beforeNative; before != nil {
			tx.driver.beforeNative = nil
			if err := before(ctx, tx.Tx); err != nil {
				return discoveryHumanErrorRow{err}
			}
		}
		args = append([]any(nil), args...)
		if len(args) == 16 {
			tx.driver.auditID, _ = args[13].(string)
		}
		switch tx.driver.mode {
		case "wrong-actor":
			args[3] = "pid_72008099-0000-4000-8000-000000000099"
		case "wrong-target":
			args[4] = "pid_72008099-0000-4000-8000-000000000099"
		case "wrong-operation":
			q = `SELECT zasp_temporal72.public_delete_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
			args = append(args[:7], args[13:]...)
		case "forged-marker":
			if _, err := tx.Tx.Exec(ctx, `SELECT set_config('zasp.discovery72_human','{"domain":"discovery72-human-v1","stage":"recording"}',true),set_config('zasp.discovery72_human_seal','',true)`); err != nil {
				return discoveryHumanErrorRow{err}
			}
		case "raw-audit-capture":
			// Same legitimate sealed scope/op, but no native invocation marker.
			// The public writer cannot manufacture a live delegation from it.
			q = `SELECT public.zasp_execution_record_public_mutation($1,$2,$3,$4,'syncIntegration',$5,jsonb_build_object('scope',jsonb_build_object('organization_id',$1::text,'workspace_id',$2::text,'environment_id',$3::text),'integration_id',$6::text,'expected_version',1,'idempotency_key',$5::text,'body','{}'::jsonb),jsonb_build_object('id',$7::text,'integration_id',$6::text),'integration_sync',$7,1,$8,$9,'')`
			args = []any{args[0], args[1], args[2], args[3], args[5], args[4], args[7], args[13], args[14]}
		}
		return discoveryHumanRow{Row: tx.Tx.QueryRow(ctx, q, args...), driver: tx.driver}
	}
	return tx.Tx.QueryRow(ctx, q, args...)
}

type discoveryHumanErrorRow struct{ err error }

func (r discoveryHumanErrorRow) Scan(...any) error { return r.err }

type discoveryHumanRow struct {
	pgx.Row
	driver *discoveryHumanDriver
}

func (r discoveryHumanRow) Scan(values ...any) error {
	err := r.Row.Scan(values...)
	var native *pgconn.PgError
	if errors.As(err, &native) {
		r.driver.nativeCode = native.Code
		r.driver.t.Logf("Discovery native control mode=%s code=%s message=%s", r.driver.mode, native.Code, native.Message)
	}
	if err == nil && r.driver.mode == "rollback-after-mutation" {
		r.driver.nativeSuccess = true
		return errors.New("owned failure after native audit/capture")
	}
	return err
}

func discoveryWaitLock(t *testing.T, ctx context.Context, reader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, pid int32, event string) {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		var waiting bool
		if err := reader.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event=$2)`, pid, event).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	t.Fatal("owned contender did not reach expected native lock", event)
}
