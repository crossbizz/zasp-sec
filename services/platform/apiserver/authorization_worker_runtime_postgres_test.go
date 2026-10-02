package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestP7WorkerSingleTestRetainedRuntimeSource(t *testing.T) {
	runWorkerTest74PlanningFixture(t, "runtime-retained")
}

func TestP7WorkerCurrentTestActivation(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, _, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		runner := workerMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalFindingResponse(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE worker_test_executor LOGIN;CREATE ROLE worker_test_compensation LOGIN;SELECT zasp_temporal68.register_principals('worker_test_executor','worker_test_compensation');UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests","investigate_sessions"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		definition := workerRuntimeDraftDefinition(t, ctx, owner, api, o, w, e, actor, false)
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal(err)
		}
		workerRuntimeActivateCurrent(t, ctx, owner, api, o, w, e, actor, definition)
	})
}

// This is deliberately separate from historical-source worker admission. The
// current profile must also support ongoing actual runtime projection.
func TestP7WorkerCurrentRuntimeProjection(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, _, actor string) {
		installAutomaticSourceFixture(t, ctx, owner)
		runner := workerMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalFindingResponse(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE worker_test_executor LOGIN;CREATE ROLE worker_test_compensation LOGIN;SELECT zasp_temporal68.register_principals('worker_test_executor','worker_test_compensation')`); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal(err)
		}
		workerRuntimeProjection(t, ctx, owner, o, w, e, actor, true).publish(t, ctx, owner, o, w, e)
		workerRuntimeStartupChild(t, ctx, owner)
	})
}

// Configured77 activation must use actual current human authorization. A draft
// created under the predecessor is not an activated worker delegation.
func TestP7WorkerSingleTestConfiguredRuntimeActivation(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		runtimeSource := workerRuntimeHistoricalProjection(t, ctx, owner, o, w, e, actor)
		installAutomaticSourceFixture(t, ctx, owner)
		runner := workerMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalFindingResponse(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE worker_test_executor LOGIN; CREATE ROLE worker_test_compensation LOGIN;SELECT zasp_temporal68.register_principals('worker_test_executor','worker_test_compensation');UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests","investigate_sessions"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		definition := workerRuntimeDefinition(t, ctx, owner, api, o, w, e, actor, true)
		if _, err := owner.Exec(ctx, `SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":1,"enabled":true}')`); err != nil {
			t.Fatal("configured runtime selector", err)
		}
		selection := workerRuntimePlanningPrice(t, ctx, owner, o, w, e, actor)
		earlierGatewayEvent := runtimeSource.event.EventID
		runtimeSource.publishAt(t, ctx, owner, o, w, e, time.Now().UTC().Truncate(time.Second).Add(-time.Second))
		runtimeSource.event.EventID = automaticSourceID(46)
		runtimeSource.event.ExpectedFloor, runtimeSource.event.NextFloor = 1, 2
		runtimeSource.publish(t, ctx, owner, o, w, e)
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal(err)
		}
		gap := workerRuntimeHistoricalSourceGap(t, ctx, owner, o, w, e, earlierGatewayEvent)
		workerRuntimeActivateCurrent(t, ctx, owner, api, o, w, e, actor, definition)
		run := workerRuntimeAdmitConfigured(t, ctx, owner, o, w, e, definition, runtimeSource.event.EventID)
		assertWorkerTest74PlanningLoad(t, ctx, owner, o, w, e, run, testID, selection, "runtime-configured")
		assertWorkerRuntimeCatchup(t, ctx, owner, o, w, e, run, definition, gap)
	})
}

func workerRuntimePlanningPrice(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, actor string) map[string]any {
	t.Helper()
	config := owner.Config().Copy()
	config.User = "security_agent_v33_discovery_api_login"
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	policy := orderedPricingAdminRequest(o, w, e, actor)
	bindTemporalTestPlannerPricing(policy)
	pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
	if err != nil {
		t.Fatal("runtime planner pricing", err)
	}
	return orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
}

func workerRuntimeAdmitConfigured(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, definition, gatewayEvent string) string {
	t.Helper()
	config := owner.Config().Copy()
	config.User = "worker_test_executor"
	executor, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(context.Background())
	var sourceEvent string
	if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE (organization_id,workspace_id,environment_id,source_kind,source_id)=($1,$2,$3,'runtime_decision',$4)`, o, w, e, gatewayEvent).Scan(&sourceEvent); err != nil {
		t.Fatal("actual configured runtime source capture", err)
	}
	request, _ := json.Marshal(map[string]any{"ref": map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": definition}, "revision": 1, "event_id": sourceEvent})
	var raw json.RawMessage
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, request).Scan(&raw); err != nil {
		t.Fatal("actual configured runtime occurrence admission", err)
	}
	var admitted struct {
		Disposition string `json:"disposition"`
		RunID       string `json:"run_id"`
	}
	if json.Unmarshal(raw, &admitted) != nil || admitted.Disposition != "admitted" || admitted.RunID == "" {
		t.Fatal("configured runtime did not admit its exact occurrence")
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, admitted.RunID).Scan(&raw); err != nil || string(raw) == "null" {
		t.Fatal("configured runtime native takeover", err)
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, request).Scan(&raw); err != nil {
		t.Fatal("configured runtime admission replay", err)
	}
	var replay struct {
		Disposition         string `json:"disposition"`
		OriginalDisposition string `json:"original_disposition"`
		RunID               string `json:"run_id"`
	}
	if json.Unmarshal(raw, &replay) != nil || replay.Disposition != "replayed" || replay.OriginalDisposition != "admitted" || replay.RunID != admitted.RunID {
		t.Fatal("configured runtime replay changed identity")
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(x.source_kind='automatic73' AND x.definition_version=5 AND x.trigger_id=$5 AND x.input_digest=encode(a.snapshot_digest,'hex') AND a.snapshot_digest=digest(convert_to(a.snapshot::text,'UTF8'),'sha256')) FROM zasp_temporal77.occurrences a JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,definition_id,definition_version,run_id) WHERE (a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.run_id)=($1,$2,$3,$4,$6)`, o, w, e, definition, gatewayEvent, admitted.RunID).Scan(&exact); err != nil || !exact {
		t.Fatal("configured occurrence ownership/snapshot cardinality", err)
	}
	return admitted.RunID
}

// The archived/project-stage fixture is fed through the actual Go projection
// and registered native completion writer. No session summary or gateway event
// is inserted by this helper. Gateway prerequisites are separate from evidence.
func workerRuntimeSource(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, actor string) string {
	t.Helper()
	return workerRuntimeHistoricalProjection(t, ctx, owner, o, w, e, actor).publish(t, ctx, owner, o, w, e)
}

type workerRuntimeProjectedSource struct {
	repository *gatewaycontrol.PostgresRepository
	key        ed25519.PrivateKey
	event      gatewaycontrol.DecisionEvent
}

// For worker-source tests this runs while the fixture still has release60,
// before upgrade. The separate current-projection test must also pass before
// runtime-family acceptance. Neither path fabricates a session summary.
func workerRuntimeHistoricalProjection(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, actor string) workerRuntimeProjectedSource {
	return workerRuntimeProjection(t, ctx, owner, o, w, e, actor, false)
}

func workerRuntimeProjection(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, actor string, current bool) workerRuntimeProjectedSource {
	t.Helper()
	_, repository, key, event := seedAutomaticRuntimeGateway(t, ctx, owner, o, w, e)
	identity := automaticSourceIdentity(t, o, w, e, actor)
	const agent = "pid_89000011-0000-4000-8000-000000000001"
	const session = "pid_96000007-0000-4000-8000-000000000007"
	arguments, _ := seedScopedSessionProjectionCompletion(t, ctx, owner, identity.Scope, agent, false, true)
	config := owner.Config().Copy()
	config.User = "source77_coordinator"
	coordinator, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close(context.Background())
	var completion json.RawMessage
	if current {
		pipeline, setupErr := runtimeevent.NewPostgresCurrentRuntimePipelineRepository(workerRuntimeProjectionDatabase{coordinator}, runtimeevent.ProductionPipelineAuthorityCoordinator)
		if setupErr != nil {
			t.Fatal(setupErr)
		}
		var input, resultDigest [32]byte
		copy(input[:], arguments[8].([]byte))
		copy(resultDigest[:], arguments[14].([]byte))
		request := runtimeevent.StageFinishRequest{Lease: runtimeevent.StageLease{Scope: identity.Scope, BatchID: mustProductID(t, arguments[3].(string)), Generation: 1, Stage: runtimeevent.RuntimeStageComplete, Attempt: 1, ImplementationVersion: "runtime-complete-v3", InputDigest: input, InputReference: "s3://zasp-evidence/projected.json", InputVersionID: "projected-v1", LeaseExpiresAt: time.Now().Add(time.Hour)}, WorkerID: "session-worker", LeaseToken: "session-lease-token-0001", Outcome: runtimeevent.StageOutcomeSucceeded, EffectDigest: input, ResultReference: arguments[12].(string), ResultVersionID: arguments[13].(string), ResultDigest: resultDigest, ProjectionReceipt: string(arguments[17].([]byte))}
		result, finishErr := pipeline.FinishStage(ctx, request)
		if finishErr != nil || result.State != runtimeevent.StageOutcomeSucceeded {
			t.Fatal("actual current typed projection completion", finishErr)
		}
		if replay, replayErr := pipeline.FinishStage(ctx, request); replayErr != nil || replay != result {
			t.Fatal("actual current typed projection replay", replayErr)
		}
	} else if err := coordinator.QueryRow(ctx, strings.Replace(sessionProjectionFinishSQL, "zasp_runtime_finish_session_projection", "zasp_runtime_finish_precise_session_projection", 1), arguments...).Scan(&completion); err != nil {
		var native *pgconn.PgError
		if errors.As(err, &native) {
			t.Logf("runtime projection SQLSTATE=%s native_context=%s", native.Code, native.Where)
		}
		for _, probe := range []struct{ name, query string }{
			{"precision", `SELECT zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint'))`},
			{"sandbox-security", `SELECT zasp_production_runtime_sandbox_binding_security_ready()`},
			{"audit-exports", `SELECT zasp_production_audit_exports_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=52),(SELECT value FROM zasp_schema_metadata WHERE key='production_audit_exports_fingerprint'))`},
			{"context", `SELECT zasp_production_security_agent_run_context_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=54),(SELECT value FROM zasp_schema_metadata WHERE key='production_security_agent_run_context_fingerprint'))`},
			{"temporal74", `SELECT zasp_temporal74.current_ready()`},
			{"temporal78", `SELECT zasp_temporal78.current_ready()`},
			{"coordinator", `SELECT zasp_runtime_principal_ready('zasp_runtime_coordinator')`},
		} {
			var ready bool
			probeConnection := owner
			if probe.name == "coordinator" {
				probeConnection = coordinator
			}
			probeErr := probeConnection.QueryRow(ctx, probe.query).Scan(&ready)
			code := "none"
			if errors.As(probeErr, &native) {
				code = native.Code
			} else if probeErr != nil {
				code = "non-sql"
			}
			t.Logf("runtime readiness probe=%s ready=%t SQLSTATE=%s", probe.name, ready, code)
		}
		t.Fatal("actual registered runtime session projection", err)
	}
	event.Evaluation.AgentID, event.Evaluation.SessionID = agent, session
	event.Classification["session_id"], event.Classification["outcome"] = session, "gateway"
	return workerRuntimeProjectedSource{repository: repository, key: key, event: event}
}

type workerRuntimeProjectionDatabase struct{ connection *pgx.Conn }

func (d workerRuntimeProjectionDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	var result json.RawMessage
	err := d.connection.QueryRow(ctx, q, args...).Scan(&result)
	return result, err
}

func (source workerRuntimeProjectedSource) publish(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e string) string {
	return source.publishAt(t, ctx, owner, o, w, e, time.Now().UTC().Truncate(time.Second))
}

func (source workerRuntimeProjectedSource) publishAt(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e string, occurred time.Time) string {
	t.Helper()
	repository, key, event := source.repository, source.key, source.event
	agent, session := event.Evaluation.AgentID, event.Evaluation.SessionID
	event.OccurredAt = occurred
	handler, err := gatewaycontrol.NewHTTPHandler(gatewaycontrol.HTTPHandlerConfig{Repository: repository, Clock: func() time.Time { return time.Now().UTC().Truncate(time.Second) }, OperationTimeout: 10 * time.Second, MaximumBodyBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(event)
	request := httptest.NewRequest(http.MethodPost, "https://gateway-control.zasp.example"+gatewaycontrol.DecisionPath, bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", gatewaycontrol.JSONMediaType)
	if err := gatewaycontrol.SignRequest(request, body, event.CredentialID, key, time.Now().UTC().Truncate(time.Second)); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatal("actual signed runtime source writer", response.Code)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_runtime_session_summaries WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND minimum_agent_id=$5 AND maximum_agent_id=$5) AND EXISTS(SELECT 1 FROM zasp_runtime_gateway_events WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND event_id=$6 AND classification->>'session_id'=$4 AND decision='block') AND EXISTS(SELECT 1 FROM zasp_temporal77.runtime_evaluations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND event_id=$6 AND evaluation->>'agent_id'=$5 AND evaluation->>'session_id'=$4)`, o, w, e, session, agent, event.EventID).Scan(&exact); err != nil || !exact {
		t.Fatal("persisted actual runtime ancestry", err)
	}
	return session
}

func workerRetainedRuntimeDefinition(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) string {
	t.Helper()
	return workerRuntimeDefinition(t, ctx, owner, api, o, w, e, actor, false)
}

func workerRuntimeDefinition(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string, configured bool) string {
	t.Helper()
	definition := workerRuntimeDraftDefinition(t, ctx, owner, api, o, w, e, actor, configured)
	if !configured {
		activateAutomaticPageDefinition(t, ctx, api, o, w, e, actor, definition, 8750)
	}
	return definition
}

func workerRuntimeDraftDefinition(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string, configured bool) string {
	t.Helper()
	definition := automaticSourceID(8740)
	var base json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&base); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if json.Unmarshal(base, &body) != nil {
		t.Fatal("actual retained definition")
	}
	body["id"], body["enabled"] = definition, false
	body["trigger_kind"], body["trigger_source"] = "runtime_decision", "gateway"
	delete(body, "trigger_rules") // Retained session protocol, not configured77.
	if configured {
		body["trigger_rules"] = map[string]any{"version": 1, "mode": "automatic", "cooldown_seconds": 1, "runtime": map[string]any{"decision": "block", "action": "tool_execute", "risk": "high", "count": 1, "window_seconds": 300}}
	}
	raw, _ := json.Marshal(body)
	delete(body, "id")
	intent, _ := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": body})
	var result json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write('create',$1,$2,$3,$4,$5,'createSecurityAgent',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`, definition, o, w, e, actor, "worker-runtime-retained-create", intent, raw, automaticSourceID(8741), automaticSourceID(8742), automaticSourceID(8743)).Scan(&result); err != nil {
		t.Fatal("actual runtime definition creation", err)
	}
	return definition
}

func workerRuntimeActivateCurrent(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor, definition string) {
	t.Helper()
	client, pins := newAuthorizationProjectionFGA(t)
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	var outbox, apiLogin string
	for role, name := range map[string]*string{"zasp_outbox_worker": &outbox, "zasp_discovery_api": &apiLogin} {
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role=$1`, role).Scan(name); err != nil {
			t.Fatal(err)
		}
	}
	config, err := pgxpool.ParseConfig(owner.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = outbox
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, err := authorization.NewPostgresProjectionRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	human := authorizationFixtureAttestor(t)
	if _, err := owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2);SELECT zasp_authorization79.configure($3,$4,$5)`, pgx.QueryExecModeSimpleProtocol, human.Version(), human.Verifier(), o, pins.StoreID, pins.ModelID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('worker-runtime-session','sha256'),'session-worker-runtime',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, actor, o, w, e); err != nil {
		t.Fatal(err)
	}
	apiConfig := owner.Config().Copy()
	apiConfig.User = apiLogin
	sessionAPI, err := pgx.ConnectConfig(ctx, apiConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionAPI.Close(context.Background())
	database := func(conn *pgx.Conn) *PostgresJSONDatabase {
		db, err := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: conn})
		if err != nil || db.RequireCurrentAuthorization() != nil {
			t.Fatal("current runtime fixture database", err)
		}
		return db
	}
	sessionDB := database(sessionAPI)
	sessions, err := NewPostgresRepository(sessionDB)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sessions.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "worker-runtime-session"})
	if err != nil {
		t.Fatal(err)
	}
	agentRepository, err := NewSecurityAgentPostgresRepository(database(api))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewPostgresAuthorizationResolver(sessionDB)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: human}
	for i, state := range []string{"validated", "supervised", "autonomous", "autonomous"} {
		if result, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !result.Applied {
			t.Fatal("runtime human projection", err)
		}
		grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "activateSecurityAgent", PathParameters: map[string]string{"id": definition}})
		if err != nil {
			t.Fatal("actual configured runtime human Check", err)
		}
		request := SecurityAgentActivation{DefinitionID: definition, IdempotencyKey: fmt.Sprintf("worker-runtime-configured-%s-%d", state, i), ExpectedVersion: int64(i + 1), TargetActivation: state, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: automaticSourceID(8790 + i*3), CorrelationID: automaticSourceID(8791 + i*3), ReceiptID: automaticSourceID(8792 + i*3)}
		args := []any{o, w, e, definition, actor, request.IdempotencyKey, request.ExpectedVersion, state, request.FreshAuthExpiresAt, request.AuditID, request.CorrelationID, request.ReceiptID}
		if i == 0 {
			workerActivationNativeControls(t, ctx, owner, api, grant, args)
			if projected, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !projected.Applied {
				t.Fatal("post-control activation reconciliation", err)
			}
			grant, err = authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "activateSecurityAgent", PathParameters: map[string]string{"id": definition}})
			if err != nil {
				t.Fatal(err)
			}
		}
		var ignored json.RawMessage
		rawErr := api.QueryRow(ctx, `SELECT zasp_temporal74.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, args...).Scan(&ignored)
		var pg *pgconn.PgError
		if !errors.As(rawErr, &pg) || pg.Code != "42501" {
			t.Fatal("raw activation did not refuse current proof absence", rawErr)
		}
		var before, after int64
		if err := owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&before); err != nil {
			t.Fatal(err)
		}
		result, err := agentRepository.ActivateSecurityAgent(context.WithValue(ctx, requestAuthorizationContextKey{}, grant), identity, request)
		if err != nil || result.Version != int64(i+2) || result.Activation != state {
			t.Fatal("actual checked configured runtime activation", state, err)
		}
		if err := owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&after); err != nil {
			t.Fatal(err)
		}
		delta := int64(2)
		if i == 3 {
			delta = 1
		}
		if after-before != delta {
			t.Fatalf("activation revision delta=%d want=%d", after-before, delta)
		}
		if projected, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !projected.Applied {
			t.Fatal("activation replay reconciliation", err)
		}
		replayGrant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "activateSecurityAgent", PathParameters: map[string]string{"id": definition}})
		if err != nil {
			t.Fatal(err)
		}
		replayed, err := agentRepository.ActivateSecurityAgent(context.WithValue(ctx, requestAuthorizationContextKey{}, replayGrant), identity, request)
		if err != nil || !replayed.Replayed || replayed.Version != result.Version || replayed.ReceiptID != result.ReceiptID {
			t.Fatal("actual activation receipt replay", err)
		}
		if err := owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&before); err != nil || before != after {
			t.Fatal("activation replay changed revision", err)
		}
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.service_grants g JOIN zasp_security_agent_definitions d USING(organization_id,workspace_id,environment_id,definition_id) WHERE d.definition_id=$1 AND d.version=5 AND d.activation='autonomous' AND g.definition_version=d.version AND g.definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256')) AND (SELECT count(*)=4 FROM zasp_security_agent_request_receipts WHERE resource_id=$1 AND operation='activateSecurityAgent') AND (SELECT count(*)=3 FROM zasp_temporal74.service_grants WHERE definition_id=$1)`, definition).Scan(&exact); err != nil || !exact {
		t.Fatal(fmt.Sprintf("configured runtime grant %s", definition), err)
	}
}
