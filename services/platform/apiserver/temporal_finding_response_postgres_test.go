package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catches finding-response configurations falling through stale legacy writers
// or being activated without the distinct Temporal finding execution authority.
// Identity membership and the predecessor test definition are fixture inputs.
func TestTemporalFindingResponsePostgres(t *testing.T) {
	runFindingResponseFixture(t, nil)
}

type findingResponseFixture struct {
	owner, api, executor                 *pgx.Conn
	repository                           *PostgresRepository
	handler                              http.Handler
	identity                             RequestIdentity
	o, w, e, definition, actor, assignee string
	next                                 func() string
}

func runFindingResponseFixture(t *testing.T, afterSetup func(context.Context, findingResponseFixture)) {
	runFindingResponseFixtureMode(t, afterSetup, nil)
}

func runFindingResponseFixtureMode(t *testing.T, afterSetup func(context.Context, findingResponseFixture), supervisedPlan func(context.Context, findingResponseFixture, string, string)) {
	runFindingResponseFixtureOptions(t, afterSetup, supervisedPlan, supervisedPlan != nil)
}

func runFindingResponseFixtureOptions(t *testing.T, afterSetup func(context.Context, findingResponseFixture), supervisedPlan func(context.Context, findingResponseFixture, string, string), supervised bool, noteCases ...findingResponseNoteCase) {
	runFindingResponseFixtureConfigured(t, afterSetup, supervisedPlan, supervised, 1, noteCases...)
}

// Worker delegation tests admit two real tasks through the same definition.
// The capacity is part of the original validated draft, never a post-admission
// mutation of its versioned definition or an override of native admission.
func runFindingResponseFixtureConfigured(t *testing.T, afterSetup func(context.Context, findingResponseFixture), supervisedPlan func(context.Context, findingResponseFixture, string, string), supervised bool, concurrency int, noteCases ...findingResponseNoteCase) {
	t.Helper()
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		if next, ok := any(precisionMigrationRunner(t, owner)).(interface{ UpProductionTemporalFindingResponse(context.Context) error }); ok {
			if err := next.UpProductionTemporalFindingResponse(ctx); err != nil {
				tx, txErr := owner.Begin(ctx)
				if txErr != nil {
					t.Fatal(txErr)
				}
				defer tx.Rollback(ctx)
				_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalFindingResponse().UpSQL())
				var pgError *pgconn.PgError
				if errors.As(ddlErr, &pgError) {
					t.Logf("migration source diagnostic SQLSTATE=%s position=%d internal_position=%d context=%s internal_query=%s", pgError.Code, pgError.Position, pgError.InternalPosition, pgError.Where, pgError.InternalQuery)
				}
				var fingerprint string
				pinErr := tx.QueryRow(ctx, `SELECT zasp_temporal78.fingerprint()`).Scan(&fingerprint)
				t.Logf("independent78 DDL=%v fingerprint=%s pin_error=%v", ddlErr, fingerprint, pinErr)
				t.Fatal("install78", err)
			}
		}
		var testReady, humanReady bool
		if err := api.QueryRow(ctx, `SELECT zasp_temporal74.api_ready($1,$2),zasp_temporal76.api_ready($3,$4)`, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint(), migrations.ProductionTemporalHumanAdmission().Checksum(), migrations.TemporalHumanAdmissionFingerprint()).Scan(&testReady, &humanReady); err != nil || !testReady || !humanReady {
			t.Fatal("current test/human authority after78", testReady, humanReady, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1; INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($2,$3,$4,'update_finding_response',true,$1) ON CONFLICT DO NOTHING`, pgx.QueryExecModeSimpleProtocol, actor, o, w, e); err != nil {
			t.Fatal(err)
		}
		authority, identity := orderedResourceGo(t, api, o, w, e, actor)
		db := authority.repository.database.(*PostgresJSONDatabase)
		repository := &PostgresRepository{database: db, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		definitions, err := newWorkflowHTTPHandler(repository, securityAgentTestSigningKey, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		sequence := 0
		next := func() string { sequence++; return fmt.Sprintf("pid_f0780000-0000-4000-8000-%012d", sequence) }
		assignee := actor
		if supervisedPlan != nil {
			// Keep the proposed assignee separate from the grantor and approver so
			// revocation tests exercise assignee eligibility, not actor authority.
			assignee = next()
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) SELECT $2,organization_id,organization_reference,$2,role,true FROM zasp_identity_memberships WHERE principal_id=$1 AND organization_id=$3; INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) SELECT $2,organization_id,workspace_id,environment_id,label,'["view"]'::jsonb,false FROM zasp_authorized_scopes WHERE principal_id=$1 AND organization_id=$3 AND workspace_id=$4 AND environment_id=$5`, pgx.QueryExecModeSimpleProtocol, actor, assignee, o, w, e); err != nil {
				t.Fatal("distinct current assignee prerequisite", err)
			}
		}
		handler, err := newSecurityAgentProductionHTTPHandler(ctx, repository, definitions, SecurityAgentPublicHandlerConfig{Clock: time.Now, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) { return next(), nil }}, true)
		if err != nil {
			t.Fatal(err)
		}
		var original json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body-'id' FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&original); err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if json.Unmarshal(original, &body) != nil {
			t.Fatal("fixture definition")
		}
		delete(body, "existing_test")
		body["enabled"], body["allowed_actions"], body["verification_kind"], body["max_steps"] = false, []string{"update_finding_response"}, "finding_state", 1
		body["concurrency_limit"] = concurrency
		body["trigger_rules"] = map[string]any{"version": 1, "mode": "automatic", "cooldown_seconds": 600, "finding": map[string]any{"family": "credential", "minimum_severity": "high"}}
		raw, _ := json.Marshal(body)
		req := workflowRequest(t, identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", string(raw))
		req.Header.Set("Idempotency-Key", "finding78-create")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusCreated {
			t.Fatalf("registered configured finding create status=%d want201 body=%s", response.Code, response.Body.String())
		}
		var created map[string]json.RawMessage
		var id string
		if json.Unmarshal(response.Body.Bytes(), &created) != nil || json.Unmarshal(created["id"], &id) != nil || !validProductID(id) {
			t.Fatal("missing public finding definition")
		}
		wantRules, _ := json.Marshal(body["trigger_rules"])
		assertAutomaticRuleJSON(t, "public finding rule", created["trigger_rules"], wantRules)
		var persisted json.RawMessage
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT body->'trigger_rules',activation='draft' AND version=1 AND body->'allowed_actions'='["update_finding_response"]'::jsonb AND body->>'verification_kind'='finding_state' AND NOT body?'existing_test' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, o, w, e, id).Scan(&persisted, &exact); err != nil || !exact {
			t.Fatal("finding definition not persisted exactly", exact, err)
		}
		assertAutomaticRuleJSON(t, "persisted finding rule", persisted, wantRules)
		identity.FreshAuthenticated = true
		identity.FreshAuthExpiresAt = time.Now().UTC().Add(3 * time.Minute)
		activationTargets := []string{"validated", "supervised", "autonomous"}
		if supervised {
			activationTargets = activationTargets[:2]
		}
		definitionVersion := len(activationTargets) + 1
		note, responseStatus, targetStatus := "Investigate the credential exposure", "investigating", "under_review"
		if len(noteCases) == 1 {
			note, responseStatus = noteCases[0].note, noteCases[0].status
			if responseStatus == "open" {
				targetStatus = "open"
			}
		}
		for i, target := range activationTargets {
			result, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: id, ExpectedVersion: int64(i + 1), TargetActivation: target, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, IdempotencyKey: "finding78-" + target, AuditID: next(), CorrelationID: next(), ReceiptID: next()})
			if err != nil || result.Version != int64(i+2) || result.Activation != target {
				t.Fatalf("registered finding activation %s result=%+v error=%v", target, result, err)
			}
		}
		var grantProof bool
		proofTx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = proofTx.Exec(ctx, `SET LOCAL timezone='UTC'`); err != nil {
			t.Fatal(err)
		}
		if err := proofTx.QueryRow(ctx, `SELECT count(*)=$3 AND bool_and(g.grantor_id=$2 AND g.action_key='update_finding_response' AND g.principal_id=public.zasp_discovery_canonical_id(g.organization_id,g.workspace_id,g.environment_id,'security_agent_definition_service',g.definition_id) AND g.definition_digest=h.definition_digest AND a.event_kind='finding_service_delegated' AND a.body->'grant'=to_jsonb(g) AND a.event_digest=digest(convert_to(a.body::text,'UTF8'),'sha256')) FROM zasp_temporal78.service_grants g JOIN zasp_security_agent_definition_versions h ON(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version) JOIN zasp_security_agent_audit a ON(a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=(g.organization_id,g.workspace_id,g.environment_id,g.audit_id) WHERE g.definition_id=$1`, id, actor, len(activationTargets)-1).Scan(&grantProof); err != nil || !grantProof {
			proofTx.Rollback(ctx)
			t.Fatal("finding scoped delegation proof", grantProof, err)
		}
		if err := proofTx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE finding78_executor LOGIN;CREATE ROLE finding78_compensation LOGIN;SELECT zasp_temporal68.register_principals('finding78_executor','finding78_compensation');SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":86400,"enabled":true}')`); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "finding78_executor"
		executor, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		if afterSetup != nil {
			afterSetup(ctx, findingResponseFixture{owner: owner, api: api, executor: executor, repository: repository, handler: handler, identity: identity, o: o, w: w, e: e, definition: id, actor: actor, next: next})
			return
		}
		finding := next()
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Finding response prerequisite','high','open')`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		var event string
		if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE (organization_id,workspace_id,environment_id,source_id) =($1,$2,$3,$4)`, o, w, e, finding).Scan(&event); err != nil {
			t.Fatal(err)
		}
		q, _ := json.Marshal(map[string]any{"ref": map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": id}, "revision": 1, "event_id": event})
		var admitted json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, q).Scan(&admitted); err != nil {
			t.Fatal("registered finding source admission", err)
		}
		var disposition struct {
			Disposition string `json:"disposition"`
		}
		if json.Unmarshal(admitted, &disposition) != nil || disposition.Disposition != "admitted" {
			t.Fatal("finding source not admitted", string(admitted))
		}
		var run string
		if err := owner.QueryRow(ctx, `SELECT run_id FROM zasp_temporal78.run_owners WHERE definition_id=$1`, id).Scan(&run); err != nil {
			t.Fatal(err)
		}
		assertFindingStartJournal(t, ctx, owner, executor, run)
		planningRequest, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": definitionVersion, "operation": "load"})
		var job struct {
			State      string          `json:"state"`
			Context    json.RawMessage `json:"context_value"`
			RunVersion int64           `json:"run_version"`
		}
		var loaded json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.plan($1::jsonb)`, planningRequest).Scan(&loaded); err != nil {
			var zone string
			var keys []string
			const difference = `SELECT current_setting('TimeZone'),ARRAY(SELECT key FROM jsonb_each(x.snapshot->'source') k WHERE k.value IS DISTINCT FROM to_jsonb(f)->k.key) FROM zasp_temporal78.run_owners x JOIN zasp_risk_findings f ON(f.organization_id,f.workspace_id,f.environment_id,f.id)=(x.organization_id,x.workspace_id,x.environment_id,x.trigger_id) WHERE x.run_id=$1`
			if diagnostic := owner.QueryRow(ctx, difference, run).Scan(&zone, &keys); diagnostic == nil {
				t.Logf("snapshot diagnostic zone=%s differing_source_keys=%v", zone, keys)
			}
			tx, diagnostic := owner.Begin(ctx)
			if diagnostic == nil {
				if _, diagnostic = tx.Exec(ctx, `SET LOCAL timezone='UTC'`); diagnostic == nil {
					if diagnostic = tx.QueryRow(ctx, difference, run).Scan(&zone, &keys); diagnostic == nil {
						t.Logf("snapshot diagnostic zone=%s differing_source_keys=%v", zone, keys)
					}
				}
				tx.Rollback(ctx)
			}
			t.Fatal("registered finding planner load", err)
		}
		if json.Unmarshal(loaded, &job) != nil || job.State != "loaded" || job.RunVersion != 2 {
			t.Fatal("finding planner state")
		}
		if len(noteCases) == 1 {
			assertFindingNoteParser(t, ctx, owner, job.Context, finding, assignee)
		}
		var contextProof bool
		if err := owner.QueryRow(ctx, `SELECT ($1::jsonb->'context'->'allowed_targets')=jsonb_build_array($2::text) AND ($1::jsonb->'context'->'allowed_assignees')? $3 AND NOT ($1::jsonb->'context')?'existing_test' AND ($1::jsonb->'context'->'allowed_actions')='["update_finding_response"]'::jsonb`, job.Context, finding, assignee).Scan(&contextProof); err != nil || !contextProof {
			t.Fatal("finding-only planner context", contextProof, err)
		}
		for _, state := range []string{"open", "investigating", "resolved", "safe", "closed"} {
			candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Assign investigation", "steps": []any{map[string]any{"index": 0, "action": "update_finding_response", "target_id": finding, "assignee_id": assignee, "status": state, "note": "Investigate the credential exposure"}}})
			provider, _ := json.Marshal(map[string]any{"id": "finding78-controlled", "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
			var accepted bool
			if err := owner.QueryRow(ctx, `SELECT zasp_temporal78.planning_result($1,$2,$3::jsonb)->'candidate'<>'null'::jsonb`, string(provider), "openai/gpt-5-mini", job.Context).Scan(&accepted); err != nil || accepted != (state == "open" || state == "investigating") {
				t.Fatalf("finding planner status=%s accepted=%t error=%v", state, accepted, err)
			}
		}
		// Actual registered planner protocol, with a controlled provider result.
		// This is SQL accounting evidence, not an outbound HTTPS claim.
		call := func(op string, payload any) (map[string]any, error) {
			q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": definitionVersion, "operation": op, "payload": payload})
			var raw json.RawMessage
			err := executor.QueryRow(ctx, `SELECT zasp_temporal78.plan($1::jsonb)`, q).Scan(&raw)
			var result map[string]any
			if err == nil {
				err = json.Unmarshal(raw, &result)
			}
			return result, err
		}
		adminConfig := owner.Config().Copy()
		adminConfig.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, adminConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(context.Background())
		policy := orderedPricingAdminRequest(o, w, e, actor)
		bindTemporalTestPlannerPricing(policy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
		delete(selection, "body")
		delete(selection, "body_digest")
		prepared, err := call("prepare", map[string]any{"pricing": selection, "input_version": "finding78-input-v1"})
		if err != nil || prepared["state"] != "prepared" {
			t.Fatal("finding prepared intent", err)
		}
		var uncertain bool
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal73.unresolved($1,$2,$3,$4)`, o, w, e, run).Scan(&uncertain); err != nil || !uncertain {
			t.Error("finding reservation missing from shared unknown accounting", uncertain, err)
		}
		if len(noteCases) == 0 {
			assertFindingPlannerCleanup(t, ctx, owner, o, w, e, run, actor, false)
		}
		started, err := call("start", map[string]any{})
		if err != nil || started["send_permit"] != true {
			t.Fatal("finding first send permit", err)
		}
		started, err = call("start", map[string]any{})
		if err != nil || started["send_permit"] != false {
			t.Fatal("finding retry obtained another send permit", err)
		}
		if len(noteCases) == 0 {
			assertFindingPlannerCleanup(t, ctx, owner, o, w, e, run, actor, true)
		}
		if len(noteCases) == 1 {
			assertFindingNoteAdmissionRefusal(t, ctx, owner, run, finding, assignee, responseStatus)
		}
		candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Assign investigation", "steps": []any{map[string]any{"index": 0, "action": "update_finding_response", "target_id": finding, "assignee_id": assignee, "status": responseStatus, "note": note}}})
		provider, _ := json.Marshal(map[string]any{"id": "finding78-controlled", "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
		if _, err := call("result", map[string]any{"raw": string(provider)}); err != nil {
			t.Fatal("finding controlled provider result", err)
		}
		settled, err := call("settle", map[string]any{})
		if err != nil || settled["state"] != "settled" {
			t.Fatal("finding usage settlement", err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal73.unresolved($1,$2,$3,$4)`, o, w, e, run).Scan(&uncertain); err != nil || uncertain {
			t.Fatal("finding settled reservation retained uncertainty", uncertain, err)
		}
		if _, err := call("admit", map[string]any{}); err == nil {
			t.Fatal("finding admitted without artifact receipt")
		}
		if _, err := call("artifacts", map[string]any{"input_version": "finding78-input-v1", "output_version": "finding78-output-v1", "output_digest": settled["output_digest"]}); err != nil {
			t.Fatal("finding artifact receipts", err)
		}
		plan, err := call("admit", map[string]any{})
		if err != nil || plan["contract_version"] != float64(78) || plan["outcome"] != "admitted" {
			t.Fatal("finding plan admission", err)
		}
		var metadata bool
		if err := owner.QueryRow(ctx, `SELECT plan->'steps'->0->>'assignee_id'=$2 AND plan->'steps'->0->>'note'=$3 AND plan->'steps'->0->>'target_status'=$4 AND plan->'steps'->0->>'response_status'=$5 AND NOT (plan->'steps'->0)?'test_definition_version' FROM zasp_security_agent_plans WHERE run_id=$1`, run, assignee, note, targetStatus, responseStatus).Scan(&metadata); err != nil || !metadata {
			t.Fatal("finding immutable planned metadata", metadata, err)
		}
		if len(noteCases) == 1 {
			assertFindingNoteReadback(t, ctx, findingResponseFixture{owner: owner, api: api, executor: executor, repository: repository, handler: handler, identity: identity, o: o, w: w, e: e, actor: actor, assignee: assignee, next: next}, run, finding, noteCases[0], supervised)
			return
		}
		if supervisedPlan != nil {
			supervisedPlan(ctx, findingResponseFixture{owner: owner, api: api, executor: executor, repository: repository, handler: handler, identity: identity, o: o, w: w, e: e, definition: id, actor: actor, assignee: assignee, next: next}, run, finding)
			return
		}
		assertFindingApplyCurrentAuthority(t, ctx, owner, o, w, e, run, finding, actor)
		assertFindingPublicMetadata(t, handler, identity, run, finding, actor, false)
		assertFindingResponseAtomicEffect(t, ctx, owner, executor, api, o, w, e, run, finding, actor)
		assertFindingPublicMetadata(t, handler, identity, run, finding, actor, true)
		assertFindingHumanAdmission(t, ctx, owner, handler, identity, o, w, e, id, actor, next)
	})
}
