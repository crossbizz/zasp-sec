package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catches configured writes/activation reaching rule-blind installed74 while
// preserving omitted-rule writes. Raw74 is used only to seed older drafts.
func TestTemporalAutomaticRolloutPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalTestSelector(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionTemporalHumanAdmission(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		authority, identity := orderedResourceGo(t, api, o, w, e, actor)
		repository := &PostgresRepository{database: authority.repository.database, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		definitions, err := newWorkflowHTTPHandler(repository, securityAgentTestSigningKey, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		sequence := 81000
		var drafts []string
		next := func() string { sequence++; return automaticSourceID(sequence) }
		handler, err := newSecurityAgentProductionHTTPHandler(ctx, repository, definitions, SecurityAgentPublicHandlerConfig{Clock: time.Now, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) { return next(), nil }}, true)
		if err != nil {
			t.Fatal(err)
		}
		var base json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body-'id' FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&base); err != nil {
			t.Fatal(err)
		}
		bodyFor := func(rule string) json.RawMessage {
			var body map[string]json.RawMessage
			if json.Unmarshal(base, &body) != nil {
				t.Fatal("base definition")
			}
			body["enabled"] = json.RawMessage(`false`)
			if rule != "" {
				body["trigger_rules"] = json.RawMessage(rule)
			}
			raw, _ := json.Marshal(body)
			return raw
		}
		rules := []string{`{"version":1,"mode":"manual"}`, `{"version":1,"mode":"automatic","cooldown_seconds":600,"finding":{"family":"credential","minimum_severity":"high"}}`}
		request := func(operation, method, id string, body json.RawMessage, version string) *httptest.ResponseRecorder {
			t.Helper()
			path := "/api/v1/security-agents"
			var params map[string]string
			if id != "" {
				path += "/" + id
				params = map[string]string{"id": id}
			}
			req := workflowRequest(t, identity, testCorrelationID, operation, params, method, path, string(body))
			req.Header.Set("Idempotency-Key", "rollout77-"+next())
			if version != "" {
				req.Header.Set("If-Match", version)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			return response
		}
		for i, rule := range rules {
			t.Run(fmt.Sprintf("absent77-rule%d", i), func(t *testing.T) {
				res := request("createSecurityAgent", http.MethodPost, "", bodyFor(rule), "")
				if res.Code != http.StatusServiceUnavailable {
					t.Errorf("configured create before77 status=%d want503", res.Code)
				}
				// Seed a configured draft through the historical protocol, as an old
				// binary could have done. This is not the guarded application path.
				id := next()
				drafts = append(drafts, id)
				var body map[string]json.RawMessage
				json.Unmarshal(bodyFor(rule), &body)
				intent, _ := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": body})
				body["id"], _ = json.Marshal(id)
				raw, _ := json.Marshal(body)
				var result json.RawMessage
				if err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write('create',$1,$2,$3,$4,$5,'createSecurityAgent',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`, id, o, w, e, actor, "rollout-seed-"+id, intent, raw, next(), next(), next()).Scan(&result); err != nil {
					t.Fatal(err)
				}
				if _, err := repository.GetSecurityAgentActivation(ctx, identity, id); err != nil {
					t.Fatal("draft read", err)
				}
				res = request("updateSecurityAgent", http.MethodPatch, id, raw, `"1"`)
				if res.Code != http.StatusServiceUnavailable {
					t.Errorf("configured update before77 status=%d want503", res.Code)
				}
				// Use the actual persisted version even on RED after an unsafe update.
				var version int64
				if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_definitions WHERE definition_id=$1`, id).Scan(&version); err != nil {
					t.Fatal(err)
				}
				identity.FreshAuthenticated = true
				identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
				_, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: id, ExpectedVersion: version, TargetActivation: "validated", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, IdempotencyKey: "rollout-activate-" + id, AuditID: next(), CorrelationID: next(), ReceiptID: next()})
				if !errors.Is(err, ErrRepositoryUnavailable) {
					t.Errorf("stored configured draft activated before77: error=%v", err)
				}
				var unchanged bool
				if err := owner.QueryRow(ctx, `SELECT activation='draft' AND version=1 AND body->'enabled'='false'::jsonb FROM zasp_security_agent_definitions WHERE definition_id=$1`, id).Scan(&unchanged); err != nil || !unchanged {
					t.Error("refused mutation changed draft", unchanged, err)
				}
			})
		}
		if res := request("createSecurityAgent", http.MethodPost, "", bodyFor(""), ""); res.Code != http.StatusCreated {
			t.Errorf("omitted create before77 status=%d", res.Code)
		}
		// Verify exact existing executor read limitations with the real login.
		// Historical ordered drafts must traverse the same persisted-rule gate.
		orderedID := next()
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) SELECT organization_id,workspace_id,environment_id,$2,'draft',1,1,body||jsonb_build_object('id',$2::text,'enabled',false,'autonomy','supervised','max_steps',2,'allowed_actions',jsonb_build_array('create_temporary_policy','run_test'),'trigger_rules','{"version":1,"mode":"manual"}'::jsonb),plan_catalog_version FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved, orderedID); err != nil {
			t.Fatal(err)
		}
		for _, resource := range []bool{false, true} {
			var err error
			if resource {
				_, err = authority.Activate(ctx, identity, SecurityAgentOrderedActivation{DefinitionID: orderedID, Version: 1, Activation: "supervised", IdempotencyKey: "rollout77-ordered-activation"})
			} else {
				_, err = authority.repository.Activate(ctx, identity, orderedID, 1)
			}
			if !errors.Is(err, ErrRepositoryUnavailable) {
				t.Errorf("public62 configured activation resource=%t error=%v", resource, err)
			}
		}
		var unchanged bool
		if err := owner.QueryRow(ctx, `SELECT activation='draft' AND version=1 FROM zasp_security_agent_definitions WHERE definition_id=$1`, orderedID).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("public62 changed refused draft", unchanged, err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE rollout77_executor LOGIN; CREATE ROLE rollout77_compensation LOGIN; SELECT zasp_temporal68.register_principals('rollout77_executor','rollout77_compensation'); SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":86400,"enabled":true}')`); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "rollout77_executor"
		// ConnString retains the original parse input after Config.User changes.
		// Child processes need an explicit URL with the registered executor role.
		executorURL := url.URL{Scheme: "postgres", User: url.User(config.User), Host: net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port))), Path: "/" + config.Database, RawQuery: "sslmode=disable"}
		executor, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		runAutomaticRolloutWorker(t, ctx, executorURL.String(), "absent", o, w, e)
		for _, query := range []string{`SELECT body FROM public.zasp_security_agent_definitions LIMIT 1`, `SELECT public.zasp_security_agent_definition_value($1,$2,$3,$4)`, `SELECT zasp_temporal74.definition($1,$2,$3,$4,$5)`} {
			var raw json.RawMessage
			var args []any
			if query != `SELECT body FROM public.zasp_security_agent_definitions LIMIT 1` {
				args = []any{o, w, e, temporalTestLegacyProved}
				if query == `SELECT zasp_temporal74.definition($1,$2,$3,$4,$5)` {
					args = append(args, actor)
				}
			}
			err := executor.QueryRow(ctx, query, args...).Scan(&raw)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Errorf("executor existing read expected denial: query=%s error=%v", query, err)
			} else {
				t.Logf("executor read denied SQLSTATE=%s query=%s", pgErr.Code, query)
			}
		}
		if err := runner.UpProductionTemporalAutomaticSources(ctx); err != nil {
			tx, txErr := owner.Begin(ctx)
			if txErr != nil {
				t.Fatal(txErr)
			}
			defer tx.Rollback(context.Background())
			_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalAutomaticSources().UpSQL())
			var pgErr *pgconn.PgError
			if errors.As(ddlErr, &pgErr) {
				t.Logf("77 DDL failure SQLSTATE=%s routine=%s", pgErr.Code, pgErr.Routine)
			}
			var pin string
			pinErr := tx.QueryRow(ctx, `SELECT zasp_temporal77.fingerprint()`).Scan(&pin)
			t.Logf("77 diagnostic DDL_ok=%t fingerprint=%s fingerprint_ok=%t", ddlErr == nil, pin, pinErr == nil)
			t.Fatal(err)
		}
		for i, rule := range rules {
			if res := request("createSecurityAgent", http.MethodPost, "", bodyFor(rule), ""); res.Code != http.StatusCreated {
				t.Errorf("ready77 configured rule%d create status=%d", i, res.Code)
			}
		}
		for _, id := range drafts {
			for i, state := range []string{"validated", "supervised", "autonomous"} {
				result, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: id, ExpectedVersion: int64(i + 1), TargetActivation: state, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, IdempotencyKey: "ready77-" + state + "-" + id, AuditID: next(), CorrelationID: next(), ReceiptID: next()})
				if err != nil || result.Version != int64(i+2) {
					t.Fatal("ready77 stored activation", state, err)
				}
			}
		}
		runAutomaticRolloutWorker(t, ctx, executorURL.String(), "ready", o, w, e)
		var admitted int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal75.admissions a JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE r.definition_id=$1`, temporalTestLegacyProved).Scan(&admitted); err != nil || admitted != 1 {
			t.Fatal("ready77 omitted actual admission", admitted, err)
		}
		if _, err := owner.Exec(ctx, `ALTER FUNCTION zasp_temporal77.api_ready(text,text) IMMUTABLE`); err != nil {
			t.Fatal(err)
		}
		for i, rule := range rules {
			if res := request("createSecurityAgent", http.MethodPost, "", bodyFor(rule), ""); res.Code != http.StatusServiceUnavailable {
				t.Errorf("invalid77 configured rule%d create status=%d want503", i, res.Code)
			}
		}
		runAutomaticRolloutWorker(t, ctx, executorURL.String(), "invalid", o, w, e)
		for _, id := range drafts {
			_, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: id, ExpectedVersion: 4, TargetActivation: "autonomous", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, IdempotencyKey: "invalid77-activate-" + id, AuditID: next(), CorrelationID: next(), ReceiptID: next()})
			if !errors.Is(err, ErrRepositoryUnavailable) {
				t.Error("invalid77 activation", err)
			}
		}
	})
}

func runAutomaticRolloutWorker(t *testing.T, ctx context.Context, dsn, mode, o, w, e string) {
	t.Helper()
	q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": temporalTestLegacyProved})
	cmd := exec.CommandContext(ctx, "go", "test", "./agentsec-worker", "-run", "^TestAutomaticSelectorInstalledStartup$", "-count=1", "-v")
	cmd.Dir = ".."
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(os.Environ(), "ZASP_TEST77_ROLLOUT_DSN="+dsn, "ZASP_TEST77_ROLLOUT_MODE="+mode, "ZASP_TEST77_ROLLOUT_REF="+string(q))
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil || !strings.Contains(string(output), "--- PASS: TestAutomaticSelectorInstalledStartup") || strings.Contains(string(output), "--- SKIP:") {
		t.Fatal("registered selector startup", mode, err)
	}
}
