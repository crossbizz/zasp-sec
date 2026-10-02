package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catches rule fields dropped/rejected by the installed public writer, its
// immutable definition history or the selected production readback route.
func TestTemporalAutomaticRulesPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalTestSelector(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionTemporalHumanAdmission(ctx); err != nil {
			t.Fatal(err)
		}
		if next, ok := any(runner).(interface{ UpProductionTemporalAutomaticSources(context.Context) error }); ok {
			if err := next.UpProductionTemporalAutomaticSources(ctx); err != nil {
				tx, txErr := owner.Begin(ctx)
				if txErr != nil {
					t.Fatal(txErr)
				}
				defer tx.Rollback(ctx)
				_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalAutomaticSources().UpSQL())
				var pin string
				pinErr := tx.QueryRow(ctx, `SELECT zasp_temporal77.fingerprint()`).Scan(&pin)
				var prior bool
				priorErr := tx.QueryRow(ctx, `SELECT zasp_temporal76.ready($1,$2)`, migrations.ProductionTemporalHumanAdmission().Checksum(), migrations.TemporalHumanAdmissionFingerprint()).Scan(&prior)
				t.Logf("independent77 DDL=%v fingerprint=%s fingerprint_error=%v predecessor76=%t predecessor_error=%v", ddlErr, pin, pinErr, prior, priorErr)
				t.Fatal("install77", err)
			}
		}
		authority, identity := orderedResourceGo(t, api, o, w, e, actor)
		db := authority.repository.database.(*PostgresJSONDatabase)
		db.driver = &automaticRulesDiagnosticDriver{PostgresDriver: db.driver, t: t}
		repository := &PostgresRepository{database: db, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		definitions, err := newWorkflowHTTPHandler(repository, securityAgentTestSigningKey, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		var original json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body-'id' FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&original); err != nil {
			t.Fatal(err)
		}
		sequence := 0
		for _, ordered := range []bool{false, true} {
			t.Run(fmt.Sprintf("ordered=%t", ordered), func(t *testing.T) {
				handler, err := newSecurityAgentProductionHTTPHandler(ctx, repository, definitions, SecurityAgentPublicHandlerConfig{Clock: time.Now, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) {
					sequence++
					return fmt.Sprintf("pid_f0770000-0000-4000-8000-%012d", sequence), nil
				}}, ordered)
				if err != nil {
					t.Fatal(err)
				}
				var body map[string]any
				if json.Unmarshal(original, &body) != nil {
					t.Fatal("fixture definition")
				}
				body["enabled"] = false
				if !ordered {
					legacyRaw, _ := json.Marshal(body)
					legacyReq := workflowRequest(t, identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", string(legacyRaw))
					legacyReq.Header.Set("Idempotency-Key", "automatic77-legacy-control")
					legacyResponse := httptest.NewRecorder()
					handler.ServeHTTP(legacyResponse, legacyReq)
					t.Logf("omitted-rule control=%d %s", legacyResponse.Code, legacyResponse.Body.String())
					if legacyResponse.Code != http.StatusCreated {
						t.Fatal("omitted-rule control rejected")
					}
				}
				body["trigger_rules"] = map[string]any{"version": 1, "mode": "automatic", "cooldown_seconds": 600, "finding": map[string]any{"family": "credential", "minimum_severity": "high"}}
				raw, _ := json.Marshal(body)
				req := workflowRequest(t, identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", string(raw))
				req.Header.Set("Idempotency-Key", fmt.Sprintf("automatic77-create-%t", ordered))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				if response.Code != http.StatusCreated {
					t.Fatalf("registered rule create=%d %s", response.Code, response.Body.String())
				}
				var created map[string]json.RawMessage
				if json.Unmarshal(response.Body.Bytes(), &created) != nil || len(created["trigger_rules"]) == 0 {
					t.Fatal("rule omitted from public result", response.Body.String())
				}
				var id string
				if json.Unmarshal(created["id"], &id) != nil {
					t.Fatal("missing definition id")
				}
				var persisted, history json.RawMessage
				var activation string
				var version int64
				if err := owner.QueryRow(ctx, `SELECT d.body->'trigger_rules',h.definition->'trigger_rules',d.activation,d.version FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions h ON(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version) WHERE(d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,$4) AND h.definition_digest=digest(convert_to(h.definition::text,'UTF8'),'sha256')`, o, w, e, id).Scan(&persisted, &history, &activation, &version); err != nil {
					t.Fatal("persisted rule/history", err)
				}
				if string(persisted) != string(history) || activation != "draft" || version != 1 {
					t.Fatal("draft/history mismatch", string(persisted), string(history), activation, version)
				}
				want, _ := json.Marshal(body["trigger_rules"])
				for label, got := range map[string]json.RawMessage{"response": created["trigger_rules"], "persisted": persisted, "history": history} {
					assertAutomaticRuleJSON(t, label, got, want)
				}
				state, err := repository.GetSecurityAgentActivation(ctx, identity, id)
				if err != nil || state.Enabled || state.Activation != "draft" {
					t.Fatal("typed configured activation read", state, err)
				}
				created["trigger_rules"] = json.RawMessage(`{"version":1,"mode":"manual"}`)
				updateRaw, _ := json.Marshal(created)
				update := workflowRequest(t, identity, testCorrelationID, "updateSecurityAgent", map[string]string{"id": id}, http.MethodPatch, "/api/v1/security-agents/"+id, string(updateRaw))
				update.Header.Set("If-Match", `"1"`)
				update.Header.Set("Idempotency-Key", fmt.Sprintf("automatic77-update-%t", ordered))
				updated := httptest.NewRecorder()
				handler.ServeHTTP(updated, update)
				if updated.Code != http.StatusOK || updated.Header().Get("ETag") != `"2"` {
					t.Fatalf("registered update=%d %s", updated.Code, updated.Body.String())
				}
				var changed map[string]json.RawMessage
				if json.Unmarshal(updated.Body.Bytes(), &changed) != nil {
					t.Fatal("update response")
				}
				assertAutomaticRuleJSON(t, "updated response", changed["trigger_rules"], created["trigger_rules"])
				var oldRule json.RawMessage
				if err := owner.QueryRow(ctx, `SELECT d.body->'trigger_rules',h.definition->'trigger_rules',old.definition->'trigger_rules',d.activation,d.version FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions h ON(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version) JOIN zasp_security_agent_definition_versions old ON(old.organization_id,old.workspace_id,old.environment_id,old.definition_id,old.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,1) WHERE(d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,$4) AND h.definition_digest=digest(convert_to(h.definition::text,'UTF8'),'sha256') AND old.definition_digest=digest(convert_to(old.definition::text,'UTF8'),'sha256')`, o, w, e, id).Scan(&persisted, &history, &oldRule, &activation, &version); err != nil {
					t.Fatal(err)
				}
				assertAutomaticRuleJSON(t, "updated body", persisted, created["trigger_rules"])
				assertAutomaticRuleJSON(t, "updated history", history, created["trigger_rules"])
				assertAutomaticRuleJSON(t, "old immutable history", oldRule, want)
				if activation != "draft" || version != 2 {
					t.Fatal("edit did not return disabled draft", activation, version)
				}
			})
		}
		for i, rule := range []string{`null`, `{"version":1,"mode":"unexpected"}`, `{"version":1,"mode":"automatic","cooldown_seconds":0,"finding":{"family":"credential","minimum_severity":"high"}}`} {
			t.Run(fmt.Sprintf("raw SQL invalid rule %d", i), func(t *testing.T) {
				id := fmt.Sprintf("pid_f0770000-0000-4000-8000-%012d", 100+i)
				var body, intent json.RawMessage
				if err := owner.QueryRow(ctx, `SELECT (body-'id')||jsonb_build_object('id',$2::text,'enabled',false,'trigger_rules',$3::jsonb),jsonb_build_object('resource_id','','expected_version',0,'body',(body-'id')||jsonb_build_object('enabled',false,'trigger_rules',$3::jsonb)) FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved, id, rule).Scan(&body, &intent); err != nil {
					t.Fatal(err)
				}
				var result json.RawMessage
				err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, "create", id, o, w, e, actor, "createSecurityAgent", fmt.Sprintf("automatic77-invalid-%d", i), int64(0), intent, body, fmt.Sprintf("pid_f0770000-0000-4000-8000-%012d", 200+i), fmt.Sprintf("pid_f0770000-0000-4000-8000-%012d", 300+i), fmt.Sprintf("pid_f0770000-0000-4000-8000-%012d", 400+i)).Scan(&result)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "22023" {
					t.Fatalf("raw malformed rule must fail at SQL authority: err=%v result=%s", err, result)
				}
				var count int
				if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_definitions WHERE definition_id=$1`, id).Scan(&count); err != nil || count != 0 {
					t.Fatal("invalid write left definition", count, err)
				}
			})
		}
		t.Run("unsupported potential cannot activate", func(t *testing.T) {
			id := "pid_f0770000-0000-4000-8000-000000000700"
			var body, intent, result json.RawMessage
			if err := owner.QueryRow(ctx, `SELECT (body-'id')||jsonb_build_object('id',$2::text,'enabled',false,'trigger_kind','attack_path','trigger_source','potential','trigger_rules','{"version":1,"mode":"automatic","cooldown_seconds":600,"attack_path":{"state":"potential"}}'::jsonb) FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved, id).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var input map[string]json.RawMessage
			if json.Unmarshal(body, &input) != nil {
				t.Fatal("potential body")
			}
			delete(input, "id")
			intent, _ = json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": input})
			if err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write('create',$1,$2,$3,$4,$5,'createSecurityAgent','automatic77-potential-create',0,$6::jsonb,$7::jsonb,$8,$9,$10)`, id, o, w, e, actor, intent, body, "pid_f0770000-0000-4000-8000-000000000701", "pid_f0770000-0000-4000-8000-000000000702", "pid_f0770000-0000-4000-8000-000000000703").Scan(&result); err != nil {
				t.Fatal("potential draft", err)
			}
			err := api.QueryRow(ctx, `SELECT zasp_temporal74.activate($1,$2,$3,$4,$5,'automatic77-potential-activate',1,'validated',$6,$7,$8,$9)`, o, w, e, id, actor, time.Now().UTC().Add(4*time.Minute), "pid_f0770000-0000-4000-8000-000000000704", "pid_f0770000-0000-4000-8000-000000000705", "pid_f0770000-0000-4000-8000-000000000706").Scan(&result)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "22023" || pgErr.Message != "automatic trigger action/source capability unavailable" {
				t.Fatalf("unsupported combination activated: %v %s", err, result)
			}
			var activation string
			var version int64
			if err := owner.QueryRow(ctx, `SELECT activation,version FROM zasp_security_agent_definitions WHERE definition_id=$1`, id).Scan(&activation, &version); err != nil || activation != "draft" || version != 1 {
				t.Fatal("refused activation changed state", activation, version, err)
			}
		})
	})
}

func assertAutomaticRuleJSON(t *testing.T, label string, got, want json.RawMessage) {
	t.Helper()
	var a, b any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal(want, &b) != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("%s rule=%s want=%s", label, got, want)
	}
}

// Preserve the underlying failure before the public repository intentionally
// translates it to a safe HTTP error. This wraps IO, not authority decisions.
type automaticRulesDiagnosticDriver struct {
	PostgresDriver
	t *testing.T
}

func (d *automaticRulesDiagnosticDriver) QueryRow(ctx context.Context, sql string, args ...any) PostgresRow {
	return automaticRulesDiagnosticRow{PostgresRow: d.PostgresDriver.QueryRow(ctx, sql, args...), t: d.t, sql: sql}
}

type automaticRulesDiagnosticRow struct {
	PostgresRow
	t   *testing.T
	sql string
}

func (r automaticRulesDiagnosticRow) Scan(values ...any) error {
	err := r.PostgresRow.Scan(values...)
	if err != nil {
		r.t.Logf("registered SQL error: %s: %v", r.sql, err)
	} else {
		for _, value := range values {
			if ready, ok := value.(*bool); ok {
				r.t.Logf("registered readiness: %s = %t", r.sql, *ready)
			}
			if raw, ok := value.(*[]byte); ok {
				r.t.Logf("registered SQL result: %s: %s", r.sql, *raw)
			}
		}
	}
	return err
}
