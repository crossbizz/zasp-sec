package apiserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func triggerKeyRequest(o, w, e, actor, definition, key string) map[string]any {
	q := public62Request(o, w, e, actor, "classify_trigger_key")
	q["definition_id"], q["idempotency_key"] = definition, key
	return q
}

func triggerKeyLegacyFixture(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor, definition, key string) {
	t.Helper()
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definitions,to_jsonb(d)||jsonb_build_object('definition_id',$1,'body',(body-'existing_test')||jsonb_build_object('id',$1,'allowed_actions',jsonb_build_array('update_finding_response'),'verification_kind','finding_state','max_steps',1)))).* FROM zasp_security_agent_definitions d WHERE definition_id=$2`, pgx.QueryExecModeSimpleProtocol, definition, public62Definition); err != nil {
		t.Fatal(err)
	}
	for i, target := range []string{"validated", "supervised"} {
		var result []byte
		args := []any{o, w, e, definition, actor, fmt.Sprintf("key-preflight-legacy-activate-%d", i), i + 1, target, time.Now().UTC().Add(4 * time.Minute), fmt.Sprintf("pid_f%d000001-0000-4000-8000-000000000001", i), fmt.Sprintf("pid_f%d000002-0000-4000-8000-000000000002", i), fmt.Sprintf("pid_f%d000003-0000-4000-8000-000000000003", i)}
		if err := api.QueryRow(ctx, postgresSecurityAgentActivateSQL, args...).Scan(&result); err != nil {
			t.Fatal(err)
		}
	}
	var result []byte
	args := []any{o, w, e, definition, actor, key, 3, "pid_f2000001-0000-4000-8000-000000000001", "finding", public62Finding, "pid_f2000002-0000-4000-8000-000000000002", "pid_f2000003-0000-4000-8000-000000000003", "pid_f2000004-0000-4000-8000-000000000004"}
	if err := api.QueryRow(ctx, `SELECT zasp_security_agent_run_v24($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, args...).Scan(&result); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityAgentTriggerKeyPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		const legacy = "pid_ffffffff-ffff-4fff-8fff-fffffffffff1"
		const orderedKey = "trigger-key-ordered-0001"
		const legacyKey = "trigger-key-legacy-0001"
		triggerKeyLegacyFixture(t, ctx, owner, api, o, w, e, actor, legacy, legacyKey)
		check := func(definition, key, want string) {
			t.Helper()
			before := public62Snapshot(t, ctx, owner)
			got, err := public62Call(ctx, api, triggerKeyRequest(o, w, e, actor, definition, key))
			if err != nil || got["family"] != want || len(got) != 4 || got["definition_id"] != definition || got["idempotency_key"] != key || got["contract_version"] != float64(62) || public62Snapshot(t, ctx, owner) != before {
				t.Fatalf("key classification: %v %v", got, err)
			}
		}
		check(public62Definition, "trigger-key-absent-0001", "ordered_release61")
		check(legacy, "trigger-key-absent-0001", "legacy_or_missing")
		check(public62Finding, "trigger-key-absent-0001", "legacy_or_missing")
		check(legacy, legacyKey, "legacy_or_missing")
		for _, mutation := range []func(map[string]any){func(q map[string]any) { q["trigger_version"] = 1 }, func(q map[string]any) { q["idempotency_key"] = 42 }, func(q map[string]any) { delete(q, "definition_id") }} {
			q := triggerKeyRequest(o, w, e, actor, legacy, legacyKey)
			mutation(q)
			_, err := public62Call(ctx, api, q)
			if pg, ok := err.(*pgconn.PgError); !ok || pg.Code != "22023" {
				t.Fatal("open key input", err)
			}
		}
		a, id := orderedResourceGo(t, api, o, w, e, actor)
		legacyBody := ` { "environment_id":"` + e + `", "trigger_kind":"finding", "trigger_id":"` + public62Finding + `" } `
		legacyCalls := 0
		h := orderedHTTPHandler(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			legacyCalls++
			raw, err := io.ReadAll(r.Body)
			if err != nil || string(raw) != legacyBody {
				t.Fatal("legacy body changed")
			}
			w.WriteHeader(http.StatusAccepted)
		}))
		for _, key := range []string{legacyKey, "trigger-key-absent-0001"} {
			r := orderedHTTPRequest(id, "runSecurityAgent", "POST", legacy, legacyBody)
			r.Header.Set("Idempotency-Key", key)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
		}
		if legacyCalls != 2 {
			t.Fatal(legacyCalls)
		}
		if _, err := a.Activate(ctx, id, SecurityAgentOrderedActivation{public62Definition, 1, "supervised", "trigger-key-activate-0001"}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Trigger(ctx, id, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{public62Definition, 2, public62Finding, 1, orderedKey}, "finding", "credential"}); err != nil {
			t.Fatal(err)
		}
		check(public62Definition, orderedKey, "ordered_release61")
		check(legacy, orderedKey, "ordered_release61")
		beforeHTTP := public62Snapshot(t, ctx, owner)
		r := orderedHTTPRequest(id, "runSecurityAgent", "POST", legacy, legacyBody)
		r.Header.Set("Idempotency-Key", orderedKey)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, r)
		if response.Code != 400 || legacyCalls != 2 || public62Snapshot(t, ctx, owner) != beforeHTTP {
			t.Fatal("ordered receipt reached legacy", response.Code, legacyCalls)
		}
		for name, sql := range map[string]string{
			"soft-delete":   `UPDATE zasp_security_agent_definitions SET deleted_at=clock_timestamp() WHERE definition_id=$1`,
			"single-action": `UPDATE zasp_security_agent_definitions SET body=(body-'existing_test')||jsonb_build_object('allowed_actions',jsonb_build_array('update_finding_response'),'verification_kind','finding_state','max_steps',1) WHERE definition_id=$1`,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, "ROLLBACK")
				if _, err := owner.Exec(ctx, sql, public62Definition); err != nil {
					t.Fatal(err)
				}
				// The owner transaction sees its historical change while the API role
				// executes the real facade; rollback is only fixture cleanup.
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				got, err := public62Call(ctx, owner, triggerKeyRequest(o, w, e, actor, public62Definition, orderedKey))
				if err != nil || got["family"] != "ordered_release61" {
					t.Fatal(got, err)
				}
				historical, historicalID := orderedHTTPPostgresHandler(t, owner, o, w, e, actor)
				orderedHTTPCall(t, historical, historicalID, "activateSecurityAgent", public62Definition, `{"activation":"supervised"}`, "trigger-key-activate-0001", 1, 200)
				orderedHTTPCall(t, historical, historicalID, "runSecurityAgent", public62Definition, legacyBody, orderedKey, 2, 400)
				orderedHTTPCall(t, historical, historicalID, "runSecurityAgent", public62Definition, `{"environment_id":"`+e+`","trigger_kind":"finding","trigger_id":"`+public62Finding+`","trigger_version":1,"trigger_source":"credential"}`, orderedKey, 2, 202)
			})
		}
		for name, sql := range map[string]string{
			"missing-receipt":               `DELETE FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1`,
			"missing-receipt-damaged-audit": `DELETE FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1;UPDATE zasp_security_agent_audit SET event_kind='run_queued',actor_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',body=jsonb_set(body,'{request}',(body->'request')-'operation'-'actor_id') WHERE body->'request'->>'idempotency_key'=$1`,
			"relabelled-receipt":            `UPDATE zasp_security_agent_request_receipts SET operation='activateSecurityAgent' WHERE idempotency_key=$1`,
			"intent-version":                `UPDATE zasp_security_agent_request_receipts SET intent=intent-'trigger_version' WHERE idempotency_key=$1`,
			"intent-id":                     `UPDATE zasp_security_agent_request_receipts SET intent=jsonb_set(intent,'{trigger_id}','42') WHERE idempotency_key=$1`,
			"response":                      `UPDATE zasp_security_agent_request_receipts SET response=response-'run_id' WHERE idempotency_key=$1`,
			"audit":                         `DELETE FROM zasp_security_agent_audit WHERE body->'request'->>'idempotency_key'=$1`,
			"stripped":                      `DELETE FROM zasp_security_agent_audit WHERE body->'request'->>'idempotency_key'=$1;UPDATE zasp_security_agent_request_receipts SET intent=intent-'operation'-'trigger_version',response=response-'contract_version'-'run_id' WHERE idempotency_key=$1`,
			"legacy-intent":                 `UPDATE zasp_security_agent_request_receipts SET intent=jsonb_build_object('definition_id',resource_id,'expected_version',expected_version,'trigger_kind','finding','trigger_id','pid_8d300001-0000-4000-8000-000000000003') WHERE idempotency_key=$1`,
		} {
			t.Run(name, func(t *testing.T) {
				before := public62Snapshot(t, ctx, owner)
				if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol, orderedKey); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				_, err := public62Call(ctx, owner, triggerKeyRequest(o, w, e, actor, legacy, orderedKey))
				if pg, ok := err.(*pgconn.PgError); !ok || pg.Code != "40001" {
					t.Errorf("corruption became legacy: %v", err)
				}
				if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				if public62Snapshot(t, ctx, owner) != before {
					t.Fatal("classification changed owner")
				}
			})
		}
		before := public62Snapshot(t, ctx, owner)
		got, err := public62Call(ctx, api, triggerKeyRequest(o, w, e, orderedProgressionApprover, legacy, orderedKey))
		if err != nil || got["family"] != "legacy_or_missing" || public62Snapshot(t, ctx, owner) != before {
			t.Fatal("foreign actor claim", got, err)
		}
		foreign := "pid_ffffffff-ffff-4fff-8fff-fffffffffff2"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_authorized_scopes SELECT (jsonb_populate_record(NULL::zasp_authorized_scopes,to_jsonb(s)||jsonb_build_object('environment_id',$1))).* FROM zasp_authorized_scopes s WHERE principal_id=$2 AND environment_id=$3`, pgx.QueryExecModeSimpleProtocol, foreign, actor, e); err != nil {
			t.Fatal(err)
		}
		before = public62Snapshot(t, ctx, owner)
		got, err = public62Call(ctx, api, triggerKeyRequest(o, w, foreign, actor, legacy, orderedKey))
		if err != nil || got["family"] != "legacy_or_missing" || public62Snapshot(t, ctx, owner) != before {
			t.Fatal("foreign scope claim", got, err)
		}
		for name, sql := range map[string]string{
			"legacy-state-null":  `UPDATE zasp_security_agent_request_receipts SET response=response||'{"state":null}'::jsonb WHERE idempotency_key=$1`,
			"legacy-state-type":  `UPDATE zasp_security_agent_request_receipts SET response=response||'{"state":42}'::jsonb WHERE idempotency_key=$1`,
			"legacy-state-value": `UPDATE zasp_security_agent_request_receipts SET response=response||'{"state":"invented"}'::jsonb WHERE idempotency_key=$1`,
			"legacy-response":    `UPDATE zasp_security_agent_request_receipts SET response=response-'evidence_ids' WHERE idempotency_key=$1`,
			"legacy-digest":      `UPDATE zasp_security_agent_request_receipts SET intent_digest=decode(repeat('00',32),'hex') WHERE idempotency_key=$1`,
			"legacy-expired":     `UPDATE zasp_security_agent_request_receipts SET expires_at=clock_timestamp()-interval '1 second' WHERE idempotency_key=$1`,
			"legacy-audit":       `DELETE FROM zasp_security_agent_audit WHERE audit_id=(SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1)`,
			"legacy-audit-extra": `UPDATE zasp_security_agent_audit SET body=body||'{"contract_version":62}'::jsonb WHERE audit_id=(SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1)`,
		} {
			t.Run(name, func(t *testing.T) {
				before := public62Snapshot(t, ctx, owner)
				_, _ = owner.Exec(ctx, "BEGIN")
				if _, err := owner.Exec(ctx, sql, legacyKey); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				_, err := public62Call(ctx, owner, triggerKeyRequest(o, w, e, actor, legacy, legacyKey))
				if pg, ok := err.(*pgconn.PgError); !ok || pg.Code != "40001" {
					t.Error(err)
				}
				_, _ = owner.Exec(ctx, "ROLLBACK")
				if public62Snapshot(t, ctx, owner) != before {
					t.Fatal("legacy refusal changed owner")
				}
			})
		}
	})
}
