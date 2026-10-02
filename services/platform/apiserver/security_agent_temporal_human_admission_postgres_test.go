package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catches production HTTP admissions that lack exclusive ownership before
// delivery, or whose human source cannot enter the specialized test executor.
func TestTemporalHumanAdmissionHTTPPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalTestSelector(ctx); err != nil {
			t.Fatal(err)
		}
		if up, ok := any(precisionMigrationRunner(t, owner)).(interface{ UpProductionTemporalHumanAdmission(context.Context) error }); ok {
			if err := up.UpProductionTemporalHumanAdmission(ctx); err != nil {
				tx, txErr := owner.Begin(ctx)
				if txErr != nil {
					t.Fatal(txErr)
				}
				defer tx.Rollback(ctx)
				_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalHumanAdmission().UpSQL())
				var pin string
				pinErr := tx.QueryRow(ctx, `SELECT zasp_temporal76.fingerprint()`).Scan(&pin)
				t.Logf("independent76 compile DDL=%v fingerprint_error=%v fingerprint=%s", ddlErr, pinErr, pin)
				t.Fatal("install76", err)
			}
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE human_test_executor LOGIN; CREATE ROLE human_test_compensation LOGIN; SELECT zasp_temporal68.register_principals('human_test_executor','human_test_compensation')`); err != nil {
			t.Fatal(err)
		}
		connect := func(user string) *pgx.Conn {
			cfg := owner.Config().Copy()
			cfg.User = user
			c, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close(context.Background()) })
			return c
		}
		executor := connect("human_test_executor")
		worker := connect("security_agent_v33_worker_login")
		workerDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		retained, err := NewSecurityAgentWorkerRepository(workerDB)
		if err != nil {
			t.Fatal(err)
		}
		authority, identity := orderedResourceGo(t, api, o, w, e, actor)
		db := authority.repository.database.(*PostgresJSONDatabase)
		repository := &PostgresRepository{database: db, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		sequence := 0
		config := SecurityAgentPublicHandlerConfig{Clock: time.Now, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) {
			sequence++
			return fmt.Sprintf("pid_f0760000-0000-4000-8000-%012d", sequence), nil
		}}
		for _, ordered := range []bool{false, true} {
			for _, kind := range []string{"manual", "finding"} {
				t.Run(fmt.Sprintf("ordered=%t/%s", ordered, kind), func(t *testing.T) {
					if ordered && kind == "finding" {
						if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=2 WHERE id=$1`, public62Finding); err != nil {
							t.Fatal(err)
						}
					}
					handler, err := newSecurityAgentProductionHTTPHandler(ctx, repository, http.NotFoundHandler(), config, ordered)
					if err != nil {
						t.Fatal("selected production handler", err)
					}
					body := `{"environment_id":"` + e + `"}`
					if kind == "finding" {
						body = `{"environment_id":"` + e + `","trigger_kind":"finding","trigger_id":"` + public62Finding + `"}`
						if ordered {
							body = `{"environment_id":"` + e + `","trigger_kind":"finding","trigger_id":"` + public62Finding + `","trigger_version":2,"trigger_source":"credential"}`
						}
					}
					key := fmt.Sprintf("human-admission-%t-%s", ordered, kind)
					request := func(expected int64) *httptest.ResponseRecorder {
						r := workflowRequest(t, identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": temporalTestLegacyProved}, http.MethodPost, "/api/v1/security-agents/"+temporalTestLegacyProved+"/runs", body)
						r.Header.Set("Idempotency-Key", key)
						r.Header.Set("If-Match", `"`+strconv.FormatInt(expected, 10)+`"`)
						response := httptest.NewRecorder()
						handler.ServeHTTP(response, r)
						return response
					}
					first := request(4)
					if first.Code != http.StatusAccepted {
						family, classifyErr := authority.resolver.Resolve(ctx, identity, SecurityAgentResourceDefinition, temporalTestLegacyProved)
						t.Logf("actual definition owner=%s error=%v", family, classifyErr)
						if kind == "finding" {
							if _, beginErr := api.Exec(ctx, "BEGIN"); beginErr != nil {
								t.Fatal(beginErr)
							}
							actual, handled, actualErr := db.RunTemporalHumanTest(ctx, identity, SecurityAgentRunRequest{DefinitionID: temporalTestLegacyProved, ExpectedVersion: 4, IdempotencyKey: key, RunID: "pid_f0760000-0000-4000-8000-000000009001", TriggerKind: "finding", TriggerID: public62Finding, AuditID: "pid_f0760000-0000-4000-8000-000000009002", CorrelationID: testCorrelationID, ReceiptID: "pid_f0760000-0000-4000-8000-000000009003"})
							t.Logf("actual76 omitted pointer query handled=%t result=%s error=%v", handled, actual, actualErr)
							if _, rollbackErr := api.Exec(ctx, "ROLLBACK"); rollbackErr != nil {
								t.Fatal(rollbackErr)
							}
							var diagnostic []byte
							args := existingTestReadPins([]any{o, w, e, temporalTestLegacyProved, actor, key, int64(4), "pid_f0760000-0000-4000-8000-000000009001", "finding", public62Finding, "pid_f0760000-0000-4000-8000-000000009002", testCorrelationID, "pid_f0760000-0000-4000-8000-000000009003"})
							diagnosticErr := api.QueryRow(ctx, postgresExistingTestRunSQL, args...).Scan(&diagnostic)
							t.Logf("registered resource SQL diagnostic=%s error=%v", diagnostic, diagnosticErr)
						}
						t.Fatalf("actual selected HTTP admission status=%d body=%s", first.Code, first.Body.String())
					}
					var run SecurityAgentRun
					if err := json.Unmarshal(first.Body.Bytes(), &run); err != nil || run.ID == "" {
						t.Fatal("typed response", run, err)
					}
					defer func() {
						sequence += 3
						_, err := repository.CancelSecurityAgentRun(ctx, identity, SecurityAgentCancelRequest{RunID: run.ID, ExpectedVersion: 1, IdempotencyKey: key + "-cancel", AuditID: fmt.Sprintf("pid_f0760000-0000-4000-8000-%012d", sequence), CorrelationID: testCorrelationID, ReceiptID: fmt.Sprintf("pid_f0760000-0000-4000-8000-%012d", sequence+1)})
						if err != nil {
							t.Error("cleanup actual admission", err)
						}
					}()
					var rows []byte
					if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('run',to_jsonb(r),'receipt',(SELECT to_jsonb(q) FROM zasp_security_agent_request_receipts q WHERE q.response->>'id'=r.run_id AND q.operation='runSecurityAgent'),'start65',(SELECT to_jsonb(c) FROM zasp_temporal65.commands c WHERE c.run_id=r.run_id AND c.kind='start'),'owner66',(SELECT to_jsonb(x) FROM zasp_temporal66.run_owners x WHERE x.run_id=r.run_id),'admission73',(SELECT to_jsonb(a) FROM zasp_temporal73.admissions a WHERE a.run_id=r.run_id),'owner74',(SELECT to_jsonb(x) FROM zasp_temporal74.run_owners x WHERE x.run_id=r.run_id)) FROM zasp_security_agent_runs r WHERE r.run_id=$1`, run.ID).Scan(&rows); err != nil {
						t.Fatal(err)
					}
					t.Logf("committed caller=%T kind=%s rows=%s", handler, kind, rows)
					replay := request(4)
					if replay.Code != 202 || replay.Body.String() != first.Body.String() || replay.Header().Get("X-Mutation-Receipt-ID") != first.Header().Get("X-Mutation-Receipt-ID") {
						t.Error("HTTP receipt replay", replay.Code, replay.Body.String())
					}
					if conflict := request(5); conflict.Code != http.StatusConflict {
						t.Error("changed intent did not conflict", conflict.Code, conflict.Body.String())
					}
					if kind == "finding" {
						original := body
						if ordered {
							body = `{"environment_id":"` + e + `","trigger_kind":"finding","trigger_id":"` + public62Finding + `"}`
						} else {
							body = `{"environment_id":"` + e + `","trigger_kind":"finding","trigger_id":"` + public62Finding + `","trigger_version":1,"trigger_source":"credential"}`
						}
						if changed := request(4); changed.Code != http.StatusConflict {
							t.Errorf("changed optional intent silently replayed: status=%d body=%s", changed.Code, changed.Body.String())
						}
						body = original
					}
					if _, err := worker.Exec(ctx, "BEGIN"); err != nil {
						t.Fatal(err)
					}
					claims, claimErr := retained.ClaimSecurityAgentRuns(ctx, "human-delayed-takeover", "human-delayed-takeover-claim-token", 30, 10)
					if _, err := worker.Exec(ctx, "ROLLBACK"); err != nil {
						t.Fatal(err)
					}
					if claimErr != nil || len(claims) != 0 {
						t.Errorf("retained claim crossed committed human admission: claims=%+v err=%v", claims, claimErr)
					}
					if _, err := executor.Exec(ctx, "BEGIN"); err != nil {
						t.Fatal(err)
					}
					var takeover []byte
					err = executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, run.ID).Scan(&takeover)
					if _, rollbackErr := executor.Exec(ctx, "ROLLBACK"); rollbackErr != nil {
						t.Fatal(rollbackErr)
					}
					if err != nil || string(takeover) == "null" {
						t.Errorf("human admission missing specialized takeover: result=%s err=%v", takeover, err)
					} else {
						t.Logf("takeover=%s", takeover)
					}
					if kind == "finding" {
						if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1 WHERE id=$1`, public62Finding); err != nil {
							t.Fatal(err)
						}
						if stale := request(4); stale.Code != http.StatusConflict {
							t.Errorf("source-changed replay accepted: %d %s", stale.Code, stale.Body.String())
						}
					}
				})
			}
		}
	})
}
