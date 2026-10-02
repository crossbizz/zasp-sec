package apiserver

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Losing the audit and both JSON tags must not erase canonical ordered claims.
// Genuine legacy receipts with the opposite operation's ordered key stay legacy.
func TestSecurityAgentOrderedResourceMutationMarkersPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		legacy, foreign := "pid_ffffffff-ffff-4fff-8fff-fffffffffff1", "pid_ffffffff-ffff-4fff-8fff-fffffffffff2"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_authorized_scopes SELECT (jsonb_populate_record(NULL::zasp_authorized_scopes,to_jsonb(s)||jsonb_build_object('environment_id',$1))).* FROM zasp_authorized_scopes s WHERE principal_id=$2 AND environment_id=$3`, pgx.QueryExecModeSimpleProtocol, foreign, actor, e); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definitions,to_jsonb(d)||jsonb_build_object('definition_id',$1,'body',(body-'existing_test')||jsonb_build_object('id',$1,'allowed_actions',jsonb_build_array('update_finding_response'),'verification_kind','finding_state','max_steps',1)))).* FROM zasp_security_agent_definitions d WHERE definition_id=$2`, pgx.QueryExecModeSimpleProtocol, legacy, public62Definition); err != nil {
			t.Fatal(err)
		}
		const activationKey, triggerKey = "ordered-marker-activation", "ordered-marker-trigger-01"
		// Produce ordinary receipts through the real legacy API, not owner inserts.
		for i, target := range []string{"validated", "supervised"} {
			key := "ordinary-legacy-validate"
			if i == 1 {
				key = triggerKey
			}
			args := []any{o, w, e, legacy, actor, key, i + 1, target, time.Now().UTC().Add(4 * time.Minute), fmt.Sprintf("pid_f%d000001-0000-4000-8000-000000000001", i), fmt.Sprintf("pid_f%d000002-0000-4000-8000-000000000002", i), fmt.Sprintf("pid_f%d000003-0000-4000-8000-000000000003", i)}
			var result []byte
			if err := api.QueryRow(ctx, postgresSecurityAgentActivateSQL, args...).Scan(&result); err != nil {
				t.Fatal("authentic legacy activation", err)
			}
		}
		var legacyRun []byte
		args := []any{o, w, e, legacy, actor, activationKey, 3, "pid_f2000001-0000-4000-8000-000000000001", "finding", public62Finding, "pid_f2000002-0000-4000-8000-000000000002", "pid_f2000003-0000-4000-8000-000000000003", "pid_f2000004-0000-4000-8000-000000000004"}
		if err := api.QueryRow(ctx, `SELECT zasp_security_agent_run_v24($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, args...).Scan(&legacyRun); err != nil {
			t.Fatal("authentic legacy trigger", err)
		}
		a, id := orderedResourceGo(t, api, o, w, e, actor)
		if _, err := a.Activate(ctx, id, SecurityAgentOrderedActivation{public62Definition, 1, "supervised", activationKey}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Trigger(ctx, id, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{public62Definition, 2, public62Finding, 1, triggerKey}, "finding", "credential"}); err != nil {
			t.Fatal(err)
		}
		t.Run("closed-trigger-input", func(t *testing.T) {
			before := public62Snapshot(t, ctx, owner)
			for name, trigger := range map[string]any{
				"missing": nil, "null": nil,
				"id-type":          map[string]any{"trigger_id": 42, "trigger_version": 1},
				"id-malformed":     map[string]any{"trigger_id": "invalid", "trigger_version": 1},
				"version-type":     map[string]any{"trigger_id": public62Finding, "trigger_version": "1"},
				"version-zero":     map[string]any{"trigger_id": public62Finding, "trigger_version": 0},
				"version-overflow": map[string]any{"trigger_id": public62Finding, "trigger_version": 1e50},
				"extra":            map[string]any{"trigger_id": public62Finding, "trigger_version": 1, "actor_id": actor},
				"activation-extra": map[string]any{"trigger_id": public62Finding, "trigger_version": 1},
			} {
				q := public62Request(o, w, e, actor, "classify_mutation")
				q["mutation_kind"], q["definition_id"], q["idempotency_key"] = "trigger", public62Definition, triggerKey
				if name != "missing" {
					q["trigger"] = trigger
				}
				if name == "activation-extra" {
					q["mutation_kind"] = "activate"
				}
				_, err := public62Call(ctx, api, q)
				if pg, ok := err.(*pgconn.PgError); !ok || pg.Code != "22023" {
					t.Errorf("%s: malformed identity reached derivation: %v", name, err)
				}
			}
			if public62Snapshot(t, ctx, owner) != before {
				t.Fatal("invalid identity changed owner state")
			}
		})
		for _, kind := range []SecurityAgentMutationKind{SecurityAgentMutationActivate, SecurityAgentMutationTrigger} {
			key, ordinaryKey := activationKey, triggerKey
			if kind == SecurityAgentMutationTrigger {
				key, ordinaryKey = triggerKey, activationKey
			}
			before := public62Snapshot(t, ctx, owner)
			for _, definition := range []string{legacy, public62Finding, public62Definition} {
				want := SecurityAgentFamilyLegacyOrMissing
				if definition == public62Definition {
					want = SecurityAgentFamilyOrderedRelease61
				}
				if got, err := a.resolver.ResolveMutation(ctx, id, kind, definition, ordinaryKey, orderedResourceTriggerIdentity(kind)); err != nil || got != want {
					t.Errorf("ordinary %s receipt: %s %v", kind, got, err)
				}
				for _, control := range []struct{ scope, principal, key string }{{e, actor, ordinaryKey}, {e, orderedProgressionApprover, key}, {foreign, actor, key}} {
					wantFamily := want
					if control.scope == foreign {
						wantFamily = SecurityAgentFamilyLegacyOrMissing
					}
					q := public62Request(o, w, control.scope, control.principal, "classify_mutation")
					q["mutation_kind"], q["definition_id"], q["idempotency_key"] = string(kind), definition, control.key
					if kind == SecurityAgentMutationTrigger {
						q["trigger"] = orderedResourceTriggerIdentity(kind)
					}
					if raw, err := public62Call(ctx, api, q); err != nil || raw["family"] != string(wantFamily) {
						t.Errorf("ordinary/foreign receipt: %v %v", raw, err)
					}
					ca, ci := orderedResourceGo(t, api, o, w, control.scope, control.principal)
					if got, err := ca.resolver.ResolveMutation(ctx, ci, kind, definition, control.key, orderedResourceTriggerIdentity(kind)); err != nil || got != wantFamily {
						t.Errorf("ordinary/foreign typed receipt: %s %v", got, err)
					}
					if wantFamily == SecurityAgentFamilyLegacyOrMissing {
						var err error
						if kind == SecurityAgentMutationActivate {
							_, err = ca.Activate(ctx, ci, SecurityAgentOrderedActivation{definition, 1, "supervised", control.key})
						} else {
							_, err = ca.Trigger(ctx, ci, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{definition, 2, public62Finding, 1, control.key}, "finding", "credential"})
						}
						if err != ErrSecurityAgentNotOwned {
							t.Errorf("ordinary/foreign mutation: got %v, want not-owned", err)
						}
					}
				}
			}
			if public62Snapshot(t, ctx, owner) != before {
				t.Fatal("ordinary receipt classification changed state")
			}
			for name, extra := range map[string]string{
				"canonical-identities": "",
				"receipt-only":         `UPDATE zasp_security_agent_request_receipts SET audit_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',correlation_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' WHERE idempotency_key=$1`,
				"audit-only":           `UPDATE zasp_security_agent_request_receipts SET receipt_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',correlation_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' WHERE idempotency_key=$1`,
				"correlation-only":     `UPDATE zasp_security_agent_request_receipts SET receipt_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',audit_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' WHERE idempotency_key=$1`,
				"malformed-resource":   `UPDATE zasp_security_agent_request_receipts SET resource_id='not-a-product-id' WHERE idempotency_key=$1`,
				"typed-intent-id":      `UPDATE zasp_security_agent_request_receipts SET intent=jsonb_set(intent,'{definition_id}','42') WHERE idempotency_key=$1`,
			} {
				t.Run(string(kind)+"/"+name, func(t *testing.T) {
					// Scope damage to this operation: another ordinary receipt shares K.
					if extra != "" {
						operation := "activateSecurityAgent"
						if kind == SecurityAgentMutationTrigger {
							operation = "runSecurityAgent"
						}
						extra += " AND operation='" + operation + "'"
					}
					damage := `DELETE FROM zasp_security_agent_audit WHERE audit_id IN (SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND response->'contract_version'='62'); UPDATE zasp_security_agent_request_receipts SET response=response-'contract_version'-'audit_id'-'correlation_id'-'receipt_id'-'run_id',intent=intent-'operation' WHERE idempotency_key=$1 AND response->'contract_version'='62'; ` + extra
					if kind == SecurityAgentMutationTrigger {
						// Remove the independent historical shape marker so these
						// identity probes cannot pass just because history claims it.
						damage += `; UPDATE zasp_security_agent_definition_versions SET definition=jsonb_set(definition,'{allowed_actions}','["update_finding_response"]') WHERE (definition_id,version)=(SELECT rr.definition_id,rr.definition_version FROM zasp_security_agent_runs rr JOIN zasp_security_agent_request_receipts q ON rr.run_id=q.resource_id WHERE q.idempotency_key=$1 AND q.operation='runSecurityAgent')`
					}
					orderedResourceMarkerRefusal(t, ctx, owner, api, o, w, e, actor, kind, key, legacy, damage)
				})
			}
			const otherIDs = `UPDATE zasp_security_agent_request_receipts SET audit_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',correlation_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',receipt_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' WHERE idempotency_key=$1 AND operation=`
			if kind == SecurityAgentMutationActivate {
				t.Run("activate/response-identities-only", func(t *testing.T) {
					damage := `DELETE FROM zasp_security_agent_audit WHERE audit_id IN (SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND response->'contract_version'='62'); UPDATE zasp_security_agent_request_receipts SET response=response-'contract_version',intent=intent-'operation' WHERE idempotency_key=$1 AND response->'contract_version'='62'; ` + otherIDs + "'activateSecurityAgent'"
					orderedResourceMarkerRefusal(t, ctx, owner, api, o, w, e, actor, kind, key, legacy, damage)
				})
			}
			t.Run(string(kind)+"/canonical-proof-only", func(t *testing.T) {
				op := "'activateSecurityAgent'"
				if kind == SecurityAgentMutationTrigger {
					op = "'runSecurityAgent'"
				}
				damage := `UPDATE zasp_security_agent_audit SET event_kind='definition_activated',body='{}' WHERE audit_id IN (SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND response->'contract_version'='62'); UPDATE zasp_security_agent_request_receipts SET response=response-'contract_version'-'audit_id'-'correlation_id'-'receipt_id'-'run_id',intent=intent-'operation' WHERE idempotency_key=$1 AND response->'contract_version'='62'; ` + otherIDs + op
				orderedResourceMarkerRefusal(t, ctx, owner, api, o, w, e, actor, kind, key, legacy, damage)
			})
			if kind == SecurityAgentMutationTrigger {
				for _, malformed := range []bool{false, true} {
					t.Run(fmt.Sprintf("trigger/response-run-only/%t", malformed), func(t *testing.T) {
						damage := `DELETE FROM zasp_security_agent_audit WHERE audit_id IN (SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND response->'contract_version'='62'); UPDATE zasp_security_agent_request_receipts SET response=response-'contract_version',intent=intent-'operation' WHERE idempotency_key=$1 AND response->'contract_version'='62'; ` + otherIDs + "'runSecurityAgent'"
						damage += `; UPDATE zasp_security_agent_definition_versions SET definition=jsonb_set(definition,'{allowed_actions}','["update_finding_response"]') WHERE (definition_id,version)=(SELECT rr.definition_id,rr.definition_version FROM zasp_security_agent_runs rr JOIN zasp_security_agent_request_receipts q ON rr.run_id=q.resource_id WHERE q.idempotency_key=$1 AND q.operation='runSecurityAgent')`
						if malformed {
							damage += `; UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(response,'{run_id}','42') WHERE idempotency_key=$1 AND operation='runSecurityAgent'`
						}
						orderedResourceMarkerRefusal(t, ctx, owner, api, o, w, e, actor, kind, key, legacy, damage)
					})
				}
				t.Run("trigger/run-history-only", func(t *testing.T) {
					damage := `DELETE FROM zasp_security_agent_audit WHERE audit_id IN (SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND response->'contract_version'='62'); UPDATE zasp_security_agent_request_receipts SET response=response-'contract_version'-'run_id',intent=intent-'operation' WHERE idempotency_key=$1 AND response->'contract_version'='62'; ` + otherIDs + "'runSecurityAgent'"
					orderedResourceMarkerRefusal(t, ctx, owner, api, o, w, e, actor, kind, key, legacy, damage)
				})
			}
			for _, missing := range []string{"deleted", "relabelled"} {
				corruptions := map[string]string{"full-body": "", "correlation": ",correlation_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'", "actor": ",actor_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'", "body": ",body=jsonb_set(body,'{response}','{}')"}
				if kind == SecurityAgentMutationActivate {
					corruptions["all-tags"] = ",actor_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',correlation_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',body='{}'"
				}
				for label, corrupt := range corruptions {
					t.Run(string(kind)+"/missing-receipt/"+missing+"/"+label, func(t *testing.T) {
						op := "activateSecurityAgent"
						definitions := []string{legacy, public62Finding}
						if kind == SecurityAgentMutationTrigger {
							op, definitions = "runSecurityAgent", []string{public62Definition}
						}
						damage := `UPDATE zasp_security_agent_audit SET event_kind='definition_activated'` + corrupt + ` WHERE audit_id=(SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND operation='` + op + `'); `
						if missing == "deleted" {
							damage += `DELETE FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND operation='` + op + `'`
						} else {
							damage += `UPDATE zasp_security_agent_request_receipts SET operation='simulateSecurityAgent' WHERE idempotency_key=$1 AND operation='` + op + `'`
						}
						if kind == SecurityAgentMutationTrigger {
							// Suppress definition-wide markers so exact trigger identity
							// must discover the independently retained canonical audit.
							damage += `; UPDATE zasp_security_agent_definitions SET body=(body-'existing_test')||'{"allowed_actions":["update_finding_response"],"max_steps":1,"verification_kind":"finding_state"}' WHERE definition_id='` + public62Definition + `'; UPDATE zasp_security_agent_definition_versions SET definition=jsonb_set(definition,'{allowed_actions}','["update_finding_response"]') WHERE definition_id='` + public62Definition + `'`
							damage += `; UPDATE zasp_security_agent_audit SET event_kind='definition_activated',body='{}' WHERE event_kind='ordered_public_activation_receipted' AND body->'request'->>'definition_id'='` + public62Definition + `'`
						}
						orderedResourceMarkerRefusal(t, ctx, owner, api, o, w, e, actor, kind, key, legacy, damage, definitions...)
					})
				}
			}
		}
		for _, mode := range []string{"erased-key", "foreign-actor", "distinct-key", "changed-trigger", "changed-definition-erased-key"} {
			t.Run("trigger/no-invented-provenance/"+mode, func(t *testing.T) {
				original := public62Snapshot(t, ctx, owner)
				if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				damage := `UPDATE zasp_security_agent_audit SET event_kind='definition_activated' WHERE audit_id=(SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND operation='runSecurityAgent'); DELETE FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND operation='runSecurityAgent'; UPDATE zasp_security_agent_definitions SET body=(body-'existing_test')||'{"allowed_actions":["update_finding_response"],"max_steps":1,"verification_kind":"finding_state"}' WHERE definition_id='` + public62Definition + `'; UPDATE zasp_security_agent_definition_versions SET definition=jsonb_set(definition,'{allowed_actions}','["update_finding_response"]') WHERE definition_id='` + public62Definition + `'; UPDATE zasp_security_agent_audit SET event_kind='definition_activated',body='{}' WHERE event_kind='ordered_public_activation_receipted' AND body->'request'->>'definition_id'='` + public62Definition + `'`
				if mode == "erased-key" || mode == "changed-definition-erased-key" {
					damage += `; UPDATE zasp_security_agent_audit SET body=jsonb_set(body,'{request}',(body->'request')-'idempotency_key') WHERE body->'request'->>'idempotency_key'=$1`
				}
				if _, err := owner.Exec(ctx, damage, pgx.QueryExecModeSimpleProtocol, triggerKey); err != nil {
					t.Fatal(err)
				}
				before := public62Snapshot(t, ctx, owner)
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				principal, key, definition := actor, triggerKey, public62Definition
				trigger := orderedResourceTriggerIdentity(SecurityAgentMutationTrigger)
				switch mode {
				case "foreign-actor":
					principal = orderedProgressionApprover
				case "distinct-key":
					key = "ordered-never-used-key"
				case "changed-trigger":
					trigger.TriggerID = public62Definition
				case "changed-definition-erased-key":
					definition = legacy
				}
				q := public62Request(o, w, e, principal, "classify_mutation")
				q["mutation_kind"], q["definition_id"], q["idempotency_key"], q["trigger"] = "trigger", definition, key, trigger
				if got, err := public62Call(ctx, owner, q); err != nil || got["family"] != "legacy_or_missing" {
					t.Fatal("invented actor/key/run provenance", got, err)
				}
				ca, ci := orderedResourceGo(t, owner, o, w, e, principal)
				if _, err := ca.Trigger(ctx, ci, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{definition, 2, trigger.TriggerID, trigger.TriggerVersion, key}, "finding", "credential"}); err != ErrSecurityAgentNotOwned {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `RESET SESSION AUTHORIZATION`); err != nil {
					t.Fatal(err)
				}
				if public62Snapshot(t, ctx, owner) != before {
					t.Fatal("no-claim classification mutated state")
				}
				if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil || public62Snapshot(t, ctx, owner) != original {
					t.Fatal("corruption probe leaked state", err)
				}
			})
		}
	})
}

func TestSecurityAgentOrderedResourceMissingReceiptRunMarkerPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		// Keep a genuine admitted run marker and actor/key-linked audit body,
		// but corrupt the audit ID and definition-wide links independently.
		damage := `UPDATE zasp_security_agent_audit SET audit_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',event_kind='definition_activated' WHERE audit_id=(SELECT audit_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND operation='runSecurityAgent'); DELETE FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1 AND operation='runSecurityAgent'; UPDATE zasp_security_agent_definitions SET body=(body-'existing_test')||'{"allowed_actions":["update_finding_response"],"max_steps":1,"verification_kind":"finding_state"}' WHERE definition_id='` + public62Definition + `'; UPDATE zasp_security_agent_definition_versions SET definition=jsonb_set(definition,'{allowed_actions}','["update_finding_response"]') WHERE definition_id='` + public62Definition + `'; UPDATE zasp_security_agent_audit SET event_kind='definition_activated',body='{}' WHERE event_kind='ordered_public_activated'; UPDATE zasp_sa_multistep_runs SET definition_id='pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' WHERE definition_id='` + public62Definition + `'`
		orderedResourceMarkerRefusal(t, ctx, owner, api, o, w, e, actor, SecurityAgentMutationTrigger, "public62-execution-0001", public62Finding, damage, public62Definition)
	})
}

func orderedResourceMarkerRefusal(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string, kind SecurityAgentMutationKind, key, legacy, damage string, definitions ...string) {
	t.Helper()
	original := public62Snapshot(t, ctx, owner)
	if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(ctx, `ROLLBACK`)
	if _, err := owner.Exec(ctx, damage, pgx.QueryExecModeSimpleProtocol, key); err != nil {
		t.Fatal(err)
	}
	before := public62Snapshot(t, ctx, owner)
	if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	a, id := orderedResourceGo(t, owner, o, w, e, actor)
	if len(definitions) == 0 {
		definitions = []string{legacy, public62Finding}
	}
	for _, definition := range definitions {
		if _, err := owner.Exec(ctx, `SAVEPOINT classification`); err != nil {
			t.Fatal(err)
		}
		q := public62Request(o, w, e, actor, "classify_mutation")
		q["mutation_kind"], q["definition_id"], q["idempotency_key"] = string(kind), definition, key
		if kind == SecurityAgentMutationTrigger {
			q["trigger"] = orderedResourceTriggerIdentity(kind)
		}
		if got, err := public62Call(ctx, owner, q); err == nil {
			t.Errorf("raw corrupt %s classified: %v", kind, got)
		} else if pg, ok := err.(*pgconn.PgError); !ok || pg.Code != "40001" {
			t.Errorf("raw corrupt %s: want safe ownership refusal, got %v", kind, err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK TO classification`); err != nil {
			t.Fatal(err)
		}
		var err error
		if kind == SecurityAgentMutationActivate {
			_, err = a.Activate(ctx, id, SecurityAgentOrderedActivation{definition, 1, "supervised", key})
		} else {
			_, err = a.Trigger(ctx, id, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{definition, 2, public62Finding, 1, key}, "finding", "credential"})
		}
		if err != ErrRepositoryUnavailable {
			t.Errorf("typed corrupt %s: got %v, want unavailable (never not-owned)", kind, err)
		}
		// Refusal must originate inside SQL, not after committing and decoding.
		if _, err := owner.Exec(ctx, `SELECT 1`); err == nil {
			t.Error("typed refusal did not abort the SQL statement transaction")
		} else if pg, ok := err.(*pgconn.PgError); !ok || pg.Code != "25P02" {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK TO classification`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(ctx, `RESET SESSION AUTHORIZATION`); err != nil {
		t.Fatal(err)
	}
	if public62Snapshot(t, ctx, owner) != before {
		t.Fatal("refusal changed corrupt owner snapshot")
	}
	if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	if public62Snapshot(t, ctx, owner) != original {
		t.Fatal("corruption probe leaked owner changes")
	}
}

// Removing receipt-bound activation or the stable product projection must fail
// this test through the API principal, not through an owner success fixture.
func TestSecurityAgentOrderedResourceActivationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		read := public62Request(o, w, e, actor, "resource_activation")
		read["definition_id"] = public62Definition
		got, err := public62Call(ctx, api, read)
		if err != nil || got["activation"] != "draft" {
			t.Fatal(got, err)
		}
		q := public62Request(o, w, e, actor, "activate_resource")
		q["definition_id"], q["definition_version"], q["activation"], q["idempotency_key"] = public62Definition, 1, "supervised", "ordered-resource-activation-1"
		activated, err := public62Call(ctx, api, q)
		if err != nil || activated["version"] != float64(2) || activated["audit_id"] == "" || activated["receipt_id"] == "" {
			t.Fatal(activated, err)
		}
		before := public62Snapshot(t, ctx, owner)
		replay, err := public62Call(ctx, api, q)
		if err != nil || replay["replayed"] != true || replay["receipt_id"] != activated["receipt_id"] || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(replay, err)
		}
		q["activation"] = "validated"
		if _, err := public62Call(ctx, api, q); err == nil || public62Snapshot(t, ctx, owner) != before {
			t.Fatal("changed intent accepted", err)
		}
		q["activation"] = "supervised"
		t.Run("activation-history-binding", func(t *testing.T) {
			orderedResourceRefusal(t, ctx, owner, api, q, public62Definition, `UPDATE zasp_security_agent_definition_versions SET definition=jsonb_set(definition,'{name}','"Changed snapshot"'),definition_digest=digest(convert_to(jsonb_set(definition,'{name}','"Changed snapshot"')::text,'UTF8'),'sha256') WHERE definition_id=$1`)
		})
		t.Run("activation-marker", func(t *testing.T) {
			classify := public62Request(o, w, e, actor, "classify")
			classify["resource_kind"], classify["resource_id"] = "definition", public62Definition
			orderedResourceRefusal(t, ctx, owner, api, classify, public62Definition, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{allowed_actions}','["update_finding_response"]') WHERE definition_id=$1; DELETE FROM zasp_security_agent_definition_versions WHERE definition_id=$1`)
		})
		q = public62Request(o, w, e, actor, "trigger_resource")
		q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["trigger_kind"], q["trigger_source"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "finding", "credential", "ordered-resource-trigger-01"
		triggered, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal(err)
		}
		before = public62Snapshot(t, ctx, owner)
		replay, err = public62Call(ctx, api, q)
		if err != nil || replay["replayed"] != true || replay["receipt_id"] != triggered["receipt_id"] || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(replay, err)
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_request_receipts WHERE receipt_id=$1 AND audit_id=$2 AND correlation_id=$2`, triggered["receipt_id"], triggered["audit_id"]).Scan(&count); err != nil || count != 1 {
			t.Fatal("invented trigger proof", count, err)
		}
		read = public62Request(o, w, e, actor, "resource_run")
		read["run_id"] = triggered["id"]
		detail, err := public62Call(ctx, api, read)
		if err != nil || detail["trigger_id"] != public62Finding || detail["created_at"] == "" || detail["plan"] != nil {
			t.Fatal(detail, err)
		}
	})
}

func orderedResourceRefusal(t *testing.T, ctx context.Context, owner, api *pgx.Conn, q map[string]any, resource, mutation string) {
	t.Helper()
	before := public62Snapshot(t, ctx, owner)
	if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, mutation, pgx.QueryExecModeSimpleProtocol, resource); err != nil {
		_, _ = owner.Exec(ctx, `ROLLBACK`)
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	_, err := public62Call(ctx, owner, q)
	if _, rollback := owner.Exec(ctx, `ROLLBACK`); rollback != nil {
		t.Fatal(rollback)
	}
	if err == nil || public62Snapshot(t, ctx, owner) != before {
		t.Fatal("contradiction accepted or refusal changed state", err)
	}
}

func TestSecurityAgentOrderedResourceDecisionPostgres(t *testing.T) {
	for _, decision := range []string{"approved", "rejected"} {
		t.Run(decision, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
				run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
				var approval string
				if err := owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1 AND step_id=$2`, run, steps[0]).Scan(&approval); err != nil {
					t.Fatal(err)
				}
				q := public62Request(o, w, e, orderedProgressionApprover, "decide_resource")
				q["approval_id"], q["approval_version"], q["decision"], q["idempotency_key"], q["fresh_auth_at"] = approval, 1, decision, "ordered-resource-decision-1", time.Now().UTC().Format(time.RFC3339Nano)
				result, err := public62Call(ctx, api, q)
				if err != nil {
					t.Fatal(err)
				}
				if result["mutation"].(map[string]any)["decision"] != decision {
					t.Fatal(result)
				}
				before := public62Snapshot(t, ctx, owner)
				replay, err := public62Call(ctx, api, q)
				if err != nil || replay["mutation"].(map[string]any)["replayed"] != true || public62Snapshot(t, ctx, owner) != before {
					t.Fatal(replay, err)
				}
			})
		})
	}
}

// Retained receipt ownership must survive legitimate current-definition edits;
// a caller changing intent still reaches immutable replay conflict, not legacy.
func TestSecurityAgentOrderedResourceMutationReplayPostgres(t *testing.T) {
	for name, mutation := range map[string]string{
		"newer-ordered": `UPDATE zasp_security_agent_definitions SET version=3,definition_version=2,body=jsonb_set(body||'{"name":"new ordered revision"}','{definition_version}','2') WHERE definition_id=$1;
INSERT INTO zasp_security_agent_definition_versions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definition_versions,to_jsonb(h)||jsonb_build_object('version',3,'definition',d.body,'definition_digest',digest(convert_to(d.body::text,'UTF8'),'sha256')))).* FROM zasp_security_agent_definition_versions h JOIN zasp_security_agent_definitions d USING(organization_id,workspace_id,environment_id,definition_id) WHERE d.definition_id=$1 AND h.version=2`,
		"single-action": `UPDATE zasp_security_agent_definitions SET version=3,activation='draft',body=(body-'existing_test')||'{"allowed_actions":["create_temporary_policy"],"max_steps":1,"enabled":false}' WHERE definition_id=$1;
INSERT INTO zasp_security_agent_definition_versions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definition_versions,to_jsonb(h)||jsonb_build_object('version',3,'activation','draft','definition',d.body,'definition_digest',digest(convert_to(d.body::text,'UTF8'),'sha256')))).* FROM zasp_security_agent_definition_versions h JOIN zasp_security_agent_definitions d USING(organization_id,workspace_id,environment_id,definition_id) WHERE d.definition_id=$1 AND h.version=2`,
		"soft-deleted": `UPDATE zasp_security_agent_definitions SET deleted_at=clock_timestamp() WHERE definition_id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
				if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
					t.Fatal(err)
				}
				public62Seed(t, ctx, owner, o, w, e, testID, actor)
				a, id := orderedResourceGo(t, api, o, w, e, actor)
				aq := SecurityAgentOrderedActivation{public62Definition, 1, "supervised", "1234567890123456"}
				activated, err := a.Activate(ctx, id, aq)
				if err != nil {
					t.Fatal(err)
				}
				tq := SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{public62Definition, 2, public62Finding, 1, "2345678901234567"}, "finding", "credential"}
				triggered, err := a.Trigger(ctx, id, tq)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, mutation, pgx.QueryExecModeSimpleProtocol, public62Definition); err != nil {
					t.Fatal(err)
				}
				conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close(ctx)
				restarted, _ := orderedResourceGo(t, conn, o, w, e, actor)
				before := public62Snapshot(t, ctx, owner)
				activated.Replayed, triggered.Replayed = true, true
				if got, err := restarted.Activate(ctx, id, aq); err != nil || got != activated {
					t.Errorf("retained activation: %v %v", got, err)
				}
				if got, err := restarted.Trigger(ctx, id, tq); err != nil || !reflect.DeepEqual(got, triggered) {
					t.Errorf("retained trigger: %v %v", got, err)
				}
				for _, kind := range []string{"activate", "trigger"} {
					key, op := aq.IdempotencyKey, "activate_resource"
					q := public62Request(o, w, e, actor, op)
					q["definition_id"], q["definition_version"], q["activation"], q["idempotency_key"] = public62Definition, 1, "supervised", key
					if kind == "trigger" {
						key, op = tq.IdempotencyKey, "trigger_resource"
						q = public62Request(o, w, e, actor, op)
						q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["trigger_kind"], q["trigger_source"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "finding", "credential", key
					}
					classify := public62Request(o, w, e, actor, "classify_mutation")
					classify["mutation_kind"], classify["definition_id"], classify["idempotency_key"] = kind, public62Definition, key
					if kind == "trigger" {
						classify["trigger"] = orderedResourceTriggerIdentity(SecurityAgentMutationTrigger)
					}
					if got, err := public62Call(ctx, conn, classify); err != nil || got["family"] != "ordered_release61" {
						t.Errorf("retained %s classifier: %v %v", kind, got, err)
					}
					if got, err := public62Call(ctx, conn, q); err != nil || got["replayed"] != true {
						t.Errorf("raw %s replay: %v %v", kind, got, err)
					}
					if name == "soft-deleted" {
						for label, damage := range map[string]string{
							"receipt-id":      `UPDATE zasp_security_agent_request_receipts SET receipt_id='pid_ffffffff-ffff-4fff-8fff-ffffffffffff' WHERE idempotency_key=$1`,
							"correlation":     `UPDATE zasp_security_agent_request_receipts SET correlation_id='pid_ffffffff-ffff-4fff-8fff-ffffffffffff' WHERE idempotency_key=$1`,
							"intent-digest":   `UPDATE zasp_security_agent_request_receipts SET intent_digest=decode(repeat('00',32),'hex') WHERE idempotency_key=$1`,
							"intent-key-type": `UPDATE zasp_security_agent_request_receipts SET intent=jsonb_set(intent,'{idempotency_key}',to_jsonb(idempotency_key::numeric)) WHERE idempotency_key=$1; UPDATE zasp_security_agent_request_receipts SET intent_digest=digest(convert_to(intent::text,'UTF8'),'sha256') WHERE idempotency_key=$1; UPDATE zasp_security_agent_audit a SET body=jsonb_set(body,'{request}',r.intent) FROM zasp_security_agent_request_receipts r WHERE r.idempotency_key=$1 AND a.audit_id=r.audit_id; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE body->'request'->>'idempotency_key'=$1`,
							"receipt-missing": `DELETE FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1`,
							"operation":       `UPDATE zasp_security_agent_request_receipts SET operation=CASE operation WHEN 'runSecurityAgent' THEN 'activateSecurityAgent' ELSE 'runSecurityAgent' END WHERE idempotency_key=$1`,
							"audit-missing":   `DELETE FROM zasp_security_agent_audit WHERE body->'request'->>'idempotency_key'=$1`,
							"audit-digest":    `UPDATE zasp_security_agent_audit SET event_digest=decode(repeat('00',32),'hex') WHERE body->'request'->>'idempotency_key'=$1`,
							"snapshot":        `UPDATE zasp_security_agent_definition_versions SET definition=jsonb_set(definition,'{name}','"changed immutable snapshot"'),definition_digest=digest(convert_to(jsonb_set(definition,'{name}','"changed immutable snapshot"')::text,'UTF8'),'sha256') WHERE version=2 AND definition_id=(SELECT intent->>'definition_id' FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1)`,
						} {
							t.Run(kind+"/"+label, func(t *testing.T) {
								orderedResourceRefusal(t, ctx, owner, conn, classify, key, damage)
								orderedResourceRefusal(t, ctx, owner, conn, q, key, damage)
							})
						}
						if kind == "trigger" {
							t.Run("trigger/history", func(t *testing.T) {
								orderedResourceRefusal(t, ctx, owner, conn, classify, key, `UPDATE zasp_security_agent_trigger_receipts SET trigger_digest=decode(repeat('00',32),'hex') WHERE run_id=(SELECT resource_id FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1)`)
							})
						}
					}
				}
				aq.Version = 2
				if _, err := restarted.Activate(ctx, id, aq); err != ErrRepositoryConflict {
					t.Errorf("changed activation: %v", err)
				}
				tq.TriggerSource = "wrong"
				if _, err := restarted.Trigger(ctx, id, tq); err != ErrRepositoryConflict {
					t.Errorf("changed trigger: %v", err)
				}
				aq.Version, aq.DefinitionID = 1, public62Finding
				if _, err := restarted.Activate(ctx, id, aq); err != ErrRepositoryConflict {
					t.Errorf("changed activation resource: %v", err)
				}
				tq.TriggerSource, tq.DefinitionID = "credential", public62Finding
				if _, err := restarted.Trigger(ctx, id, tq); err != ErrRepositoryConflict {
					t.Errorf("changed trigger resource: %v", err)
				}
				if public62Snapshot(t, ctx, owner) != before {
					t.Fatal("replay/refusal changed owner authority")
				}
			})
		})
	}
}

func TestSecurityAgentOrderedResourceMutationNotOwnedPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		legacy, foreign := "pid_ffffffff-ffff-4fff-8fff-fffffffffff1", "pid_ffffffff-ffff-4fff-8fff-fffffffffff2"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definitions,to_jsonb(d)||jsonb_build_object('definition_id',$1,'body',(body-'existing_test')||jsonb_build_object('id',$1,'allowed_actions',jsonb_build_array('create_temporary_policy'),'max_steps',1)))).* FROM zasp_security_agent_definitions d WHERE definition_id=$2;
INSERT INTO zasp_authorized_scopes SELECT (jsonb_populate_record(NULL::zasp_authorized_scopes,to_jsonb(s)||jsonb_build_object('environment_id',$3))).* FROM zasp_authorized_scopes s WHERE principal_id=$4 AND environment_id=$5`, pgx.QueryExecModeSimpleProtocol, legacy, public62Definition, foreign, actor, e); err != nil {
			t.Fatal(err)
		}
		before := public62Snapshot(t, ctx, owner)
		for _, scope := range []string{e, foreign} {
			a, id := orderedResourceGo(t, api, o, w, scope, actor)
			for _, credential := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
				id.CredentialKind = credential
				for _, definition := range []string{legacy, public62Finding, public62Definition} {
					want := SecurityAgentFamilyLegacyOrMissing
					if scope == e && definition == public62Definition {
						want = SecurityAgentFamilyOrderedRelease61
					}
					for _, kind := range []SecurityAgentMutationKind{SecurityAgentMutationActivate, SecurityAgentMutationTrigger} {
						got, err := a.resolver.ResolveMutation(ctx, id, kind, definition, "ordered-unowned-classification", orderedResourceTriggerIdentity(kind))
						if got != want || err != nil {
							t.Fatal(scope, credential, definition, kind, got, err)
						}
						q := public62Request(o, w, scope, actor, "classify_mutation")
						q["mutation_kind"], q["definition_id"], q["idempotency_key"] = string(kind), definition, "ordered-unowned-classification"
						if kind == SecurityAgentMutationTrigger {
							q["trigger"] = orderedResourceTriggerIdentity(kind)
						}
						if raw, err := public62Call(ctx, api, q); err != nil || raw["family"] != string(want) {
							t.Fatal(raw, err)
						}
					}
					if want == SecurityAgentFamilyOrderedRelease61 && credential == CredentialBrowserSession {
						continue
					}
					wantErr := ErrSecurityAgentNotOwned
					if want == SecurityAgentFamilyOrderedRelease61 {
						wantErr = ErrRepositoryOperation
					}
					if _, err := a.Activate(ctx, id, SecurityAgentOrderedActivation{definition, 1, "supervised", "ordered-unowned-classification"}); err != wantErr {
						t.Fatal(err, wantErr)
					}
					if _, err := a.Trigger(ctx, id, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{definition, 1, public62Finding, 1, "ordered-unowned-classification"}, "finding", "credential"}); err != wantErr {
						t.Fatal(err, wantErr)
					}
				}
			}
		}
		if public62Snapshot(t, ctx, owner) != before {
			t.Fatal("classification/refusal changed state")
		}
	})
}
