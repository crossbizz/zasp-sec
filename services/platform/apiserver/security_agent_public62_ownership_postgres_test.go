package apiserver

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func public62ClassifyRequest(o, w, e, actor, kind, resource string) map[string]any {
	q := public62Request(o, w, e, actor, "classify")
	q["resource_kind"], q["resource_id"] = kind, resource
	return q
}

// Mutable definition edits cannot erase a run's pinned historical ownership.
// Missing or contradictory pinned history must still refuse classification.
func public62OwnershipHistoryProbes(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor, run string, approvals ...string) {
	t.Helper()
	before := public62Snapshot(t, ctx, owner)
	for name, mutation := range map[string]string{
		"newer-ordered": `UPDATE zasp_security_agent_definitions SET version=version+1,definition_version=definition_version+1,body=jsonb_set(body||'{"name":"new ordered revision"}','{definition_version}',to_jsonb(definition_version+1)) WHERE definition_id=$1;
 INSERT INTO zasp_security_agent_definition_versions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definition_versions,to_jsonb(h)||jsonb_build_object('version',d.version,'definition',d.body,'definition_digest',digest(convert_to(d.body::text,'UTF8'),'sha256')))).* FROM zasp_security_agent_definition_versions h JOIN zasp_security_agent_definitions d USING(organization_id,workspace_id,environment_id,definition_id) WHERE d.definition_id=$1 AND h.version=(SELECT definition_version FROM zasp_security_agent_runs WHERE run_id=$2)`,
		"single-action":  `UPDATE zasp_security_agent_definitions SET version=version+1,activation='draft',body=(body-'existing_test')||'{"allowed_actions":["create_temporary_policy"],"max_steps":1,"enabled":false}' WHERE definition_id=$1`,
		"soft-deleted":   `UPDATE zasp_security_agent_definitions SET deleted_at=clock_timestamp() WHERE definition_id=$1`,
		"pinned-missing": `DELETE FROM zasp_security_agent_definition_versions WHERE definition_id=$1 AND version=(SELECT definition_version FROM zasp_security_agent_runs WHERE run_id=$2)`,
		"pinned-corrupt": `UPDATE zasp_security_agent_definition_versions SET definition=definition||'{"max_steps":1}' WHERE definition_id=$1 AND version=(SELECT definition_version FROM zasp_security_agent_runs WHERE run_id=$2)`,
	} {
		t.Run("history-"+name, func(t *testing.T) {
			for _, resource := range append([]string{run}, approvals...) {
				func() {
					if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica`); err != nil {
						t.Fatal(err)
					}
					defer owner.Exec(ctx, `ROLLBACK`)
					if _, err := owner.Exec(ctx, mutation+`; SELECT $1::text,$2::text`, pgx.QueryExecModeSimpleProtocol, public62Definition, run); err != nil {
						t.Fatal(err)
					}
					if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
						t.Fatal(err)
					}
					kind := "approval"
					if resource == run {
						kind = "run"
					}
					got, err := public62Call(ctx, owner, public62ClassifyRequest(o, w, e, actor, kind, resource))
					if name == "pinned-missing" || name == "pinned-corrupt" {
						var pg *pgconn.PgError
						if !errors.As(err, &pg) || pg.Code != "40001" {
							t.Fatalf("contradictory pinned %s: %v %v", kind, got, err)
						}
					} else if err != nil || got["family"] != "ordered_release61" {
						t.Errorf("retained %s ownership erased: %v %v", kind, got, err)
					}
				}()
			}
		})
	}
	if before != public62Snapshot(t, ctx, owner) {
		t.Fatal("historical classification changed owner state")
	}
}

// Removing positive authority checks must either lose an owned resource or
// accept a corrupted one; neither can silently dispatch to a legacy boundary.
func TestSecurityAgentPublic62OwnershipPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		var approval string
		if err := owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1`, run).Scan(&approval); err != nil {
			t.Fatal(err)
		}
		public62OwnershipHistoryProbes(t, ctx, owner, api, o, w, e, actor, run, approval)
		before := public62Snapshot(t, ctx, owner)
		for _, item := range []struct{ kind, id string }{{"definition", public62Definition}, {"run", run}, {"approval", approval}} {
			q := public62ClassifyRequest(o, w, e, actor, item.kind, item.id)
			got, err := public62Call(ctx, api, q)
			want := map[string]any{"contract_version": float64(62), "resource_kind": item.kind, "resource_id": item.id, "family": "ordered_release61"}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("owned %s: %v %v", item.kind, got, err)
			}
			q["resource_id"] = public62Finding
			got, err = public62Call(ctx, api, q)
			want["resource_id"], want["family"] = public62Finding, "legacy_or_missing"
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("missing %s: %v %v", item.kind, got, err)
			}
		}
		if public62Snapshot(t, ctx, owner) != before {
			t.Fatal("classification mutated owner authority")
		}
		for name, mutation := range map[string]string{
			"definition-lost-history":  `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{allowed_actions}','["create_temporary_policy"]') WHERE definition_id=$1; DELETE FROM zasp_security_agent_definition_versions WHERE definition_id=$1`,
			"definition-history":       `UPDATE zasp_security_agent_definition_versions SET definition=definition||'{"autonomy":"autonomous"}' WHERE definition_id=$1`,
			"definition-current":       `UPDATE zasp_security_agent_definitions SET body=body||'{"max_steps":3}' WHERE definition_id=$1`,
			"definition-cost":          `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{max_ai_cost_nano_credits}','0') WHERE definition_id=$1`,
			"definition-reference":     `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{existing_test,definition_version}','0') WHERE definition_id=$1`,
			"trigger-receipt":          `UPDATE zasp_security_agent_trigger_receipts SET trigger_digest=decode(repeat('00',32),'hex') WHERE run_id=$2`,
			"trigger-audit":            `UPDATE zasp_security_agent_audit SET body=body||'{"unexpected":true}' WHERE run_id=$2 AND event_kind='ordered_public_triggered'`,
			"trigger-operation":        `UPDATE zasp_security_agent_audit SET body=jsonb_set(body,'{request,operation}','"activate"') WHERE run_id=$2 AND event_kind='ordered_public_triggered'; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$2 AND event_kind='ordered_public_triggered'; UPDATE zasp_security_agent_request_receipts SET intent=jsonb_set(intent,'{operation}','"activate"') WHERE resource_id=$2; UPDATE zasp_security_agent_request_receipts SET intent_digest=digest(convert_to(intent::text,'UTF8'),'sha256') WHERE resource_id=$2`,
			"trigger-receipt-identity": `UPDATE zasp_security_agent_request_receipts SET receipt_id='pid_ffffffff-ffff-4fff-8fff-ffffffffffff' WHERE resource_id=$2`,
			"request-receipt":          `UPDATE zasp_security_agent_request_receipts SET intent_digest=decode(repeat('00',32),'hex') WHERE resource_id=$2`,
			"run-linkage":              `UPDATE zasp_security_agent_runs SET definition_version=999 WHERE run_id=$2`,
			"step-identity":            `UPDATE zasp_security_agent_steps SET step_id='pid_ffffffff-ffff-4fff-8fff-ffffffffffff' WHERE step_id=$3`,
			"approval-identity":        `UPDATE zasp_security_agent_approvals SET approval_id='pid_ffffffff-ffff-4fff-8fff-ffffffffffff' WHERE approval_id=$4`,
			"approval-missing":         `DELETE FROM zasp_security_agent_approvals WHERE approval_id=$4`,
			"approval-linkage":         `UPDATE zasp_security_agent_approvals SET step_id=$3 WHERE approval_id=$4`,
			"registration":             `UPDATE zasp_ordered_public62.registration SET checksum=repeat('0',64) WHERE $1<>''`,
			"fingerprint":              `UPDATE zasp_ordered_public62.registration SET fingerprint=repeat('0',64)`,
			"helper-definition":        `ALTER FUNCTION zasp_ordered_public62.classify(text,text,text,text,text) IMMUTABLE`,
			"acl":                      `GRANT EXECUTE ON FUNCTION zasp_ordered_public62.history(text,text,text,text) TO zasp_security_agent_api`,
			"scope":                    `DELETE FROM zasp_authorized_scopes WHERE principal_id=$5`,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				// Simple protocol permits the same bound fixture values for every probe.
				if _, err := owner.Exec(ctx, mutation+`; SELECT $1::text,$2::text,$3::text,$4::text,$5::text`, pgx.QueryExecModeSimpleProtocol, public62Definition, run, steps[1], approval, actor); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				resource := run
				kind := "run"
				if name == "definition-current" || name == "definition-lost-history" || name == "definition-cost" || name == "definition-reference" {
					kind, resource = "definition", public62Definition
				}
				if name == "approval-identity" {
					kind, resource = "approval", "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"
				}
				if name == "approval-linkage" {
					kind, resource = "approval", approval
				}
				if got, err := public62Call(ctx, owner, public62ClassifyRequest(o, w, e, actor, kind, resource)); err == nil {
					t.Fatalf("corrupt authority relabeled: %v", got)
				} else {
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || (pg.Code != "40001" && pg.Code != "42501" && pg.Code != "55000") {
						t.Fatal("probe did not reach authority refusal", err)
					}
					if (name == "definition-cost" || name == "definition-reference") && pg.Code != "40001" {
						t.Fatal("persisted contradiction was not unavailable", err)
					}
				}
			})
		}
		if public62Snapshot(t, ctx, owner) != before {
			t.Fatal("refusal changed owner authority")
		}
	})
}

func TestSecurityAgentPublic62OwnershipDraftPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		// Retained resources must still classify after the public facade is
		// demoted and reinstalled, without altering the canonical chain.
		if err := runner.DownProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := public62Call(ctx, api, public62ClassifyRequest(o, w, e, actor, "definition", public62Definition))
		if err != nil || got["family"] != "ordered_release61" {
			t.Fatal(got, err)
		}
		for _, field := range []string{"version", "definition_version"} {
			t.Run(field, func(t *testing.T) {
				if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				mutation := `UPDATE zasp_security_agent_definitions SET version=1000001 WHERE definition_id=$1`
				if field == "definition_version" {
					mutation = `UPDATE zasp_security_agent_definitions SET definition_version=1000001,body=jsonb_set(body,'{definition_version}','1000001') WHERE definition_id=$1`
				}
				if _, err := owner.Exec(ctx, mutation, public62Definition); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				if got, err := public62Call(ctx, owner, public62ClassifyRequest(o, w, e, actor, "definition", public62Definition)); err == nil {
					t.Fatal("out-of-contract version owned", got)
				}
			})
		}
	})
}

func TestSecurityAgentPublic62OwnershipIsolationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		var approval string
		if err := owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1`, run).Scan(&approval); err != nil {
			t.Fatal(err)
		}
		legacy := "pid_ffffffff-ffff-4fff-8fff-fffffffffff1"
		foreignEnvironment := "pid_ffffffff-ffff-4fff-8fff-fffffffffff2"
		// Seed ordinary single-step legacy rows only. No ordered success authority
		// is synthesized; the owned side used public trigger and the real planner.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definitions,to_jsonb(d)||jsonb_build_object('definition_id',$1,'body',body||jsonb_build_object('id',$1,'allowed_actions',jsonb_build_array('create_temporary_policy'),'max_steps',1)))).* FROM zasp_security_agent_definitions d WHERE definition_id=$2;
 INSERT INTO zasp_security_agent_runs SELECT (jsonb_populate_record(NULL::zasp_security_agent_runs,to_jsonb(r)||jsonb_build_object('run_id',$1,'definition_id',$1))).* FROM zasp_security_agent_runs r WHERE run_id=$3;
 INSERT INTO zasp_security_agent_steps SELECT (jsonb_populate_record(NULL::zasp_security_agent_steps,to_jsonb(s)||jsonb_build_object('run_id',$1,'step_id',$1))).* FROM zasp_security_agent_steps s WHERE step_id=$4;
 INSERT INTO zasp_security_agent_approvals SELECT (jsonb_populate_record(NULL::zasp_security_agent_approvals,to_jsonb(a)||jsonb_build_object('run_id',$1,'step_id',$1,'approval_id',$1))).* FROM zasp_security_agent_approvals a WHERE approval_id=$5;
 INSERT INTO zasp_authorized_scopes SELECT (jsonb_populate_record(NULL::zasp_authorized_scopes,to_jsonb(s)||jsonb_build_object('environment_id',$6))).* FROM zasp_authorized_scopes s WHERE principal_id=$7 AND environment_id=$8`, pgx.QueryExecModeSimpleProtocol, legacy, public62Definition, run, steps[0], approval, foreignEnvironment, actor, e); err != nil {
			t.Fatal(err)
		}
		before := public62Snapshot(t, ctx, owner)
		for attempt := 0; attempt < 2; attempt++ {
			connection := api
			if attempt == 1 {
				var err error
				connection, err = pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close(ctx)
			}
			repo, id := public62GoRepository(t, connection, o, w, e, actor)
			resolver, _ := NewSecurityAgentOwnershipResolver(repo.database)
			if attempt == 1 {
				id.CredentialKind = CredentialBearerToken
				id.CSRFToken = ""
			}
			for _, item := range []struct {
				kind     SecurityAgentResourceKind
				resource string
			}{{SecurityAgentResourceDefinition, public62Definition}, {SecurityAgentResourceRun, run}, {SecurityAgentResourceApproval, approval}} {
				if family, err := resolver.Resolve(ctx, id, item.kind, item.resource); err != nil || family != SecurityAgentFamilyOrderedRelease61 {
					t.Fatal("typed owned", family, err)
				}
				for _, resource := range []string{legacy, public62Finding} {
					if family, err := resolver.Resolve(ctx, id, item.kind, resource); err != nil || family != SecurityAgentFamilyLegacyOrMissing {
						t.Fatal("typed legacy/missing", family, err)
					}
				}
				q := public62ClassifyRequest(o, w, foreignEnvironment, actor, string(item.kind), item.resource)
				foreign, err := public62Call(ctx, connection, q)
				if err != nil || !reflect.DeepEqual(foreign, map[string]any{"contract_version": float64(62), "resource_kind": string(item.kind), "resource_id": item.resource, "family": "legacy_or_missing"}) {
					t.Fatal("foreign existence leaked", foreign, err)
				}
			}
		}
		for _, change := range []func(map[string]any){func(q map[string]any) { q["resource_kind"] = "step" }, func(q map[string]any) { q["resource_kind"] = nil }, func(q map[string]any) { q["resource_id"] = "bad" }, func(q map[string]any) { q["step_id"] = steps[0] }, func(q map[string]any) { q["definition_version"] = 2 }} {
			q := public62ClassifyRequest(o, w, e, actor, "run", run)
			change(q)
			if _, err := public62Call(ctx, api, q); err == nil {
				t.Fatal("open or invalid request accepted")
			}
		}
		if before != public62Snapshot(t, ctx, owner) {
			t.Fatal("classification changed owner state")
		}
		t.Run("approval-full-relink", func(t *testing.T) {
			if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM zasp_security_agent_approvals WHERE approval_id=$1; UPDATE zasp_security_agent_approvals SET run_id=$1,step_id=$1 WHERE approval_id=$2`, pgx.QueryExecModeSimpleProtocol, legacy, approval); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			got, err := public62Call(ctx, owner, public62ClassifyRequest(o, w, e, actor, "approval", approval))
			if _, rollbackErr := owner.Exec(ctx, `ROLLBACK`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("retained ordered approval relabeled: %v %v", got, err)
			}
			if before != public62Snapshot(t, ctx, owner) {
				t.Fatal("relink refusal changed owner state")
			}
		})
		t.Run("mixed-versions", func(t *testing.T) {
			public62OwnershipMixedVersionProbes(t, ctx, owner, api, o, w, e, actor, legacy, run, approval, foreignEnvironment)
		})
	})
}

// A newer ordered version or sibling must not capture an older single-action
// run. Only direct ordered evidence can contradict that run's pinned version.
func public62OwnershipMixedVersionProbes(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor, legacy, orderedRun, orderedApproval, foreign string) {
	t.Helper()
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$2 FROM zasp_security_agent_definitions WHERE definition_id=$1`, legacy, actor); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, sibling string) {
		t.Helper()
		before := public62Snapshot(t, ctx, owner)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		resolver, _ := NewSecurityAgentOwnershipResolver(repo.database)
		for _, bearer := range []bool{false, true} {
			if bearer {
				id.CredentialKind = CredentialBearerToken
				id.CSRFToken = ""
			}
			for _, kind := range []SecurityAgentResourceKind{SecurityAgentResourceRun, SecurityAgentResourceApproval} {
				for _, resource := range []string{legacy, public62Finding} {
					if family, err := resolver.Resolve(ctx, id, kind, resource); err != nil || family != SecurityAgentFamilyLegacyOrMissing {
						t.Errorf("mixed-version legacy %s bearer=%t: %s %v", kind, bearer, family, err)
					}
				}
				_, foreignID := public62GoRepository(t, api, o, w, foreign, actor)
				foreignID.CredentialKind, foreignID.CSRFToken = id.CredentialKind, id.CSRFToken
				if family, err := resolver.Resolve(ctx, foreignID, kind, legacy); err != nil || family != SecurityAgentFamilyLegacyOrMissing {
					t.Errorf("mixed-version foreign %s: %s %v", kind, family, err)
				}
			}
			if sibling != "" {
				if family, err := resolver.Resolve(ctx, id, SecurityAgentResourceRun, sibling); err != nil || family != SecurityAgentFamilyOrderedRelease61 {
					t.Errorf("ordered sibling: %s %v", family, err)
				}
				if sibling == orderedRun {
					if family, err := resolver.Resolve(ctx, id, SecurityAgentResourceApproval, orderedApproval); err != nil || family != SecurityAgentFamilyOrderedRelease61 {
						t.Errorf("ordered sibling approval: %s %v", family, err)
					}
				}
			}
		}
		if before != public62Snapshot(t, ctx, owner) {
			t.Fatal("mixed-version classification changed owner state")
		}
	}
	t.Run("before-ordered-revision", func(t *testing.T) { check(t, "") })
	// Only a disabled configuration revision is seeded; activation and the new
	// ordered sibling's trigger authority are established through the facade.
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions d SET version=3,activation='draft',body=jsonb_set(s.body||'{"enabled":false}','{id}',to_jsonb(d.definition_id)) FROM zasp_security_agent_definitions s WHERE d.definition_id=$1 AND s.definition_id=$2`, legacy, public62Definition); err != nil {
		t.Fatal(err)
	}
	repo, id := public62GoRepository(t, api, o, w, e, actor)
	if _, err := repo.Activate(ctx, id, legacy, 3); err != nil {
		t.Fatal(err)
	}
	t.Run("newer-ordered-revision", func(t *testing.T) { check(t, "") })
	sibling, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: legacy, DefinitionVersion: 4, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "ownership-mixed-version-trigger"})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("queued-ordered-sibling", func(t *testing.T) { check(t, sibling.RunID) })
	t.Run("direct-receipt-legacy-pin", func(t *testing.T) {
		before := public62Snapshot(t, ctx, owner)
		if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica; UPDATE zasp_security_agent_runs SET definition_version=2 WHERE run_id=$1; DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_public_triggered'`, pgx.QueryExecModeSimpleProtocol, sibling.RunID); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		got, err := public62Call(ctx, owner, public62ClassifyRequest(o, w, e, actor, "run", sibling.RunID))
		if _, rollbackErr := owner.Exec(ctx, `ROLLBACK`); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("retained public receipt fell back: %v %v", got, err)
		}
		if before != public62Snapshot(t, ctx, owner) {
			t.Fatal("receipt refusal changed owner state")
		}
	})
	// The authentic admitted sibling retains its original version-2 authority.
	// Add an ordinary earlier version and link only the legacy fixture to it.
	if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica;
 INSERT INTO zasp_security_agent_definition_versions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definition_versions,to_jsonb(h)||jsonb_build_object('definition_id',$2,'version',1,'definition',jsonb_set(definition,'{id}',to_jsonb($2::text)),'definition_digest',digest(convert_to(jsonb_set(definition,'{id}',to_jsonb($2::text))::text,'UTF8'),'sha256')))).* FROM zasp_security_agent_definition_versions h WHERE definition_id=$1 AND version=2;
 UPDATE zasp_security_agent_runs SET definition_id=$2,definition_version=1 WHERE run_id=$1; COMMIT`, pgx.QueryExecModeSimpleProtocol, legacy, public62Definition); err != nil {
		t.Fatal(err)
	}
	t.Run("admitted-ordered-sibling", func(t *testing.T) { check(t, orderedRun) })
	for _, kind := range []string{"run", "approval"} {
		t.Run("direct-marker-legacy-pin-"+kind, func(t *testing.T) {
			before := public62Snapshot(t, ctx, owner)
			if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica; UPDATE zasp_security_agent_runs SET definition_version=1 WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, orderedRun); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			resource := orderedRun
			if kind == "approval" {
				resource = orderedApproval
			}
			got, err := public62Call(ctx, owner, public62ClassifyRequest(o, w, e, actor, kind, resource))
			if _, rollbackErr := owner.Exec(ctx, `ROLLBACK`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("direct ordered marker fell back: %v %v", got, err)
			}
			if before != public62Snapshot(t, ctx, owner) {
				t.Fatal("direct-marker refusal changed owner state")
			}
		})
	}
}

func TestSecurityAgentPublic62OwnershipSuccessorPostgres(t *testing.T) {
	public62TerminalFixture(t, func(ctx context.Context, owner, _, api, _ *pgx.Conn, o, w, e, run string, steps []string) {
		var actor, approval string
		if err := owner.QueryRow(ctx, `SELECT r.requested_by,a.approval_id FROM zasp_security_agent_runs r JOIN zasp_security_agent_approvals a USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND a.step_id=$2`, run, steps[1]).Scan(&actor, &approval); err != nil {
			t.Fatal(err)
		}
		public62OwnershipHistoryProbes(t, ctx, owner, api, o, w, e, actor, run, approval)
		q := public62ClassifyRequest(o, w, e, actor, "approval", approval)
		if got, err := public62Call(ctx, api, q); err != nil || got["family"] != "ordered_release61" {
			t.Fatal("terminal successor", got, err)
		}
		before := public62Snapshot(t, ctx, owner)
		if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM zasp_security_agent_approvals WHERE approval_id=$1`, pgx.QueryExecModeSimpleProtocol, approval); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		got, err := public62Call(ctx, owner, q)
		if _, rollbackErr := owner.Exec(ctx, `ROLLBACK`); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err == nil {
			t.Fatal("deleted owned successor relabeled", got)
		}
		if before != public62Snapshot(t, ctx, owner) {
			t.Fatal("missing successor refusal changed state")
		}
	}, false)
}

func TestSecurityAgentPublic62OwnershipRevokedPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		resolver, _ := NewSecurityAgentOwnershipResolver(repo.database)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		created, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "ownership-revocation-trigger"})
		if err != nil {
			t.Fatal(err)
		}
		public62OwnershipHistoryProbes(t, ctx, owner, api, o, w, e, actor, created.RunID)
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$1; UPDATE zasp_red_team_definitions SET enabled=false WHERE definition_id=$2`, pgx.QueryExecModeSimpleProtocol, o, testID); err != nil {
			t.Fatal(err)
		}
		before := public62Snapshot(t, ctx, owner)
		for _, item := range []struct {
			kind SecurityAgentResourceKind
			id   string
		}{{SecurityAgentResourceDefinition, public62Definition}, {SecurityAgentResourceRun, created.RunID}} {
			if family, err := resolver.Resolve(ctx, id, item.kind, item.id); err != nil || family != SecurityAgentFamilyOrderedRelease61 {
				t.Fatalf("revoked execution erased ownership: %s %v", family, err)
			}
		}
		if before != public62Snapshot(t, ctx, owner) {
			t.Fatal("classification changed revoked authority")
		}
		// Simulate the later adapter's positive dispatch, without adding a route.
		if _, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: created.RunID, RunVersion: 1, IdempotencyKey: "ownership-revocation-cancel"}); err != nil {
			t.Fatal("owned cancellation blocked by execution revocation", err)
		}
		if family, err := resolver.Resolve(ctx, id, SecurityAgentResourceRun, created.RunID); err != nil || family != SecurityAgentFamilyOrderedRelease61 {
			t.Fatal(family, err)
		}
		if got, err := repo.Run(ctx, id, created.RunID); err != nil || got.State != "cancelled" {
			t.Fatal("owned terminal read", got, err)
		}
	})
}
