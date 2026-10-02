package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The retained worker still runs beside native adapters. It must leave the
// finding family to78 without failing the whole ordinary processor pass.
func TestTemporalFindingResponseRetainedSchedulerPostgres(t *testing.T) {
	runFindingResponseFixture(t, func(ctx context.Context, f findingResponseFixture) {
		finding := f.next()
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id<>$1;INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($2,$3,$4,$5,'posture','credential','Retained scheduler fixture','high','open')`, pgx.QueryExecModeSimpleProtocol, f.definition, f.o, f.w, f.e, finding); err != nil {
			t.Fatal(err)
		}
		config := f.owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentWorkerRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		created, err := repository.ScheduleSecurityAgentTriggers(ctx, "finding78-retained", 5)
		if err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) {
				t.Log("retained scheduler SQLSTATE", pg.Code, "finding_owner_guard", pg.Message == "finding owner required before admission")
			}
			t.Fatal("registered retained scheduler must exclude78 finding definitions", err)
		}
		if created != 0 {
			t.Fatal("retained worker admitted native finding", created)
		}
		var absent bool
		if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_trigger_receipts WHERE trigger_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE trigger_id=$1)`, finding).Scan(&absent); err != nil || !absent {
			t.Fatal("retained finding effects", absent, err)
		}
		// Seed one genuinely unmigrated definition and its immutable history.
		// This is a historical prerequisite, not a78 API activation claim.
		legacy := f.next()
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_risk_findings SET status='under_review' WHERE id<>$2;
INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
 SELECT organization_id,workspace_id,environment_id,$3,activation,1,1,(body-'trigger_rules')||jsonb_build_object('id',$3::text),plan_catalog_version FROM zasp_security_agent_definitions WHERE definition_id=$1;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$4 FROM zasp_security_agent_definitions WHERE definition_id=$3`, pgx.QueryExecModeSimpleProtocol, f.definition, finding, legacy, f.actor); err != nil {
			t.Fatal(err)
		}
		created, err = repository.ScheduleSecurityAgentTriggers(ctx, "finding78-retained", 5)
		if err != nil || created != 1 {
			t.Fatal("unmigrated finding admission", created, err)
		}
		var legacyRun string
		var original json.RawMessage
		if err := f.owner.QueryRow(ctx, `SELECT r.run_id,to_jsonb(r) FROM zasp_security_agent_runs r WHERE r.definition_id=$1 AND r.trigger_id=$2 AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.run_owners x WHERE x.run_id=r.run_id)`, legacy, finding).Scan(&legacyRun, &original); err != nil {
			t.Fatal("unmigrated queued owner", err)
		}
		// A current edit with no new grant plus revocation cannot erase earlier
		// migration ownership. Stored history is retained exactly. This fixture
		// deliberately makes it enabled to exercise the dangerous old fallback.
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET version=version+1,body=body-'trigger_rules' WHERE definition_id=$1;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$2 FROM zasp_security_agent_definitions WHERE definition_id=$1;
INSERT INTO zasp_temporal78.grant_revocations(organization_id,workspace_id,environment_id,definition_id,definition_version,actor_id,audit_id) SELECT organization_id,workspace_id,environment_id,definition_id,definition_version,$2,$3 FROM zasp_temporal78.service_grants WHERE definition_id=$1`, pgx.QueryExecModeSimpleProtocol, f.definition, f.actor, f.next()); err != nil {
			t.Fatal(err)
		}
		created, err = repository.ScheduleSecurityAgentTriggers(ctx, "finding78-retained", 5)
		if err != nil || created != 0 {
			t.Fatal("edited/revoked finding regained legacy execution", created, err)
		}
		var current json.RawMessage
		if err := f.owner.QueryRow(ctx, `SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE run_id=$1`, legacyRun).Scan(&current); err != nil {
			t.Fatal(err)
		}
		assertAutomaticRuleJSON(t, "retained queued backlog unchanged", original, current)
		var raw json.RawMessage
		err = worker.QueryRow(ctx, `SELECT zasp_security_agent_schedule_triggers_v21($1,$2)`, "finding78-old-worker", 5).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" || pg.Message != "finding owner required before admission" {
			t.Fatal("old scheduler finding owner backstop", err)
		}
		claims, err := repository.ClaimSecurityAgentRuns(ctx, "finding78-retained", "finding78-retained-lease-token", 60, 25)
		if err != nil {
			t.Fatal("retained backlog claim", err)
		}
		claimed := false
		for _, claim := range claims {
			if claim.RunID == legacyRun {
				claimed = true
			}
			if claim.DefinitionID == f.definition {
				t.Fatal("retained worker claimed migrated finding")
			}
		}
		if !claimed {
			t.Fatal("unmigrated backlog was dropped")
		}
	})
}
