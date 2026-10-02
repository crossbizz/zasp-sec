package main

import (
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"strings"
	"testing"
	"time"
)

// A raw malformed identity must not become valid by replacing its ID. Provider
// IDs can coincide across integrations; stored observation IDs cannot.
func TestTemporalDiscoveryRelationshipMappingPostgres(t *testing.T) {
	f, worker, _, _ := temporalDiscoveryPageFixture(t)
	query := `SELECT zasp_temporal72.normalize_relationships($1,$2,$3,$4,$5,$6::jsonb)`
	base := `[{"id":"pid_72910001-0000-4000-8000-000000000001","kind":"contains","source_native_id":"shared-native","from_entity_id":"pid_72910002-0000-4000-8000-000000000002","to_entity_id":"pid_72910003-0000-4000-8000-000000000003","attributes":{}}]`
	ids := map[string]bool{}
	for _, provider := range []string{"aws", "kubernetes", "github", "okta"} {
		var first, repeated, second []byte
		args := []any{replayOrg, replayWorkspace, replayEnvironment, replayIntegration, provider, base}
		if err := f.owner.QueryRow(f.ctx, query, args...).Scan(&first); err != nil {
			t.Fatal(err)
		}
		if err := f.owner.QueryRow(f.ctx, query, args...).Scan(&repeated); err != nil || string(first) != string(repeated) {
			t.Fatal("unstable mapping", err)
		}
		args[3] = capacityIntegration
		if err := f.owner.QueryRow(f.ctx, query, args...).Scan(&second); err != nil {
			t.Fatal(err)
		}
		for _, body := range [][]byte{first, second} {
			var items []map[string]any
			if json.Unmarshal(body, &items) != nil || len(items) != 1 {
				t.Fatal("mapped shape")
			}
			id := items[0]["id"].(string)
			if ids[id] || id == "pid_72910001-0000-4000-8000-000000000001" || items[0]["from_entity_id"] != "pid_72910002-0000-4000-8000-000000000002" || items[0]["to_entity_id"] != "pid_72910003-0000-4000-8000-000000000003" || items[0]["source_native_id"] != "shared-native" {
				t.Fatal("connector identity collision or changed endpoint", string(body))
			}
			ids[id] = true
		}
	}
	for _, malformed := range []string{
		strings.Replace(base, `"pid_72910001-0000-4000-8000-000000000001"`, `"bad"`, 1),
		strings.Replace(base, `"shared-native"`, `42`, 1),
		strings.Replace(base, `"attributes":{}`, `"attributes":null`, 1),
		strings.Replace(base, `"attributes":{}`, `"attributes":{},"extra":true`, 1),
		`[` + strings.Trim(base, "[]") + `,` + strings.Trim(base, "[]") + `]`,
	} {
		var raw []byte
		if err := f.owner.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, replayIntegration, "aws", malformed).Scan(&raw); err == nil {
			t.Fatal("malformed raw relationship repaired", malformed, string(raw))
		}
	}
	var raw []byte
	if err := worker.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, replayIntegration, "aws", base).Scan(&raw); err == nil {
		t.Fatal("private normalizer exposed to worker")
	}
}

func capacityRelationshipCompatibility(t *testing.T, f scheduleReplayFixture, worker *pgx.Conn, historical bool) {
	t.Helper()
	var valid bool
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_inventory_entities WHERE state='active')=2 AND (SELECT count(*) FROM zasp_inventory_relationships WHERE state='present')=2 AND (SELECT count(DISTINCT id) FROM zasp_inventory_relationships)=2 AND NOT EXISTS(SELECT 1 FROM zasp_discovery_snapshot_projection_items p JOIN zasp_discovery_snapshot_inputs s ON(s.organization_id,s.workspace_id,s.environment_id,s.snapshot_id)=(p.organization_id,p.workspace_id,p.environment_id,p.snapshot_id) WHERE p.section='relationships' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s.relationships) item WHERE item=p.payload))`).Scan(&valid); err != nil || !valid {
		t.Fatal("shared entities/scoped edges/projection identity", valid, err)
	}
	if historical {
		if err := f.owner.QueryRow(f.ctx, `SELECT id<>zasp_discovery_relationship_id(organization_id,workspace_id,environment_id,integration_id,source,kind,source_native_id) FROM zasp_inventory_relationships WHERE integration_id=$1`, capacityIntegration).Scan(&valid); err != nil || !valid {
			t.Fatal("pre-upgrade edge was renamed", valid, err)
		}
	}
	// Force a deterministic generated-ID collision with another connector in
	// a disposable transaction. The helper must refuse, never reparent its row.
	tx, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE zasp_inventory_relationships SET id=zasp_discovery_relationship_id(organization_id,workspace_id,environment_id,$1,source,kind,'new-colliding-native') WHERE integration_id=$2`, replayIntegration, capacityIntegration); err != nil {
		tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	var collision []byte
	if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal72.normalize_relationships($1,$2,$3,$4,'aws',jsonb_build_array(jsonb_build_object('id','pid_72910001-0000-4000-8000-000000000001','kind','contains','source_native_id','new-colliding-native','from_entity_id','pid_72910002-0000-4000-8000-000000000002','to_entity_id','pid_72910003-0000-4000-8000-000000000003','attributes','{}'::jsonb)))`, replayOrg, replayWorkspace, replayEnvironment, replayIntegration).Scan(&collision); err == nil {
		tx.Rollback(f.ctx)
		t.Fatal("foreign connector collision reparented")
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT relationships FROM zasp_discovery_snapshot_inputs WHERE integration_id=$1`, replayIntegration).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// Admit through the actual scoped API authority, then use an explicit empty
	// complete SQL candidate to test connector-local removal. This is domain
	// application evidence, not a claim that the cloud double deleted resources.
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'discovery-org','discovery-member','security_engineer') ON CONFLICT DO NOTHING; INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Discovery','["view","manage_workflows"]') ON CONFLICT DO NOTHING`, pgx.QueryExecModeSimpleProtocol, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal); err != nil {
		t.Fatal(err)
	}
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.api
	api, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(f.ctx)
	job := "pid_72930002-0000-4000-8000-000000000002"
	var raw []byte
	if err := api.QueryRow(f.ctx, `SELECT zasp_temporal72.public_request_sync($1,$2,$3,$4,$5,'relationship-local-delete',1,'pid_72930001-0000-4000-8000-000000000001',$6,'pid_72930003-0000-4000-8000-000000000003',decode(repeat('dc',32),'hex'),'parser_v1','tool_v1','pid_72930004-0000-4000-8000-000000000004','pid_72930005-0000-4000-8000-000000000005','pid_72930006-0000-4000-8000-000000000006')`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, job).Scan(&raw); err != nil {
		t.Fatal("removal admission", err)
	}
	var start orchestration.DiscoveryStart
	var deadline time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_temporal72.start_receipt(r),deadline FROM zasp_temporal72.runs r WHERE job_id=$1`, job).Scan(&raw, &deadline); err != nil || json.Unmarshal(raw, &start) != nil {
		t.Fatal("removal start", err)
	}
	prepared := capacityPrepare(t, f, worker, start, deadline)
	var effect string
	if json.Unmarshal(prepared["effect_id"], &effect) != nil {
		t.Fatal("removal effect")
	}
	key := "organizations/" + replayOrg + "/workspaces/" + replayWorkspace + "/environments/" + replayEnvironment + "/artifacts/pid_72930007-0000-4000-8000-000000000007"
	details := map[string]any{"outcome": "complete", "cursor": map[string]any{"provider": "aws", "version": "cursor_v1", "value": "removal-complete"}, "manifest": map[string]any{"reference": "s3://zasp-evidence/" + key, "key": key, "version_id": "removal-version-1", "checksum": strings.Repeat("cd", 32), "size_bytes": 100, "media_type": "application/json", "schema_version": "manifest_v1", "parser_version": "parser_v1", "tool_version": "tool_v1"}, "candidate": map[string]any{"entities": []any{}, "relationships": []any{}, "evidence": []any{}}}
	encoded, _ := json.Marshal(details)
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,$6::jsonb)`, replayOrg, replayWorkspace, replayEnvironment, job, effect, string(encoded)).Scan(&raw); err != nil {
		t.Fatal("removal receipt", err)
	}
	var complete orchestration.DiscoveryPage
	if json.Unmarshal(raw, &complete) != nil {
		t.Fatal("removal complete")
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.prepare_apply($1,$2,$3,$4,$5,$6,$7,$8)`, replayOrg, replayWorkspace, replayEnvironment, job, replayIntegration, start.InputDigest, deadline, complete.ReceiptDigest).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var application struct {
		EffectID string `json:"effect_id"`
	}
	if json.Unmarshal(raw, &application) != nil {
		t.Fatal("removal apply")
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.commit_apply($1,$2,$3,$4,$5,$6)`, replayOrg, replayWorkspace, replayEnvironment, job, application.EffectID, deadline).Scan(&raw); err != nil {
		t.Fatal("removal commit", err)
	}
	var result orchestration.DiscoveryResult
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("removal result")
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.settle($1,$2,$3,$4,$5,$6,$7,'succeeded',$8)`, replayOrg, replayWorkspace, replayEnvironment, job, replayIntegration, start.InputDigest, deadline, result.ReceiptDigest).Scan(&raw); err != nil {
		t.Fatal("removal settlement", err)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_inventory_relationships WHERE integration_id=$1 AND state='removed')=1 AND (SELECT count(*) FROM zasp_inventory_relationships WHERE integration_id=$2 AND state='present')=1 AND (SELECT count(*) FROM zasp_inventory_entities WHERE state='active')=2 AND (SELECT count(*) FROM zasp_projection_work)=9`, replayIntegration, capacityIntegration).Scan(&valid); err != nil || !valid {
		t.Fatal("removal crossed connector boundary", valid, err)
	}
	var mapped []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_temporal72.normalize_relationships($1,$2,$3,$4,'aws',$5::jsonb)`, replayOrg, replayWorkspace, replayEnvironment, replayIntegration, string(before)).Scan(&mapped); err != nil || string(mapped) != string(before) {
		t.Fatal("removed edge identity lost", string(mapped), string(before), err)
	}
	t.Log("two connectors shared two entities with separate persisted edges; historical identity/replay preserved; empty domain snapshot removed only its connector edge")
}
