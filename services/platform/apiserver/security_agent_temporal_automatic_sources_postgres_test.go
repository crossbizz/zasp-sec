package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/riskprojection"
)

func installAutomaticSourceFixture(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	installTemporalTestExecutorFixture(t, ctx, owner)
	runner := precisionMigrationRunner(t, owner)
	if err := runner.UpProductionTemporalTestSelector(ctx); err != nil {
		t.Fatal(err)
	}
	installAutomaticSourceAfterSelectorFixture(t, ctx, owner)
}

func installAutomaticSourceAfterSelectorFixture(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	runner := precisionMigrationRunner(t, owner)
	if err := runner.UpProductionTemporalHumanAdmission(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionTemporalAutomaticSources(ctx); err != nil {
		tx, txErr := owner.Begin(ctx)
		if txErr != nil {
			t.Fatal(txErr)
		}
		defer tx.Rollback(ctx)
		_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalAutomaticSources().UpSQL())
		var pin string
		pinErr := tx.QueryRow(ctx, `SELECT zasp_temporal77.fingerprint()`).Scan(&pin)
		t.Logf("independent77 DDL=%v fingerprint=%s pin_error=%v", ddlErr, pin, pinErr)
		var writerHash, writerOwner, writerACL string
		metadataErr := tx.QueryRow(ctx, `SELECT encode(digest(convert_to(pg_get_functiondef(oid),'UTF8'),'sha256'),'hex'),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid='public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure`).Scan(&writerHash, &writerOwner, &writerACL)
		t.Logf("risk writer hash=%s owner=%s acl=%s metadata_error=%v", writerHash, writerOwner, writerACL, metadataErr)
		t.Fatal("install77", err)
	}
}

func automaticSourceID(n int) string { return fmt.Sprintf("pid_f0773000-0000-4000-8000-%012d", n) }

func automaticSourceIdentity(t *testing.T, o, w, e, actor string) RequestIdentity {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	parse := func(s string) domain.ProductID {
		v, err := domain.ParseProductID(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	var err error
	identity.Scope, err = domain.NewScope(parse(o), parse(w), parse(e))
	if err != nil {
		t.Fatal(err)
	}
	identity.PrincipalID = parse(actor)
	identity.CredentialKind = CredentialBrowserSession
	return identity
}

func TestTemporalAutomaticSourcesPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		identity := automaticSourceIdentity(t, o, w, e, actor)
		t.Run("actual finding mutation commit rollback replay", func(t *testing.T) {
			finding := automaticSourceID(1)
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Capture fixture','high','open')`, o, w, e, finding); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$5)`, o, w, e, finding, automaticSourceID(5)); err != nil {
				t.Fatal(err)
			}
			var riskSource string
			if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure)`).Scan(&riskSource); err != nil {
				t.Fatal(err)
			}
			t.Logf("effective public risk writer: %s", riskSource)
			var principal string
			if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_api'`).Scan(&principal); err != nil {
				t.Fatal(err)
			}
			config := owner.Config().Copy()
			config.User = principal
			findingAPI, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer findingAPI.Close(context.Background())
			var readyProof json.RawMessage
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('release',zasp_temporal77.ready($1,$2),'policy',zasp_audit_export_policy_state_ready(),'worker',zasp_audit_export_worker_security_ready(),'source_acl',zasp_audit_export_source_acl_ready(),'workflow_acl',zasp_audit_export_workflow_acl_ready())`, migrations.ProductionTemporalAutomaticSources().Checksum(), migrations.TemporalAutomaticSourcesFingerprint()).Scan(&readyProof); err != nil {
				t.Fatal(err)
			}
			t.Logf("live finding authority invariants=%s", readyProof)
			db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: findingAPI})
			if err != nil {
				t.Fatal(err)
			}
			repo := &PostgresRepository{database: db}
			mutation := RiskFindingMutation{Operation: "updateFinding", FindingID: finding, ExpectedVersion: 1, Status: "under_review", IdempotencyKey: "automatic-source-finding-update-0001", AuditID: automaticSourceID(2), CorrelationID: automaticSourceID(3), ReceiptID: automaticSourceID(4)}
			if _, err := findingAPI.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			result, writeErr := repo.MutateRiskFinding(ctx, identity, mutation)
			if _, err := findingAPI.Exec(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			if writeErr != nil || result.Version != 2 {
				t.Fatal("actual risk writer", result, writeErr)
			}
			var count int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.source_events WHERE organization_id=$1 AND source_kind='finding' AND source_id=$2 AND source_version=2`, o, finding).Scan(&count); err != nil || count != 0 {
				t.Fatal("rolled-back occurrence", count, err)
			}
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_audit WHERE audit_id=$1)+(SELECT count(*) FROM zasp_workflow_receipts WHERE receipt_id=$2)`, mutation.AuditID, mutation.ReceiptID).Scan(&count); err != nil || count != 0 {
				t.Fatal("rollback leaked audit/receipt", count, err)
			}
			result, err = repo.MutateRiskFinding(ctx, identity, mutation)
			if err != nil || result.Version != 2 {
				t.Fatal("committed risk writer", result, err)
			}
			replay, err := repo.MutateRiskFinding(ctx, identity, mutation)
			if err != nil || !replay.Replayed {
				t.Fatal("risk exact replay", replay, err)
			}
			var capturedAt time.Time
			if err := owner.QueryRow(ctx, `SELECT count(*),min(source_at) FROM zasp_temporal77.source_events WHERE (organization_id,workspace_id,environment_id,source_kind,source_id,source_version)=($1,$2,$3,'finding',$4,2)`, o, w, e, finding).Scan(&count, &capturedAt); err != nil || count != 1 || !capturedAt.Equal(result.Body.UpdatedAt) {
				t.Fatal("canonical committed occurrence", count, capturedAt, result.Body.UpdatedAt, err)
			}
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_audit WHERE audit_id=$1 AND resource_version=2)+(SELECT count(*) FROM zasp_workflow_receipts WHERE receipt_id=$2 AND resource_version=2)`, mutation.AuditID, mutation.ReceiptID).Scan(&count); err != nil || count != 2 {
				t.Fatal("committed audit/receipt replay", count, err)
			}
			foreign := automaticSourceIdentity(t, o, w, automaticSourceID(90), actor)
			if _, err := repo.MutateRiskFinding(ctx, foreign, mutation); err != ErrRepositoryNotFound {
				t.Fatal("foreign scope finding mutation", err)
			}
			var invoker bool
			if err := owner.QueryRow(ctx, `SELECT NOT prosecdef AND COALESCE(proacl::text,'')='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_discovery_api=X/zasp_discovery_authority}' FROM pg_proc WHERE oid='zasp_temporal77.risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure`).Scan(&invoker); err != nil || !invoker {
				t.Fatal("private writer lost invoker/ACL boundary", invoker, err)
			}
			if _, err := api.Exec(ctx, `INSERT INTO zasp_temporal77.source_events SELECT * FROM zasp_temporal77.source_events`); err == nil {
				t.Fatal("API fabricated source occurrence")
			}
		})
		t.Run("actual discovery writer final same-version finding and path", func(t *testing.T) {
			input := seedAutomaticProjection(t, ctx, owner, identity)
			var principal string
			if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_execution_principals WHERE authority_role='zasp_projection_risk_worker'`).Scan(&principal); err != nil {
				t.Fatal("existing registered projection principal", err)
			}
			config := owner.Config().Copy()
			config.User = principal
			conn, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close(context.Background())
			db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: conn})
			if err != nil {
				t.Fatal(err)
			}
			repo, err := NewDiscoveryExecutionRepository(db, DiscoveryExecutionAuthorityProjectionRisk)
			if err != nil {
				t.Fatal("registered projection repository", err)
			}
			result, err := repo.ApplyRiskProjectionInput(ctx, input)
			if err != nil || result.Replayed {
				t.Fatal("actual projection writer", result, err)
			}
			finding := automaticSourceID(15)
			var path string
			var version int64
			if err := owner.QueryRow(ctx, `SELECT path_id,version FROM zasp_risk_findings WHERE id=$1`, finding).Scan(&path, &version); err != nil || path == "" || version != 1 {
				t.Fatal("same-version final finding", path, version, err)
			}
			var count int
			var valid bool
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal77.source_events WHERE organization_id=$1 AND source_kind='finding' AND source_id=$2 AND source_version=1),(SELECT zasp_risk_attack_path_valid(p) FROM zasp_risk_attack_paths p WHERE p.id=$3)`, o, finding, path).Scan(&count, &valid); err != nil || count != 1 || !valid {
				t.Fatal("final committed finding/path occurrence", count, valid, err)
			}
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.source_events WHERE organization_id=$1 AND source_kind='attack_path' AND source_id=$2 AND source_version=1`, o, path).Scan(&count); err != nil || count != 1 {
				t.Fatal("canonical path occurrence", count, err)
			}
			result, err = repo.ApplyRiskProjectionInput(ctx, input)
			if err != nil || !result.Replayed {
				t.Fatal("projection exact replay", result, err)
			}
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.source_events WHERE organization_id=$1 AND source_id=ANY($2::text[])`, o, []string{finding, path}).Scan(&count); err != nil || count != 2 {
				t.Fatal("projection duplicate occurrences", count, err)
			}
		})
		t.Run("signed runtime HTTP and actual atomic capture", func(t *testing.T) { exerciseAutomaticRuntimeCapture(t, ctx, owner, o, w, e) })
	})
}

// Only prerequisites are seeded. The finding, path and all children are produced
// by the actual registered, lease-fenced production projection writer.
func seedAutomaticProjection(t *testing.T, ctx context.Context, owner *pgx.Conn, identity RequestIdentity) riskprojection.CompleteInput {
	t.Helper()
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	integration, syncID, snapshot, entry, sink, finding, evidence, edge := automaticSourceID(10), automaticSourceID(11), automaticSourceID(12), automaticSourceID(13), automaticSourceID(14), automaticSourceID(15), automaticSourceID(16), automaticSourceID(17)
	digest := sha256.Sum256([]byte("automatic-source-projection"))
	payload, _ := json.Marshal(map[string]any{"id": evidence, "finding_id": finding, "entity_id": sink, "check_id": "credential", "severity": "high", "status": "FAIL"})
	if _, err := owner.Exec(ctx, `
INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name) VALUES($1,$2,$3,$4,'aws','1','Automatic source fixture');
INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$5,$4,'automatic-source-projection-sync',$12,'manual',$13,'v1','v1');
INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,complete,collected_at) VALUES($1,$2,$3,$6,$4,$5,1,'aws','s3://zasp-evidence/automatic77/manifest.json',$12,'candidate',$12,false,transaction_timestamp());
INSERT INTO zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,generation,candidate_digest,manifest_reference,manifest_key,manifest_version_id,manifest_checksum,manifest_size_bytes,manifest_media_type,manifest_schema_version,parser_version,tool_version,entities,relationships,evidence) VALUES($1,$2,$3,$6,$4,'aws',1,$12,'s3://zasp-evidence/automatic77/manifest.json','automatic77/complete-source/manifest.json','version-1',$12,1,'application/json','v1','v1','v1','[]','[]',jsonb_build_array($14::jsonb));
INSERT INTO zasp_discovery_snapshot_projection_items(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,section,item_id,payload) VALUES($1,$2,$3,$6,$4,'aws','evidence',$10,jsonb_set($14::jsonb,'{finding_id}',to_jsonb($9::text)));
INSERT INTO zasp_projection_work(organization_id,workspace_id,environment_id,snapshot_id,kind,version,input_digest,state,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$6,'risk','v1',$12,'leased','automatic-risk','automatic-risk-lease-0001',transaction_timestamp()+interval '3 minutes');
INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind) VALUES($1,$2,$3,$7,'identity','Source identity','active',now(),now(),'identity'),($1,$2,$3,$8,'asset','Source asset','active',now(),now(),'asset');
INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,first_seen_at,last_seen_at) VALUES($1,$2,$3,$11,$4,'aws',$6,$7,$8,'has_permission','automatic77-edge',now(),now());`, pgx.QueryExecModeSimpleProtocol, o, w, e, integration, syncID, snapshot, entry, sink, finding, evidence, edge, digest[:], identity.PrincipalID.String(), string(payload)); err != nil {
		t.Fatal("projection prerequisites", err)
	}
	parse := func(s string) domain.ProductID {
		v, err := domain.ParseProductID(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	return riskprojection.CompleteInput{Scope: identity.Scope, IntegrationID: parse(integration), SnapshotID: parse(snapshot), Source: "aws", Generation: 1, Version: "v1", Worker: "automatic-risk", LeaseToken: "automatic-risk-lease-0001", InputDigest: digest, Items: []riskprojection.Item{{Section: "evidence", ID: parse(evidence), Payload: payload}}}
}
