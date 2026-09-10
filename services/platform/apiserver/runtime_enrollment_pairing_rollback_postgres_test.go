package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimeEnrollmentPairingRollbackWaitsForRetainedProvenance(t *testing.T) {
	for _, scenario := range []string{"pairing", "batch"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
			for _, up := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing} {
				if err := up(ctx); err != nil {
					t.Fatal(err)
				}
			}
			connect := func(user string) *pgx.Conn {
				config := admin.Config().Copy()
				config.User = user
				connection, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { connection.Close(context.Background()) })
				return connection
			}
			rollback := connect(admin.Config().User)
			rollbackRunner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: rollback})
			if err != nil {
				t.Fatal(err)
			}
			identity := fixtureRequestIdentity(t)
			org, workspace, environment, principal := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
			const anchor = "pid_78300001-0000-4000-8000-000000000001"
			const source = "pid_78300002-0000-4000-8000-000000000002"
			const token = "pid_78300003-0000-4000-8000-000000000003"
			const batch = "pid_78300004-0000-4000-8000-000000000004"
			digest := sha256.Sum256([]byte("rollback-pairing-provenance-fixture"))
			if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Concurrent rollback anchor','tetragon','active')`, org, workspace, environment, anchor); err != nil {
				t.Fatal(err)
			}
			var mutation pgx.Tx
			if scenario == "pairing" {
				if _, err := admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'rollback-org','rollback-member','security_admin',true) ON CONFLICT(organization_id,principal_id) DO UPDATE SET role='security_admin',active=true`, org, principal); err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Rollback proof','["view","manage_workflows"]',true) ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions='["view","manage_workflows"]'`, org, workspace, environment, principal); err != nil {
					t.Fatal(err)
				}
				api := connect("invocation_discovery_api")
				mutation, err = api.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer mutation.Rollback(context.Background())
				var receipt json.RawMessage
				if err := mutation.QueryRow(ctx, pairedSensorCreateSQL, org, workspace, environment, principal, source, "Concurrent paired source", "otlp", "metadata_only", "rollback-pairing-request-0001", digest[:], token, int64(1), digest[:], digest[:], digest[:], time.Now().UTC().Add(time.Hour), anchor).Scan(&receipt); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$6,clock_timestamp()+interval '1 hour')`, org, workspace, environment, token, anchor, digest[:]); err != nil {
					t.Fatal(err)
				}
				writer := connect(admin.Config().User)
				mutation, err = writer.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer mutation.Rollback(context.Background())
				if _, err := mutation.Exec(ctx, `INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key) VALUES($1,$2,$3,$4,$5,$6,1,1,'rollback-batch-fixture-0001',$7,$7,'tetragon','application/json','runtime-event-v1',1,1,'runtime/v15/rollback-batch-fixture-0001.json')`, org, workspace, environment, batch, anchor, token, digest[:]); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { done <- rollbackRunner.DownProductionRuntimeEnrollmentPairing(ctx) }()
			waiting := false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				if err := admin.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, rollback.PgConn().PID()).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case early := <-done:
					t.Fatalf("rollback bypassed uncommitted %s: %v", scenario, early)
				case <-time.After(10 * time.Millisecond):
				}
			}
			if !waiting {
				t.Fatal("rollback lock wait not observed")
			}
			if err := mutation.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("rollback discarded concurrently committed provenance")
			}
			if version, err := runner.Version(ctx); err != nil || version != 45 {
				t.Fatalf("rollback changed schema version=%d error=%v", version, err)
			}
			var count int
			table := "zasp_runtime_sensor_pairings"
			if scenario == "batch" {
				table = "zasp_runtime_batch_domains"
			}
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&count); err != nil || count != 1 {
				t.Fatal("concurrent provenance lost", err)
			}
		})
	}
}
