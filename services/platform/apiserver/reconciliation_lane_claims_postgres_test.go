package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestReconciliationLanePlanClaimsPreserveIsolationFairnessAndConcurrency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	scopes := [][3]string{{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()}, {"pid_78600001-0000-4000-8000-000000000001", "pid_78600002-0000-4000-8000-000000000002", "pid_78600003-0000-4000-8000-000000000003"}}
	// Explicit component fixtures. No provider or enrollment composition is claimed.
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,state) VALUES($1,$2,$3,$4,'github','1.0.0','Other tenant fixture','active')`, scopes[1][0], scopes[1][1], scopes[1][2], invocationIntegration); err != nil {
		t.Fatal(err)
	}
	connect := func() *pgx.Conn {
		config := admin.Config().Copy()
		config.User = "invocation_discovery_worker"
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { connection.Close(context.Background()) })
		return connection
	}
	worker := connect()
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	repository := &ConnectorRepository{database: database}
	sequence := 0
	seed := func(t *testing.T, scope int, provider, operation string, age int) string {
		sequence++
		id := fmt.Sprintf("pid_78600004-0000-4000-8000-%012d", sequence)
		s := scopes[scope]
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,connection_reference,available_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,digest($4::text,'sha256'),'unknown',CASE WHEN $7='pkce_cleanup' THEN 'ref:oauth/pkce/plan_fixture' ELSE NULL END,transaction_timestamp()-interval '1 minute',transaction_timestamp()-make_interval(secs=>$9))`, s[0], s[1], s[2], id, invocationIntegration, provider, operation, "plan-fixture-effect-"+id, age); err != nil {
			t.Fatal(err)
		}
		return id
	}
	reset := func(t *testing.T) {
		if _, err := admin.Exec(ctx, `DELETE FROM zasp_connector_effects; DELETE FROM zasp_connector_oauth_attempts`); err != nil {
			t.Fatal(err)
		}
	}
	claim := func(t *testing.T, limit int) []ConnectorEffectLease {
		items, err := repository.ClaimReconciliation(ctx, "plan-worker", 90, limit)
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	t.Run("scope fairness precedes global limit", func(t *testing.T) {
		defer reset(t)
		seed(t, 0, "nango:older_a", "bind", 120)
		seed(t, 0, "nango:older_b", "bind", 100)
		seed(t, 1, "nango:newer_a", "bind", 60)
		seed(t, 1, "nango:newer_b", "bind", 40)
		items := claim(t, 2)
		if len(items) != 2 || items[0].OrganizationID == items[1].OrganizationID {
			t.Fatalf("scope fairness lost: %#v", items)
		}
	})
	t.Run("another tenant live lease blocks the whole provider operation", func(t *testing.T) {
		defer reset(t)
		seed(t, 0, "github", "bind", 120)
		live := seed(t, 1, "github", "bind", 60)
		if _, err := admin.Exec(ctx, `UPDATE zasp_connector_effects SET lease_owner='other-worker',lease_token=repeat('a',64),lease_expires_at=transaction_timestamp()+interval '90 seconds' WHERE id=$1`, live); err != nil {
			t.Fatal(err)
		}
		if items := claim(t, 25); len(items) != 0 {
			t.Fatalf("cross-tenant lane leased twice: %#v", items)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_connector_effects SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=$1`, live); err != nil {
			t.Fatal(err)
		}
		if items := claim(t, 25); len(items) != 1 || items[0].OrganizationID != scopes[0][0] {
			t.Fatalf("global lane winner changed: %#v", items)
		}
	})
	t.Run("consuming PKCE remains excluded without hiding next eligible candidate", func(t *testing.T) {
		defer reset(t)
		blocked := seed(t, 0, "github", "pkce_cleanup", 120)
		eligible := seed(t, 0, "github", "pkce_cleanup", 60)
		const attempt = "pid_78600005-0000-4000-8000-000000000005"
		s := scopes[0]
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,id,integration_id,provider,principal_id,session_digest,state_hash,pkce_verifier_reference,request_digest,integration_version,configuration_digest,requested_scopes,status,expires_at,consumed_at) VALUES($1,$2,$3,$4,$5,'github',$6,decode(repeat('ab',32),'hex'),decode(repeat('ac',32),'hex'),'ref:oauth/pkce/plan_fixture',decode(repeat('ad',32),'hex'),1,decode(repeat('ae',32),'hex'),'["read:org"]','consuming',transaction_timestamp()+interval '5 minutes',transaction_timestamp())`, s[0], s[1], s[2], attempt, invocationIntegration, identity.PrincipalID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_connector_effects SET oauth_attempt_id=$1 WHERE id=$2`, attempt, blocked); err != nil {
			t.Fatal(err)
		}
		if items := claim(t, 25); len(items) != 1 || items[0].ID != eligible {
			t.Fatalf("PKCE eligibility changed: %#v", items)
		}
	})
	t.Run("attempt time and row-lock eligibility are unchanged", func(t *testing.T) {
		defer reset(t)
		attempt := seed(t, 0, "nango:attempt_cap", "bind", 60)
		future := seed(t, 0, "nango:future_time", "bind", 60)
		fresh := seed(t, 0, "nango:fresh_time", "bind", 1)
		locked := seed(t, 0, "nango:locked_row", "bind", 60)
		eligible := seed(t, 1, "nango:eligible_row", "bind", 60)
		if _, err := admin.Exec(ctx, `UPDATE zasp_connector_effects SET attempt=100 WHERE id=$1`, attempt); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_connector_effects SET available_at=transaction_timestamp()+interval '1 hour' WHERE id=$1`, future); err != nil {
			t.Fatal(err)
		}
		lock, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(context.Background())
		if _, err := lock.Exec(ctx, `SELECT 1 FROM zasp_connector_effects WHERE id=$1 FOR UPDATE`, locked); err != nil {
			t.Fatal(err)
		}
		items := claim(t, 25)
		if len(items) != 1 || items[0].ID != eligible {
			t.Fatalf("eligibility changed fresh=%s items=%#v", fresh, items)
		}
		if err := lock.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("global capacity remains one hundred", func(t *testing.T) {
		defer reset(t)
		for i := 0; i < 101; i++ {
			seed(t, i%2, fmt.Sprintf("nango:capacity_%03d", i), "bind", 60)
		}
		if items := claim(t, 100); len(items) != 100 {
			t.Fatalf("capacity claim=%d", len(items))
		}
		if items := claim(t, 100); len(items) != 0 {
			t.Fatalf("capacity exceeded by %d", len(items))
		}
	})
	t.Run("concurrent claim waits then observes committed global lease", func(t *testing.T) {
		defer reset(t)
		seed(t, 0, "github", "bind", 120)
		seed(t, 1, "github", "bind", 60)
		first, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Rollback(context.Background())
		var firstPayload []byte
		if err := first.QueryRow(ctx, postgresConnectorClaimReconciliationSQL, "plan-first", 90, 25).Scan(&firstPayload); err != nil {
			t.Fatal(err)
		}
		var firstPage struct {
			Items []ConnectorEffectLease `json:"items"`
		}
		if err := json.Unmarshal(firstPayload, &firstPage); err != nil || len(firstPage.Items) != 1 {
			t.Fatal("first global claim", err)
		}
		second := connect()
		secondDatabase, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: second})
		secondRepository := &ConnectorRepository{database: secondDatabase}
		type result struct {
			items []ConnectorEffectLease
			err   error
		}
		done := make(chan result, 1)
		go func() {
			items, err := secondRepository.ClaimReconciliation(ctx, "plan-second", 90, 25)
			done <- result{items, err}
		}()
		deadline := time.Now().Add(5 * time.Second)
		waiting := false
		for time.Now().Before(deadline) {
			if err := admin.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, second.PgConn().PID()).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !waiting {
			t.Fatal("second claim did not wait for the real advisory lock")
		}
		if err := first.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case secondResult := <-done:
			if secondResult.err != nil || len(secondResult.items) != 0 {
				t.Fatalf("concurrent global lane claim=%#v error=%v", secondResult.items, secondResult.err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	})
}
