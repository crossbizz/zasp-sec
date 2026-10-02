package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Catch an unscoped recovery selector and two workers owning the same work.
// Foreign expired work is fault-injected configuration, never an acknowledgement.
func TestSecurityAgentMultistepApplicationDeploymentClaimPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
		defer deployment.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		foreign := "pid_8f000002-0000-4000-8000-000000000001"
		seedOrderedApplicationGatewayAt(t, ctx, owner, foreign, w, e, foreign)
		if _, err := owner.Exec(ctx, `UPDATE zasp_policy_deployment_work SET state='leased',lease_owner='foreign-worker',lease_token='foreign-expired-lease',lease_expires_at=clock_timestamp()-interval '1 second',leased_generation=desired_generation,leased_sequence=1,leased_policy_version=1,leased_credential_id=device_id,leased_input_digest=decode(repeat('ab',32),'hex') WHERE organization_id=$1`, foreign); err != nil {
			t.Fatal(err)
		}
		foreignSnapshot := func() string {
			var value string
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(w)::text FROM zasp_policy_deployment_work w WHERE organization_id=$1`, foreign).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		before := foreignSnapshot()
		r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 740, true)
		claimed, err := orderedProgressionCall(ctx, action, "application", orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0))
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		stored, err := orderedProgressionCall(ctx, action, "application", orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claimed, key))
		if err != nil {
			t.Fatal(err)
		}
		request := orderedApplicationDeploymentRequest(o, w, e, r, steps[0], stored)
		if _, err = deployment.Exec(ctx, `BEGIN`); err != nil {
			t.Fatal(err)
		}
		defer deployment.Exec(ctx, `ROLLBACK`)
		first, err := orderedProgressionCall(ctx, deployment, "deployment", request)
		if err != nil {
			t.Fatal("scoped deployment claim unavailable", err)
		}
		other, err := pgx.ConnectConfig(ctx, deployment.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(ctx)
		rival := cloneOrderedApplicationRequest(t, request)
		rival["lease_token"] = "ordered-deployment-rival-lease"
		done := make(chan error, 1)
		go func() { _, callErr := orderedProgressionCall(ctx, other, "deployment", rival); done <- callErr }()
		waitOrderedProgressionBlocked(t, ctx, deployment, other)
		if _, err = deployment.Exec(ctx, `COMMIT`); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil {
			t.Fatal("concurrent scoped claims acquired two leases")
		}
		if foreignSnapshot() != before {
			t.Fatal("scoped claim recovered unrelated tenant")
		}
		replay, err := orderedProgressionCall(ctx, other, "deployment", request)
		if err != nil || replay["work_id"] != first["work_id"] {
			t.Fatal("scoped deployment restart", replay, err)
		}
		var attempts int
		if err = owner.QueryRow(ctx, `SELECT attempt FROM zasp_policy_deployment_work WHERE organization_id=$1 AND device_id=$2`, o, orderedApplicationDevice).Scan(&attempts); err != nil || attempts != 1 {
			t.Fatal("duplicate deployment lease", attempts, err)
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_policy_deployment_work SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND device_id=$2`, o, orderedApplicationDevice); err != nil {
			t.Fatal(err)
		}
		if _, err = orderedProgressionCall(ctx, other, "deployment", request); err == nil {
			t.Fatal("expired claim replay accepted")
		}
		recovery, err := orderedProgressionCall(ctx, other, "deployment", rival)
		if err != nil || recovery["work_id"] != first["work_id"] || foreignSnapshot() != before {
			t.Fatal("scoped recovery", recovery, err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
		var leaked bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_audit WHERE run_id=$1 AND (body::text LIKE '%ordered-deployment-lease%' OR body::text LIKE '%ordered-deployment-rival-lease%' OR body::text LIKE '%ordered-application-lease%'))`, r).Scan(&leaked); err != nil || leaked {
			t.Fatal("lease credential leaked into audit", leaked, err)
		}
	})
}

func orderedApplicationDeploymentConnection(t *testing.T, ctx context.Context, owner *pgx.Conn) *pgx.Conn {
	t.Helper()
	if _, err := owner.Exec(ctx, `DO $role$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ordered_application_deployment') THEN CREATE ROLE ordered_application_deployment LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;END IF;END $role$`); err != nil {
		t.Fatal(err)
	}
	var registered bool
	if err := owner.QueryRow(ctx, `SELECT zasp_policy_deployment_register_principal(session_user,'ordered_application_deployment')`).Scan(&registered); err != nil || !registered {
		t.Fatal(err)
	}
	config := owner.Config().Copy()
	config.User = "ordered_application_deployment"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func orderedApplicationDeploymentRequest(o, w, e, r, s string, stored map[string]any) map[string]any {
	target := stored["targets"].([]any)[0].(map[string]any)
	return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "run_version": stored["run_version"], "effect_version": stored["effect_version"], "action_worker_id": "ordered-action-worker", "action_lease_token": "ordered-application-lease", "device_id": target["device_id"], "credential_id": target["credential_id"], "source_sequence": target["sequence"], "source_digest": target["envelope_digest"], "desired_generation": target["desired_generation"], "operation": "claim", "worker_id": "ordered-deployment", "lease_token": "ordered-deployment-lease", "lease_seconds": 60, "sequence": 0, "input_digest": "", "composition": map[string]any{}, "envelope": map[string]any{}, "digest": ""}
}

func cloneOrderedApplicationRequest(t *testing.T, request map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
