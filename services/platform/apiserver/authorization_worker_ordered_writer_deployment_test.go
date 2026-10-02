package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Complete actual retained deployment work before the action finish guard.
// No owner update to applied_generation, target state or audit rows is used.
func completeOrderedLegacyDeployment(t *testing.T, ctx context.Context, owner *pgx.Conn, run string) {
	t.Helper()
	const login = "ordered_writer_deployment_login"
	var exists bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, login).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := owner.Exec(ctx, `CREATE ROLE ordered_writer_deployment_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		var registered bool
		if err := owner.QueryRow(ctx, `SELECT zasp_policy_deployment_register_principal(session_user,$1)`, login).Scan(&registered); err != nil || !registered {
			t.Fatal("deployment fixture registration", err)
		}
	}
	config := owner.Config().Copy()
	config.User = login
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := connection.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPolicyDeploymentRepository(database)
	if err != nil {
		t.Fatal("registered deployment fixture repository", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-writer-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 16; attempt++ {
		var pending bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets t WHERE t.run_id=$1 AND t.phase='apply' AND NOT EXISTS(SELECT 1 FROM zasp_policy_deployment_work w WHERE(w.organization_id,w.workspace_id,w.environment_id,w.device_id)=(t.organization_id,t.workspace_id,t.environment_id,t.device_id) AND w.applied_generation>=t.desired_generation))`, run).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if !pending {
			return
		}
		claims, err := repository.ClaimPolicyDeployments(ctx, "ordered-deployment", "ordered-deployment-lease", 60, 25)
		if err != nil || len(claims) == 0 {
			t.Fatal("actual deployment claims absent", err)
		}
		for _, claim := range claims {
			values := make([]policy.CompiledPolicy, 0, len(claim.PersistentPolicies)+len(claim.TemporaryPolicies))
			failureMode := "open"
			for _, source := range claim.PersistentPolicies {
				value, active, err := policy.CompileGatewayPolicy(source)
				if err != nil {
					t.Fatal(err)
				}
				if active {
					values = append(values, value)
					if source.FailureMode == "closed" {
						failureMode = "closed"
					}
				}
			}
			values = append(values, claim.TemporaryPolicies...)
			if len(claim.TemporaryPolicies) != 0 {
				failureMode = "closed"
			}
			sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
			now := time.Now().UTC().Truncate(time.Second)
			expires := now.Add(10 * time.Minute)
			if claim.TemporaryExpiresAt != nil && claim.TemporaryExpiresAt.Before(expires) {
				expires = *claim.TemporaryExpiresAt
			}
			binding := policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}
			envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-writer-key", Binding: binding, Sequence: uint64(claim.Sequence), PolicyVersion: uint64(claim.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: failureMode, Policies: values}, privateKey)
			if err != nil {
				t.Fatal("deployment fixture signature", err)
			}
			digest, err := repository.StorePolicyDeployment(ctx, claim, "ordered-deployment", "ordered-deployment-lease", envelope)
			if err != nil {
				t.Fatal("actual deployment store", err)
			}
			readback, err := repository.ReadPolicyDeployment(ctx, claim)
			if err != nil {
				t.Fatal("actual deployment read", err)
			}
			if _, err := policy.VerifyGatewayPolicyEnvelope(readback, keys, binding, now); err != nil {
				t.Fatal("actual deployment readback verification", err)
			}
			if err := repository.FinishPolicyDeployment(ctx, claim, "ordered-deployment", "ordered-deployment-lease", digest); err != nil {
				t.Fatal("actual deployment finish", err)
			}
		}
	}
	t.Fatal("retained deployment fixture did not converge within bounded claims")
}
