package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// This deliberately pauses after a real claim, then changes its persistent
// source through the existing enqueue trigger. It characterizes supersession;
// it is not a successful action-worker recovery or a browser acceptance test.
func TestRuntimeCandidateAuthorityPolicySupersessionBaseline(t *testing.T) {
	for _, version := range []int{46, 47} {
		t.Run(fmt.Sprintf("schema%d", version), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, runner := reconciliationLanePlanPredecessor(t, ctx)
			if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
				t.Fatal(err)
			}
			if version == 47 {
				if err := runner.UpProductionRuntimeCandidateAuthority(ctx); err != nil {
					t.Fatal(err)
				}
			}
			assertProductionPolicyDeploymentLifecycle(t, ctx, admin.Config().ConnString(), admin, func(repository *PolicyDeploymentRepository, claim PolicyDeploymentClaim) {
				compiled, active, err := policy.CompileGatewayPolicy(claim.PersistentPolicies[0])
				if err != nil || !active {
					t.Fatal("claim policy could not compile", err)
				}
				_, privateKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(privateKey)
				now := time.Now().UTC().Truncate(time.Second)
				envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{
					KeyID: "gateway-key-v28", Binding: policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID},
					Sequence: uint64(claim.Sequence), PolicyVersion: uint64(claim.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), FailureMode: "closed", Policies: []policy.CompiledPolicy{compiled},
				}, privateKey)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(ctx, `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{rollout}','"disabled"'::jsonb),version=version+1,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'policy','policy-v28')`, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID); err != nil {
					t.Fatal(err)
				}
				_, storeErr := repository.StorePolicyDeployment(ctx, claim, "policy-deployment-v28", "lease-token-policy-v28-0001", envelope)
				if !errors.Is(storeErr, ErrRepositoryConflict) {
					t.Fatal("superseded store did not refuse with conflict", storeErr)
				}
				if _, readErr := repository.ReadPolicyDeployment(ctx, claim); !errors.Is(readErr, ErrRepositoryNotFound) {
					t.Fatal("rejected store unexpectedly produced a bundle", readErr)
				}
				claims, err := repository.ClaimPolicyDeployments(ctx, "policy-deployment-v28", "lease-token-policy-v28-0002", 60, 8)
				if err != nil || len(claims) != 0 {
					t.Fatal("superseded work was unexpectedly available before lease expiry", err)
				}
				var unchangedLease bool
				if err := admin.QueryRow(ctx, `SELECT state='leased' AND desired_generation>leased_generation AND leased_generation=$5 AND lease_expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id,sequence)=($1,$2,$3,$4,$6)) FROM zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id)=($1,$2,$3,$4)`, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.DeviceID, claim.DesiredGeneration, claim.Sequence).Scan(&unchangedLease); err != nil || !unchangedLease {
					t.Fatal("supersession did not retain the fenced lease without a stale bundle", err)
				}
				t.Log("supersession refused stale store; readback was missing; subsequent poll remained leased until expiry")
			})
		})
	}
}
