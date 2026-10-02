package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// The retained cleanup mode uses a separate SQL entry and closed composition
// variant. It never enables the historical bulk selector or generic worker.
func (repository *securityAgentMultistepAdmissionRepository) cleanupDeployment(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys) (json.RawMessage, error) {
	return repository.orderedDeployment(ctx, raw, keys, true)
}

func orderedCleanupVerifiedEnvelope(value policy.GatewayPolicyEnvelope, keys policy.GatewayPolicyKeys, o, w, e, d string, sequence int64) bool {
	if value.Sequence != uint64(sequence) || value.PolicyVersion != uint64(sequence) || value.FailureMode != "closed" || value.Policies == nil {
		return false
	}
	_, err := policy.VerifyGatewayPolicyEnvelope(value, keys, policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: d}, time.Now().UTC().Truncate(time.Second))
	return err == nil
}
