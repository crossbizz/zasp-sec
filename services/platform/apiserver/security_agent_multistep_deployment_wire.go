package apiserver

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// The gateway contract still caps its canonical signed envelope at 1 MiB.
// A signable composition holds at most that much compiled policy content plus
// at most one further copy in temporary sources. Persistent provenance is
// bounded by 100 policies * (32 conditions * (6*256 value bytes + 96 framing)
// + 6*(2*128 IDs + 256 name) + 512 framing) < 5.4 MiB, including JSON escaping.
// Source metadata and claim framing fit the remaining space below 8 MiB.
// Store adds one <=1 MiB signed envelope and bounded request fields; 10 MiB
// also covers PostgreSQL jsonb's inter-field spaces. Keep SQL deployment_wire
// and deployment_signable in parity. These limits do not change generic lanes.
const (
	orderedDeploymentGatewayBytes  = 1024 * 1024
	orderedDeploymentResponseBytes = 8 * 1024 * 1024
	orderedDeploymentRequestBytes  = 10 * 1024 * 1024
)

func orderedDeploymentClosedObject(raw json.RawMessage, maximum int, keys ...string) (map[string]json.RawMessage, bool) {
	if len(raw) > maximum || !utf8.Valid(raw) {
		return nil, false
	}
	fields, ok := securityAgentOrderedJSONObject(raw)
	if !ok || len(fields) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, present := fields[key]; !present {
			return nil, false
		}
	}
	return fields, true
}

// Claim does not bind a signing key, so reserve its full allowed 64-byte ID.
// This proves every legal configured key can fit, not that signing happened.
// Real store/read still verify the actual key, signature and unchanged 1 MiB
// size limit. A composition fitting only a shorter key is refused before lease.
func orderedDeploymentSignable(scope domain.Scope, device string, sequence int64, policies []policy.CompiledPolicy) bool {
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	value := policy.GatewayPolicyEnvelope{ContractVersion: 1, KeyID: strings.Repeat("k", 64), Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), DeviceID: device, Sequence: uint64(sequence), PolicyVersion: uint64(sequence), IssuedAt: when, ExpiresAt: when.Add(time.Hour), FailureMode: "closed", PayloadDigest: strings.Repeat("0", 64), Policies: policies, Signature: strings.Repeat("A", 86)}
	raw, err := json.Marshal(value)
	return err == nil && len(raw) <= orderedDeploymentGatewayBytes
}
