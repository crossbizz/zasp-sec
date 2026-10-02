package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// NewSecurityAgentTemporalExecutorRepository uses the autocommit JSON database
// boundary. No legacy principal, lease token or scheduler authority is used by
// its Temporal methods. SQL checks exact68 and the registered session identity.
func NewSecurityAgentTemporalExecutorRepository(database JSONDatabase) (*securityAgentMultistepAdmissionRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	return &securityAgentMultistepAdmissionRepository{database: database}, nil
}

// TemporalDelivery admits only a configured-key envelope, then verifies the
// persisted composition and signed readback before the caller can acknowledge.
func (repository *securityAgentMultistepAdmissionRepository) TemporalDelivery(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys) (json.RawMessage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !keys.Valid() {
		return nil, ErrRepositoryOperation
	}
	var q temporalEffectRequest
	if _, ok := orderedDeploymentClosedObject(raw, orderedDeploymentRequestBytes, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation", "operation", "payload"); !ok || decodeStrictDiscovery(raw, &q) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedApplicationScope(q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.StepID)
	if !valid || q.Generation != 1 {
		return nil, ErrRepositoryOperation
	}
	var p struct {
		DeviceID string          `json:"device_id"`
		Phase    string          `json:"phase"`
		Envelope json.RawMessage `json:"envelope"`
		Digest   string          `json:"digest"`
	}
	allowed := []string{"device_id", "phase"}
	switch q.Operation {
	case "prepare":
	case "store":
		allowed = append(allowed, "digest", "envelope")
	case "read", "ack":
		allowed = append(allowed, "digest")
	default:
		return nil, ErrRepositoryOperation
	}
	if _, ok := orderedDeploymentClosedObject(q.Payload, orderedDeploymentRequestBytes, allowed...); !ok || decodeStrictDiscovery(q.Payload, &p) != nil || !validProductID(p.DeviceID) || (p.Phase != "apply" && p.Phase != "cleanup") {
		return nil, ErrRepositoryOperation
	}
	if q.Operation != "prepare" {
		if _, ok := decodeTemporaryPolicyDigest(p.Digest); !ok {
			return nil, ErrRepositoryOperation
		}
	}
	verifyEnvelope := orderedVerifiedEnvelope
	if p.Phase == "cleanup" {
		verifyEnvelope = orderedCleanupVerifiedEnvelope
	}
	if q.Operation == "store" {
		var envelope policy.GatewayPolicyEnvelope
		if !orderedDecodeEnvelope(p.Envelope, &envelope) || envelope.Sequence < 1 || envelope.Sequence > 999999999 || !verifyEnvelope(envelope, keys, q.OrganizationID, q.WorkspaceID, q.EnvironmentID, p.DeviceID, int64(envelope.Sequence)) || orderedEnvelopeDigest(envelope) != p.Digest {
			return nil, ErrRepositoryOperation
		}
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := repository.database.QueryJSON(bounded, `SELECT zasp_temporal68.delivery($1::jsonb)`, raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var v struct {
		OrganizationID    string          `json:"organization_id"`
		WorkspaceID       string          `json:"workspace_id"`
		EnvironmentID     string          `json:"environment_id"`
		RunID             string          `json:"run_id"`
		StepID            string          `json:"step_id"`
		Generation        int64           `json:"generation"`
		EffectKey         string          `json:"effect_key"`
		Phase             string          `json:"phase"`
		DeviceID          string          `json:"device_id"`
		CredentialID      string          `json:"credential_id"`
		SourceSequence    int64           `json:"source_sequence"`
		SourceDigest      string          `json:"source_digest"`
		DesiredGeneration int64           `json:"desired_generation"`
		Sequence          int64           `json:"sequence"`
		Composition       json.RawMessage `json:"composition"`
		State             string          `json:"state"`
		Envelope          json.RawMessage `json:"envelope"`
		EnvelopeDigest    string          `json:"envelope_digest"`
		ReadAt            *time.Time      `json:"read_at"`
		AcknowledgedAt    *time.Time      `json:"acknowledged_at"`
	}
	if !temporalDeliveryResponseObject(response) || decodeStrictDiscovery(response, &v) != nil || v.OrganizationID != q.OrganizationID || v.WorkspaceID != q.WorkspaceID || v.EnvironmentID != q.EnvironmentID || v.RunID != q.RunID || v.StepID != q.StepID || v.Generation != 1 || v.EffectKey != temporalEffectIdentity(q) || v.Phase != p.Phase || v.DeviceID != p.DeviceID || !validProductID(v.CredentialID) || v.Sequence < 1 || v.Sequence > 999999999 || v.SourceSequence < 1 || v.DesiredGeneration < 1 || !strings.HasPrefix(v.SourceDigest, "\\x") {
		return nil, ErrRepositoryUnavailable
	}
	sourceDigest := "sha256:" + strings.TrimPrefix(v.SourceDigest, "\\x")
	composition, ok := orderedDeploymentCompositionModeValid(v.Composition, scope, q.RunID, q.StepID, p.DeviceID, v.CredentialID, v.SourceSequence, v.DesiredGeneration, sourceDigest, p.Phase == "cleanup")
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	switch v.State {
	case "prepared":
		if q.Operation != "prepare" || string(v.Envelope) != "null" || v.EnvelopeDigest != "" || v.ReadAt != nil || v.AcknowledgedAt != nil {
			return nil, ErrRepositoryUnavailable
		}
	case "stored", "read", "acknowledged":
		var envelope policy.GatewayPolicyEnvelope
		expires, parseErr := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
		if parseErr != nil || !orderedDecodeEnvelope(v.Envelope, &envelope) || !verifyEnvelope(envelope, keys, q.OrganizationID, q.WorkspaceID, q.EnvironmentID, p.DeviceID, v.Sequence) || !reflect.DeepEqual(envelope.Policies, composition.Policies) || envelope.ExpiresAt.After(expires) || !strings.HasPrefix(v.EnvelopeDigest, "\\x") || orderedEnvelopeDigest(envelope) != "sha256:"+strings.TrimPrefix(v.EnvelopeDigest, "\\x") || q.Operation != "prepare" && orderedEnvelopeDigest(envelope) != p.Digest {
			return nil, ErrRepositoryUnavailable
		}
		if v.State == "stored" && (v.ReadAt != nil || v.AcknowledgedAt != nil) || v.State == "read" && (v.ReadAt == nil || v.AcknowledgedAt != nil) || v.State == "acknowledged" && (v.ReadAt == nil || v.AcknowledgedAt == nil) || q.Operation == "read" && v.ReadAt == nil || q.Operation == "ack" && v.State != "acknowledged" {
			return nil, ErrRepositoryUnavailable
		}
	default:
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}

// Only not-yet-produced delivery evidence is nullable. Required scope and
// authority fields still reject null, missing, duplicate and unknown keys.
func temporalDeliveryResponseObject(raw json.RawMessage) bool {
	if len(raw) > orderedDeploymentResponseBytes {
		return false
	}
	required := strings.Fields("organization_id workspace_id environment_id run_id step_id generation effect_key phase device_id credential_id source_sequence source_digest desired_generation sequence composition state envelope envelope_digest read_at acknowledged_at")
	nullable := []string{"envelope", "envelope_digest", "read_at", "acknowledged_at"}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || !slices.Contains(required, key) {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !slices.Contains(nullable, key) {
			return false
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(seen) != len(required) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

type temporalEffectRequest struct {
	OrganizationID string          `json:"organization_id"`
	WorkspaceID    string          `json:"workspace_id"`
	EnvironmentID  string          `json:"environment_id"`
	RunID          string          `json:"run_id"`
	StepID         string          `json:"step_id"`
	Generation     int64           `json:"generation"`
	Operation      string          `json:"operation"`
	Payload        json.RawMessage `json:"payload"`
}

func temporalEffectIdentity(q temporalEffectRequest) string {
	value := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.StepID, "1"}, "\x1f")))
	return hex.EncodeToString(value[:])
}

// TemporalApplication verifies configured keys before SQL. The returned
// source target must bind the same bytes, resource, sequence and effect key.
func (repository *securityAgentMultistepAdmissionRepository) TemporalApplication(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys) (json.RawMessage, error) {
	return repository.temporalSource(ctx, raw, keys, false)
}

func (repository *securityAgentMultistepAdmissionRepository) TemporalCleanupSource(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys) (json.RawMessage, error) {
	return repository.temporalSource(ctx, raw, keys, true)
}

func (repository *securityAgentMultistepAdmissionRepository) temporalSource(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys, cleanup bool) (json.RawMessage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > 32768 {
		return nil, ErrRepositoryOperation
	}
	var q temporalEffectRequest
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation", "operation", "payload"); !ok || decodeStrictDiscovery(raw, &q) != nil {
		return nil, ErrRepositoryOperation
	}
	if _, valid := orderedApplicationScope(q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.StepID); !valid || q.Generation != 1 {
		return nil, ErrRepositoryOperation
	}
	var source orderedApplicationSource
	verifyEnvelope := orderedVerifiedEnvelope
	if cleanup {
		verifyEnvelope = orderedCleanupVerifiedEnvelope
	}
	sourcePayload := q.Payload
	if q.Operation == "renew" {
		var renewal struct {
			SourceDigest string          `json:"source_digest"`
			Envelope     json.RawMessage `json:"envelope"`
		}
		if !cleanup {
			return nil, ErrRepositoryOperation
		}
		if _, ok := securityAgentOrderedClosedObject(q.Payload, "source_digest", "envelope"); !ok || decodeStrictDiscovery(q.Payload, &renewal) != nil {
			return nil, ErrRepositoryOperation
		}
		if _, ok := decodeTemporaryPolicyDigest(renewal.SourceDigest); !ok {
			return nil, ErrRepositoryOperation
		}
		sourcePayload = renewal.Envelope
	}
	switch q.Operation {
	case "read":
		if _, ok := securityAgentOrderedClosedObject(q.Payload); !ok {
			return nil, ErrRepositoryOperation
		}
	case "source", "renew":
		if _, ok := securityAgentOrderedClosedObject(sourcePayload, "device_id", "credential_id", "sequence", "policy_version", "key_id", "issued_at", "expires_at", "failure_mode", "payload_digest", "policies", "signature", "envelope_digest"); !ok || decodeStrictDiscovery(sourcePayload, &source) != nil || !validProductID(source.DeviceID) || !validProductID(source.CredentialID) || source.Sequence < 1 || source.Sequence > 999999999 || source.PolicyVersion != source.Sequence || (!cleanup && !orderedContainmentPolicies(source.Policies, true)) || (cleanup && (source.Policies == nil || len(source.Policies) != 0)) {
			return nil, ErrRepositoryOperation
		}
		signature, err := base64.StdEncoding.DecodeString(source.Signature)
		envelope := policy.GatewayPolicyEnvelope{ContractVersion: 1, Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: q.OrganizationID, WorkspaceID: q.WorkspaceID, EnvironmentID: q.EnvironmentID, DeviceID: source.DeviceID, Sequence: uint64(source.Sequence), PolicyVersion: uint64(source.PolicyVersion), KeyID: source.KeyID, IssuedAt: source.IssuedAt, ExpiresAt: source.ExpiresAt, FailureMode: source.FailureMode, PayloadDigest: strings.TrimPrefix(source.PayloadDigest, "sha256:"), Policies: source.Policies, Signature: base64.RawURLEncoding.EncodeToString(signature)}
		if err != nil || !strings.HasPrefix(source.PayloadDigest, "sha256:") || !verifyEnvelope(envelope, keys, q.OrganizationID, q.WorkspaceID, q.EnvironmentID, source.DeviceID, source.Sequence) || orderedEnvelopeDigest(envelope) != source.EnvelopeDigest {
			return nil, ErrRepositoryOperation
		}
	default:
		return nil, ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	query := `SELECT zasp_temporal68.application($1::jsonb)`
	if cleanup {
		query = `SELECT zasp_temporal68.cleanup($1::jsonb)`
	}
	response, err := repository.database.QueryJSON(bounded, query, raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var result struct {
		OrganizationID string            `json:"organization_id"`
		WorkspaceID    string            `json:"workspace_id"`
		EnvironmentID  string            `json:"environment_id"`
		RunID          string            `json:"run_id"`
		StepID         string            `json:"step_id"`
		Generation     int64             `json:"generation"`
		EffectKey      string            `json:"effect_key"`
		TTLSeconds     int               `json:"ttl_seconds"`
		Targets        []json.RawMessage `json:"targets"`
	}
	if _, ok := securityAgentOrderedClosedObject(response, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation", "effect_key", "ttl_seconds", "targets"); !ok || decodeStrictDiscovery(response, &result) != nil || result.OrganizationID != q.OrganizationID || result.WorkspaceID != q.WorkspaceID || result.EnvironmentID != q.EnvironmentID || result.RunID != q.RunID || result.StepID != q.StepID || result.Generation != 1 || result.EffectKey != temporalEffectIdentity(q) || result.TTLSeconds < 60 || result.TTLSeconds > 3600 || len(result.Targets) < 1 || len(result.Targets) > 100 {
		return nil, ErrRepositoryUnavailable
	}
	last := ""
	stored := false
	for _, rawTarget := range result.Targets {
		var target orderedApplicationTarget
		if _, ok := securityAgentOrderedClosedObject(rawTarget, "device_id", "credential_id", "sequence", "policy_version", "state", "desired_generation", "envelope_digest"); !ok || decodeStrictDiscovery(rawTarget, &target) != nil || !validProductID(target.DeviceID) || !validProductID(target.CredentialID) || target.DeviceID <= last || target.Sequence < 1 || target.Sequence > 999999999 || target.PolicyVersion != target.Sequence {
			return nil, ErrRepositoryUnavailable
		}
		last = target.DeviceID
		if target.State == "planned" {
			if target.DesiredGeneration != 0 || target.EnvelopeDigest != "" {
				return nil, ErrRepositoryUnavailable
			}
		} else if _, ok := decodeTemporaryPolicyDigest(target.EnvelopeDigest); !ok || target.DesiredGeneration < 1 || target.DesiredGeneration > 999999999 || (target.State != "stored" && target.State != "verified") {
			return nil, ErrRepositoryUnavailable
		}
		if q.Operation != "read" && target.DeviceID == source.DeviceID {
			stored = target.CredentialID == source.CredentialID && target.Sequence == source.Sequence && target.EnvelopeDigest == source.EnvelopeDigest && target.State == "stored"
		}
	}
	if q.Operation != "read" && (!stored || source.ExpiresAt.Sub(source.IssuedAt) != time.Duration(result.TTLSeconds)*time.Second) {
		return nil, ErrRepositoryUnavailable
	}
	if cleanup && result.TTLSeconds != 300 {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}
