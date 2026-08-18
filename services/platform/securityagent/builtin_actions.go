package securityagent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

type BuiltinBackend interface {
	Supports(context.Context, string, map[string]string) bool
	Execute(context.Context, string, map[string]string, string) (string, error)
	Verify(context.Context, string, map[string]string, string) (VerificationOutcome, error)
}
type ResponseWebhookSigner interface {
	WebhookSigningSecret(context.Context, string) ([]byte, error)
}
type responseWebhookEvent struct {
	Type           string `json:"type"`
	OrganizationID string `json:"organization_id"`
	RunID          string `json:"run_id"`
	EvidenceID     string `json:"evidence_id"`
}
type builtinAction struct {
	metadata ActionMetadata
	backend  BuiltinBackend
	mu       sync.Mutex
	results  map[string]ActionResult
}

func (action *builtinAction) Metadata() ActionMetadata { return action.metadata }
func (action *builtinAction) Validate(ctx context.Context, request ActionRequest) error {
	if action == nil || action.backend == nil || invalidContext(ctx) || request.ActionKey != action.metadata.Key || !bounded(request.OrganizationID, 128) || !bounded(request.RunID, 128) || !bounded(request.StepID, 128) || !validBuiltinParameters(request) {
		return ErrRejected
	}
	if !action.backend.Supports(ctx, request.ActionKey, cloneParameters(request.Parameters)) {
		return ErrRejected
	}
	return nil
}
func (action *builtinAction) Execute(ctx context.Context, request ActionRequest) (ActionResult, error) {
	if err := action.Validate(ctx, request); err != nil {
		return ActionResult{}, err
	}
	key, err := idempotencyKey(request.OrganizationID, request.RunID, request.StepID, request.ActionKey)
	if err != nil {
		return ActionResult{}, err
	}
	action.mu.Lock()
	defer action.mu.Unlock()
	if prior, ok := action.results[key]; ok {
		return prior, nil
	}
	parameters := cloneParameters(request.Parameters)
	if request.ActionKey == "send_response_webhook" {
		parameters, err = action.signedWebhookParameters(ctx, request)
		if err != nil {
			return ActionResult{}, err
		}
	}
	outcomeID, err := action.backend.Execute(ctx, request.ActionKey, parameters, key)
	if err != nil || !bounded(outcomeID, 128) {
		return ActionResult{}, ErrRejected
	}
	result := ActionResult{OutcomeID: outcomeID, State: "succeeded"}
	action.results[key] = result
	return result, nil
}
func (action *builtinAction) signedWebhookParameters(ctx context.Context, request ActionRequest) (map[string]string, error) {
	signer, ok := action.backend.(ResponseWebhookSigner)
	if !ok {
		return nil, ErrRejected
	}
	secret, err := webhookSecret(ctx, signer, request.Parameters["destination_id"])
	if err != nil || len(secret) < 16 || len(secret) > 256 {
		return nil, ErrRejected
	}
	body, err := json.Marshal(responseWebhookEvent{Type: "security_agent.response", OrganizationID: request.OrganizationID, RunID: request.RunID, EvidenceID: request.Parameters["evidence_id"]})
	if err != nil || len(body) == 0 || len(body) > 4096 {
		return nil, ErrRejected
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return map[string]string{"destination_id": request.Parameters["destination_id"], "payload": string(body), "signature": hex.EncodeToString(mac.Sum(nil))}, nil
}
func webhookSecret(ctx context.Context, signer ResponseWebhookSigner, destinationID string) (secret []byte, resultErr error) {
	defer func() {
		if recover() != nil {
			secret = nil
			resultErr = ErrRejected
		}
	}()
	secret, err := signer.WebhookSigningSecret(ctx, destinationID)
	if err != nil || ctx.Err() != nil {
		return nil, ErrRejected
	}
	return append([]byte(nil), secret...), nil
}
func (action *builtinAction) Verify(ctx context.Context, request ActionRequest, result ActionResult) error {
	if action.VerifyOutcome(ctx, request, result).State != VerificationVerified {
		return ErrRejected
	}
	return nil
}
func (action *builtinAction) VerifyOutcome(ctx context.Context, request ActionRequest, result ActionResult) VerificationOutcome {
	if err := action.Validate(ctx, request); err != nil || result.State != "succeeded" || !bounded(result.OutcomeID, 128) {
		return VerificationOutcome{State: VerificationInconclusive}
	}
	outcome, err := action.backend.Verify(ctx, request.ActionKey, cloneParameters(request.Parameters), result.OutcomeID)
	if err != nil || outcome.State != VerificationVerified {
		return VerificationOutcome{State: VerificationInconclusive}
	}
	return outcome
}

func RegisterResponseActions(registry *Registry, backend BuiltinBackend) error {
	if registry == nil || backend == nil {
		return ErrRejected
	}
	for _, metadata := range responseActionMetadata() {
		if err := registry.Register(&builtinAction{metadata: metadata, backend: backend, results: map[string]ActionResult{}}); err != nil {
			return err
		}
	}
	return nil
}
func responseActionMetadata() []ActionMetadata {
	return []ActionMetadata{
		{Key: "isolate_session", InputSchema: map[string]string{"session_id": "string", "scope": "string", "ttl": "duration"}, RiskClass: "containment", TargetTypes: []string{"session"}, ApprovalFloor: "operator", Reversible: true, Idempotent: true, VerificationKind: "gateway_decision"},
		{Key: "run_test", InputSchema: map[string]string{"test_definition_id": "string"}, RiskClass: "low", TargetTypes: []string{"test_definition"}, ApprovalFloor: "none", Reversible: true, Idempotent: true, VerificationKind: "test_run"},
		{Key: "rerun_test", InputSchema: map[string]string{"test_definition_id": "string"}, RiskClass: "low", TargetTypes: []string{"test_definition"}, ApprovalFloor: "none", Reversible: true, Idempotent: true, VerificationKind: "test_run"},
		{Key: "start_attack_lab", InputSchema: map[string]string{"test_definition_id": "string", "target_class": "enum:non_production,test", "preflight": "enum:approved"}, RiskClass: "moderate", TargetTypes: []string{"attack_lab"}, ApprovalFloor: "operator", Reversible: true, Idempotent: true, VerificationKind: "attack_lab_run"},
		{Key: "create_evidence_export", InputSchema: map[string]string{"run_id": "string", "evidence_ids": "string"}, RiskClass: "low", TargetTypes: []string{"evidence"}, ApprovalFloor: "none", Reversible: true, Idempotent: true, VerificationKind: "export"},
		{Key: "send_response_webhook", InputSchema: map[string]string{"destination_id": "string", "evidence_id": "string"}, RiskClass: "moderate", TargetTypes: []string{"configured_webhook"}, ApprovalFloor: "operator", Reversible: false, Idempotent: true, VerificationKind: "signed_delivery"},
		{Key: "update_finding_response", InputSchema: map[string]string{"finding_id": "string", "assignee_id": "string", "status": "enum:open,investigating", "note": "string"}, RiskClass: "low", TargetTypes: []string{"finding"}, ApprovalFloor: "none", Reversible: true, Idempotent: true, VerificationKind: "finding_state"},
		{Key: "revoke_integration_connection", InputSchema: map[string]string{"connection_id": "string", "approval_token": "string"}, RiskClass: "destructive", TargetTypes: []string{"integration_connection"}, ApprovalFloor: "admin", Reversible: false, Idempotent: true, VerificationKind: "connection_state"},
	}
}
func validBuiltinParameters(request ActionRequest) bool {
	exact := func(keys ...string) bool {
		if len(request.Parameters) != len(keys) {
			return false
		}
		for _, key := range keys {
			if !bounded(request.Parameters[key], 512) {
				return false
			}
		}
		return true
	}
	switch request.ActionKey {
	case "isolate_session":
		if !exact("session_id", "scope", "ttl") {
			return false
		}
		ttl, err := time.ParseDuration(request.Parameters["ttl"])
		return err == nil && ttl > 0 && ttl <= 24*time.Hour
	case "run_test", "rerun_test":
		return exact("test_definition_id")
	case "start_attack_lab":
		return exact("test_definition_id", "target_class", "preflight") && contains([]string{"non_production", "test"}, request.Parameters["target_class"]) && request.Parameters["preflight"] == "approved"
	case "create_evidence_export":
		if !exact("run_id", "evidence_ids") || request.Parameters["run_id"] != request.RunID {
			return false
		}
		ids := strings.Split(request.Parameters["evidence_ids"], ",")
		if len(ids) == 0 || len(ids) > 100 {
			return false
		}
		for _, id := range ids {
			if !strings.HasPrefix(id, request.RunID+":") || !bounded(id, 256) {
				return false
			}
		}
		return true
	case "send_response_webhook":
		return exact("destination_id", "evidence_id") && strings.HasPrefix(request.Parameters["evidence_id"], request.RunID+":")
	case "update_finding_response":
		return exact("finding_id", "assignee_id", "status", "note") && contains([]string{"open", "investigating"}, request.Parameters["status"])
	case "revoke_integration_connection":
		return exact("connection_id", "approval_token")
	default:
		return false
	}
}
