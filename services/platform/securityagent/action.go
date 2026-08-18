package securityagent

import (
	"context"
	"sync"
	"time"
)

type ActionRequest struct {
	OrganizationID, RunID, StepID, ActionKey string
	Parameters                               map[string]string
}
type ActionResult struct{ OutcomeID, State string }
type SecurityAction interface {
	Metadata() ActionMetadata
	Validate(context.Context, ActionRequest) error
	Execute(context.Context, ActionRequest) (ActionResult, error)
	Verify(context.Context, ActionRequest, ActionResult) error
}
type Registry struct {
	mu      sync.RWMutex
	actions map[string]SecurityAction
}

func NewRegistry() *Registry { return &Registry{actions: map[string]SecurityAction{}} }
func (registry *Registry) Register(action SecurityAction) error {
	if registry == nil || action == nil {
		return ErrRejected
	}
	metadata := action.Metadata()
	if ValidateActionMetadata(metadata) != nil {
		return ErrRejected
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, ok := registry.actions[metadata.Key]; ok {
		return ErrRejected
	}
	registry.actions[metadata.Key] = action
	return nil
}
func (registry *Registry) lookup(key string) (SecurityAction, error) {
	if registry == nil || !bounded(key, 128) {
		return nil, ErrRejected
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	action, ok := registry.actions[key]
	if !ok {
		return nil, ErrRejected
	}
	return action, nil
}
func (registry *Registry) Execute(ctx context.Context, request ActionRequest) (ActionResult, error) {
	action, err := registry.lookup(request.ActionKey)
	if err != nil {
		return ActionResult{}, err
	}
	if err := action.Validate(ctx, request); err != nil {
		return ActionResult{}, err
	}
	return action.Execute(ctx, request)
}
func (registry *Registry) Verify(ctx context.Context, request ActionRequest, result ActionResult) error {
	action, err := registry.lookup(request.ActionKey)
	if err != nil {
		return err
	}
	return action.Verify(ctx, request, result)
}

type TemporaryPolicySpec struct {
	OrganizationID, Scope, Mode string
	TTL                         time.Duration
}
type TemporaryPolicyService interface {
	CreateTemporaryPolicy(context.Context, TemporaryPolicySpec, string) (string, error)
	VerifyTemporaryPolicy(context.Context, string, TemporaryPolicySpec) error
}
type TemporaryPolicyAction struct {
	service TemporaryPolicyService
	mu      sync.Mutex
	results map[string]ActionResult
}

func NewTemporaryPolicyAction(service TemporaryPolicyService) (*TemporaryPolicyAction, error) {
	if service == nil {
		return nil, ErrRejected
	}
	return &TemporaryPolicyAction{service: service, results: map[string]ActionResult{}}, nil
}
func (action *TemporaryPolicyAction) Metadata() ActionMetadata {
	return ActionMetadata{Key: "create_temporary_policy", InputSchema: map[string]string{"mode": "enum:monitor,block", "scope": "string", "ttl": "duration"}, RiskClass: "containment", TargetTypes: []string{"environment"}, ApprovalFloor: "operator", Reversible: true, Idempotent: true, VerificationKind: "policy_state"}
}
func (action *TemporaryPolicyAction) Validate(ctx context.Context, request ActionRequest) error {
	if action == nil || action.service == nil || invalidContext(ctx) || request.ActionKey != "create_temporary_policy" || !bounded(request.OrganizationID, 128) || !bounded(request.RunID, 128) || !bounded(request.StepID, 128) || len(request.Parameters) != 3 {
		return ErrRejected
	}
	metadata := action.Metadata()
	for key, schema := range metadata.InputSchema {
		value, ok := request.Parameters[key]
		if !ok || !validInput(schema, value) {
			return ErrRejected
		}
	}
	return nil
}
func (action *TemporaryPolicyAction) spec(request ActionRequest) (TemporaryPolicySpec, error) {
	duration, err := time.ParseDuration(request.Parameters["ttl"])
	if err != nil {
		return TemporaryPolicySpec{}, ErrRejected
	}
	return TemporaryPolicySpec{OrganizationID: request.OrganizationID, Scope: request.Parameters["scope"], Mode: request.Parameters["mode"], TTL: duration}, nil
}
func (action *TemporaryPolicyAction) Execute(ctx context.Context, request ActionRequest) (ActionResult, error) {
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
	spec, err := action.spec(request)
	if err != nil {
		return ActionResult{}, err
	}
	policyID, err := action.service.CreateTemporaryPolicy(ctx, spec, key)
	if err != nil || !bounded(policyID, 128) {
		return ActionResult{}, ErrRejected
	}
	result := ActionResult{OutcomeID: policyID, State: "succeeded"}
	action.results[key] = result
	return result, nil
}
func (action *TemporaryPolicyAction) Verify(ctx context.Context, request ActionRequest, result ActionResult) error {
	if err := action.Validate(ctx, request); err != nil || result.State != "succeeded" || !bounded(result.OutcomeID, 128) {
		return ErrRejected
	}
	spec, err := action.spec(request)
	if err != nil {
		return err
	}
	if err := action.service.VerifyTemporaryPolicy(ctx, result.OutcomeID, spec); err != nil {
		return ErrRejected
	}
	return nil
}
