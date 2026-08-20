package main

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

var errGatewayRuntime = errors.New("gateway runtime unavailable")

var gatewayClassificationValuePattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,63}$`)

const gatewayPolicyAudience = "runtime-gateway-policy"

type gatewayAuthority struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	DeviceID       string
	CredentialID   string
	ReplayFloor    uint64
}

func (authority gatewayAuthority) Binding() policy.GatewayPolicyBinding {
	return policy.GatewayPolicyBinding{
		OrganizationID: authority.OrganizationID,
		WorkspaceID:    authority.WorkspaceID,
		EnvironmentID:  authority.EnvironmentID,
		DeviceID:       authority.DeviceID,
	}
}

type gatewayDecisionEvent struct {
	CredentialID   string
	DeviceID       string
	EventID        string
	ExpectedFloor  uint64
	NextFloor      uint64
	PolicyVersion  uint64
	Decision       string
	ActionKind     string
	Classification map[string]string
	OccurredAt     time.Time
}

type gatewayControlPlane interface {
	Ready(context.Context) error
	Authority(context.Context, string) (gatewayAuthority, error)
	Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error)
	Record(context.Context, gatewayDecisionEvent) error
}

type gatewayRuntimeConfig struct {
	Control              gatewayControlPlane
	Cache                *policy.GatewayPolicyCache
	CredentialID         string
	BootstrapFailureMode string
	MaximumPendingEvents int
	Now                  func() time.Time
}

type gatewayEvaluationRequest struct {
	EventID        string            `json:"event_id"`
	ActionKind     string            `json:"action_kind"`
	Attributes     map[string]string `json:"attributes"`
	Classification map[string]string `json:"classification"`
}

type gatewayEvaluationResult struct {
	Decision         string   `json:"decision"`
	PolicyVersion    uint64   `json:"policy_version"`
	CacheState       string   `json:"cache_state"`
	MatchedPolicyIDs []string `json:"matched_policy_ids"`
}

type gatewayRuntime struct {
	mu sync.Mutex

	control              gatewayControlPlane
	cache                *policy.GatewayPolicyCache
	credentialID         string
	bootstrapFailureMode string
	maximumPendingEvents int
	now                  func() time.Time

	authority      gatewayAuthority
	policySequence uint64
	confirmedFloor uint64
	nextFloor      uint64
	pending        []gatewayDecisionEvent
}

func newGatewayRuntime(config gatewayRuntimeConfig) (*gatewayRuntime, error) {
	if config.Control == nil || config.Cache == nil || !validGatewayProductID(config.CredentialID) ||
		config.BootstrapFailureMode != "open" && config.BootstrapFailureMode != "closed" ||
		config.MaximumPendingEvents < 1 || config.MaximumPendingEvents > 1024 || config.Now == nil {
		return nil, errGatewayRuntime
	}
	now := config.Now()
	if !validGatewayTime(now) {
		return nil, errGatewayRuntime
	}
	return &gatewayRuntime{
		control:              config.Control,
		cache:                config.Cache,
		credentialID:         config.CredentialID,
		bootstrapFailureMode: config.BootstrapFailureMode,
		maximumPendingEvents: config.MaximumPendingEvents,
		now:                  config.Now,
		pending:              make([]gatewayDecisionEvent, 0, config.MaximumPendingEvents),
	}, nil
}

func (runtime *gatewayRuntime) SyncOnce(ctx context.Context) error {
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return errGatewayRuntime
	}
	if err := runtime.control.Ready(ctx); err != nil {
		return errGatewayRuntime
	}
	authority, err := runtime.control.Authority(ctx, runtime.credentialID)
	if err != nil || !validGatewayAuthority(authority, runtime.credentialID) {
		return errGatewayRuntime
	}

	runtime.mu.Lock()
	if runtime.authority.CredentialID != "" && !sameGatewayAuthority(runtime.authority, authority) {
		runtime.mu.Unlock()
		return errGatewayRuntime
	}
	if authority.ReplayFloor < runtime.confirmedFloor || len(runtime.pending) > 0 && authority.ReplayFloor != runtime.confirmedFloor {
		runtime.mu.Unlock()
		return errGatewayRuntime
	}
	afterSequence := runtime.policySequence
	runtime.mu.Unlock()

	envelope, err := runtime.control.Policy(ctx, runtime.credentialID, afterSequence)
	if err != nil {
		return errGatewayRuntime
	}
	if envelope != nil {
		if envelope.Audience != gatewayPolicyAudience || envelope.Sequence <= afterSequence || runtime.cache.Store(*envelope) != nil {
			return errGatewayRuntime
		}
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.authority.CredentialID != "" && !sameGatewayAuthority(runtime.authority, authority) {
		return errGatewayRuntime
	}
	runtime.authority = authority
	runtime.confirmedFloor = authority.ReplayFloor
	runtime.nextFloor = authority.ReplayFloor
	if envelope != nil {
		runtime.policySequence = envelope.Sequence
	}
	return nil
}

func (runtime *gatewayRuntime) Evaluate(ctx context.Context, request gatewayEvaluationRequest) (gatewayEvaluationResult, error) {
	if runtime == nil || ctx == nil || ctx.Err() != nil || !validGatewayEvaluationRequest(request) {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}

	envelope, state, cacheErr := runtime.cache.Current()
	result := gatewayEvaluationResult{Decision: "allow", MatchedPolicyIDs: []string{}}
	switch {
	case cacheErr != nil:
		result.Decision = gatewayFailureDecision(runtime.bootstrapFailureMode)
		result.CacheState = "unavailable_" + runtime.bootstrapFailureMode
	case state == policy.GatewayPolicyExpiredOpen:
		result.Decision = "allow"
		result.PolicyVersion = envelope.PolicyVersion
		result.CacheState = state
	case state == policy.GatewayPolicyExpiredClosed:
		result.Decision = "block"
		result.PolicyVersion = envelope.PolicyVersion
		result.CacheState = state
	case state == policy.GatewayPolicyValid:
		result.PolicyVersion = envelope.PolicyVersion
		result.CacheState = state
		trigger := gatewayTrigger(request.ActionKind)
		for _, compiled := range envelope.Policies {
			if compiled.Trigger != trigger {
				continue
			}
			decision, err := policy.Evaluate(ctx, compiled, request.Attributes)
			if err != nil {
				return gatewayEvaluationResult{}, errGatewayRuntime
			}
			if !decision.Matched {
				continue
			}
			result.MatchedPolicyIDs = append(result.MatchedPolicyIDs, compiled.ID)
			if decision.Action == policy.ActionBlock {
				result.Decision = "block"
			} else if result.Decision == "allow" {
				result.Decision = "monitor"
			}
		}
		sort.Strings(result.MatchedPolicyIDs)
	default:
		return gatewayEvaluationResult{}, errGatewayRuntime
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.authority.CredentialID == "" {
		return result, nil
	}
	if len(runtime.pending) >= runtime.maximumPendingEvents || runtime.nextFloor == ^uint64(0) {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	now := runtime.now()
	if !validGatewayTime(now) {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	policyVersion := result.PolicyVersion
	if policyVersion == 0 {
		policyVersion = 1
	}
	event := gatewayDecisionEvent{
		CredentialID:   runtime.authority.CredentialID,
		DeviceID:       runtime.authority.DeviceID,
		EventID:        request.EventID,
		ExpectedFloor:  runtime.nextFloor,
		NextFloor:      runtime.nextFloor + 1,
		PolicyVersion:  policyVersion,
		Decision:       result.Decision,
		ActionKind:     request.ActionKind,
		Classification: cloneGatewayStrings(request.Classification),
		OccurredAt:     now,
	}
	runtime.nextFloor = event.NextFloor
	runtime.pending = append(runtime.pending, event)
	return result, nil
}

func (runtime *gatewayRuntime) RecordOnce(ctx context.Context) error {
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	if len(runtime.pending) == 0 {
		runtime.mu.Unlock()
		return nil
	}
	event := cloneGatewayDecisionEvent(runtime.pending[0])
	runtime.mu.Unlock()

	if err := runtime.control.Record(ctx, event); err != nil {
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.pending) == 0 || runtime.pending[0].EventID != event.EventID || runtime.pending[0].NextFloor != event.NextFloor {
		return errGatewayRuntime
	}
	runtime.pending = runtime.pending[1:]
	runtime.confirmedFloor = event.NextFloor
	return nil
}

func validGatewayAuthority(authority gatewayAuthority, credentialID string) bool {
	return validGatewayProductID(authority.OrganizationID) && validGatewayProductID(authority.WorkspaceID) &&
		validGatewayProductID(authority.EnvironmentID) && validGatewayProductID(authority.DeviceID) &&
		validGatewayProductID(authority.CredentialID) && authority.CredentialID == credentialID
}

func sameGatewayAuthority(left, right gatewayAuthority) bool {
	return left.OrganizationID == right.OrganizationID && left.WorkspaceID == right.WorkspaceID &&
		left.EnvironmentID == right.EnvironmentID && left.DeviceID == right.DeviceID &&
		left.CredentialID == right.CredentialID
}

func validGatewayEvaluationRequest(request gatewayEvaluationRequest) bool {
	if !validGatewayProductID(request.EventID) || request.ActionKind != "http" && request.ActionKind != "mcp" ||
		len(request.Attributes) < 1 || len(request.Attributes) > 8 || !validGatewayClassification(request.Classification) {
		return false
	}
	allowed := map[string]struct{}{"resource.class": {}, "principal.class": {}}
	if request.ActionKind == "http" {
		allowed["http.method"] = struct{}{}
		allowed["http.route_class"] = struct{}{}
		if request.Attributes["http.method"] == "" || request.Attributes["http.route_class"] == "" {
			return false
		}
	} else {
		allowed["tool.name"] = struct{}{}
		if request.Attributes["tool.name"] == "" {
			return false
		}
	}
	for key, value := range request.Attributes {
		if _, exists := allowed[key]; !exists || !boundedGatewayText(value, 256) {
			return false
		}
	}
	return true
}

func validGatewayClassification(classification map[string]string) bool {
	if len(classification) != 4 {
		return false
	}
	for _, key := range []string{"category", "route_class", "resource_class", "outcome"} {
		if !gatewayClassificationValuePattern.MatchString(classification[key]) {
			return false
		}
	}
	return true
}

func validGatewayProductID(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func validGatewayTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func boundedGatewayText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func gatewayTrigger(actionKind string) string {
	if actionKind == "mcp" {
		return "tool_call"
	}
	return "http_request"
}

func gatewayFailureDecision(mode string) string {
	if mode == "open" {
		return "allow"
	}
	return "block"
}

func cloneGatewayStrings(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneGatewayDecisionEvent(value gatewayDecisionEvent) gatewayDecisionEvent {
	value.Classification = cloneGatewayStrings(value.Classification)
	return value
}
