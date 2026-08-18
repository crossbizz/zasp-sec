package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type RolloutState string

const (
	RolloutDraft    RolloutState = "draft"
	RolloutMonitor  RolloutState = "monitor"
	RolloutEnforced RolloutState = "enforced"
	RolloutDisabled RolloutState = "disabled"
)

type RolloutRecord struct {
	PolicyID string       `json:"policy_id"`
	State    RolloutState `json:"state"`
	TargetID string       `json:"target_id"`
}

type ActionContext struct {
	PrincipalID   string            `json:"principal_id"`
	AgentID       string            `json:"agent_id"`
	SessionID     string            `json:"session_id"`
	Action        string            `json:"action"`
	Resource      string            `json:"resource"`
	EnvironmentID string            `json:"environment_id"`
	Metadata      map[string]string `json:"metadata"`
}

func NormalizeActionContext(value ActionContext) (ActionContext, error) {
	if !bounded(value.PrincipalID, 128) || !bounded(value.AgentID, 128) || !bounded(value.SessionID, 128) || !bounded(value.Action, 64) || !bounded(value.Resource, 256) || !bounded(value.EnvironmentID, 128) || len(value.Metadata) > 32 {
		return ActionContext{}, ErrRejected
	}
	for key, item := range value.Metadata {
		if !bounded(key, 128) || !bounded(item, 256) {
			return ActionContext{}, ErrRejected
		}
	}
	return value, nil
}

type SimulationResult struct {
	Matches    int      `json:"matches"`
	WouldBlock int      `json:"would_block"`
	Examples   []string `json:"example_session_ids"`
}

func (store *MemoryStore) Update(ctx context.Context, value Policy, capabilities Capabilities) error {
	if store == nil || ctx == nil || ctx.Err() != nil || Validate(value, capabilities) != nil {
		return ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.values[value.ID]; !ok {
		return ErrRejected
	}
	store.values[value.ID] = value
	return nil
}

func (store *MemoryStore) Delete(ctx context.Context, id string) error {
	if store == nil || ctx == nil || ctx.Err() != nil || !bounded(id, 128) {
		return ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.values[id]; !ok {
		return ErrRejected
	}
	delete(store.values, id)
	return nil
}

func (store *MemoryStore) Simulate(ctx context.Context, id string, events []ActionContext) (SimulationResult, error) {
	if len(events) == 0 || len(events) > 100 {
		return SimulationResult{}, ErrRejected
	}
	value, err := store.Get(ctx, id)
	if err != nil {
		return SimulationResult{}, ErrRejected
	}
	compiled, err := Compile(value)
	if err != nil {
		return SimulationResult{}, ErrRejected
	}
	result := SimulationResult{Examples: []string{}}
	for _, event := range events {
		normalized, err := NormalizeActionContext(event)
		if err != nil {
			return SimulationResult{}, ErrRejected
		}
		if normalized.Action != value.Trigger {
			continue
		}
		decision, err := Evaluate(ctx, compiled, normalized.Metadata)
		if err != nil {
			return SimulationResult{}, ErrRejected
		}
		if decision.Matched {
			result.Matches++
			if result.Examples == nil || len(result.Examples) < 5 {
				result.Examples = append(result.Examples, normalized.SessionID)
			}
			if value.Action == ActionBlock {
				result.WouldBlock++
			}
		}
	}
	return result, nil
}

func (store *MemoryStore) Rollout(ctx context.Context, id string, next RolloutState, targetID string) (RolloutRecord, error) {
	if !bounded(targetID, 128) {
		return RolloutRecord{}, ErrRejected
	}
	value, err := store.Get(ctx, id)
	if err != nil {
		return RolloutRecord{}, ErrRejected
	}
	current := RolloutState(value.Rollout)
	valid := next == current || current == RolloutDraft && next == RolloutMonitor || current == RolloutMonitor && (next == RolloutEnforced || next == RolloutDisabled) || current == RolloutEnforced && next == RolloutDisabled
	if !valid {
		return RolloutRecord{}, ErrRejected
	}
	store.mu.Lock()
	value.Rollout = string(next)
	store.values[id] = value
	store.rollouts = append(store.rollouts, RolloutRecord{PolicyID: id, State: next, TargetID: targetID})
	store.mu.Unlock()
	return RolloutRecord{PolicyID: id, State: next, TargetID: targetID}, nil
}

func (store *MemoryStore) RolloutAudit() []RolloutRecord {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return append([]RolloutRecord(nil), store.rollouts...)
}

func (store *MemoryStore) Disable(ctx context.Context, id string) (RolloutRecord, error) {
	return store.Rollout(ctx, id, RolloutDisabled, "all")
}

type HTTPAction struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

type HTTPResult struct {
	Status        int
	Headers       map[string]string
	Body          []byte
	CorrelationID string
}

type RuntimeProxy struct {
	PolicyID string
	Evaluate func(context.Context, ActionContext) (Decision, error)
	Upstream func(context.Context, HTTPAction) (HTTPResult, error)
	Monitor  func(context.Context, RuntimeDecision) error
}

func (proxy RuntimeProxy) Handle(ctx context.Context, action HTTPAction, actionContext ActionContext) (HTTPResult, error) {
	if proxy.Evaluate == nil || proxy.Upstream == nil || ctx == nil || ctx.Err() != nil || len(action.Body) > 64*1024 || !bounded(action.Method, 16) || !bounded(action.URL, 2048) {
		return HTTPResult{}, ErrRejected
	}
	normalized, err := NormalizeActionContext(actionContext)
	if err != nil {
		return HTTPResult{}, ErrRejected
	}
	decision, err := proxy.Evaluate(ctx, normalized)
	if err != nil {
		return HTTPResult{}, ErrRejected
	}
	correlation := correlationID(normalized)
	if decision.Matched && decision.Action == ActionBlock {
		return HTTPResult{Status: http.StatusForbidden, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{"code":"policy_blocked","message":"Runtime action blocked"}`), CorrelationID: correlation}, nil
	}
	if decision.Matched && decision.Action == ActionMonitor && proxy.Monitor != nil {
		if !bounded(proxy.PolicyID, 128) || proxy.Monitor(ctx, RuntimeDecision{ID: "decision-" + correlation, PolicyID: proxy.PolicyID, EnvironmentID: normalized.EnvironmentID, Result: "monitor", CorrelationID: correlation, At: time.Now().UTC()}) != nil {
			return HTTPResult{}, ErrRejected
		}
	}
	return proxy.Upstream(ctx, action)
}

func ParseMCPAction(source []byte, principalID, agentID, sessionID, environmentID string) (ActionContext, error) {
	if len(source) == 0 || len(source) > 16*1024 {
		return ActionContext{}, ErrRejected
	}
	var value struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			Name      string `json:"name"`
			Arguments struct {
				Resource string `json:"resource"`
			} `json:"arguments"`
		} `json:"params"`
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.JSONRPC != "2.0" || !bounded(value.ID, 128) || value.Method != "tools/call" || !bounded(value.Params.Name, 128) || !bounded(value.Params.Arguments.Resource, 256) || decoder.Decode(&struct{}{}) == nil {
		return ActionContext{}, ErrRejected
	}
	return NormalizeActionContext(ActionContext{PrincipalID: principalID, AgentID: agentID, SessionID: sessionID, Action: value.Method, Resource: value.Params.Arguments.Resource, EnvironmentID: environmentID, Metadata: map[string]string{"tool.name": value.Params.Name}})
}

type RuntimeDecision struct {
	ID            string    `json:"id"`
	PolicyID      string    `json:"policy_id"`
	EnvironmentID string    `json:"environment_id"`
	Result        string    `json:"result"`
	CorrelationID string    `json:"correlation_id"`
	At            time.Time `json:"at"`
}

type DecisionStore struct {
	mu     sync.RWMutex
	values map[string]RuntimeDecision
}

func NewDecisionStore() *DecisionStore { return &DecisionStore{values: map[string]RuntimeDecision{}} }
func (store *DecisionStore) Record(ctx context.Context, value RuntimeDecision) error {
	if store == nil || ctx == nil || ctx.Err() != nil || !bounded(value.ID, 128) || !bounded(value.PolicyID, 128) || !bounded(value.EnvironmentID, 128) || !contains([]string{"monitor", "block", "allow"}, value.Result) || !bounded(value.CorrelationID, 128) || value.At.IsZero() {
		return ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.values[value.ID]; ok {
		if retained == value {
			return nil
		}
		return ErrRejected
	}
	store.values[value.ID] = value
	return nil
}
func (store *DecisionStore) List(policyID string) []RuntimeDecision {
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := []RuntimeDecision{}
	for _, value := range store.values {
		if value.PolicyID == policyID {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
func (store *DecisionStore) Count() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.values)
}

func EvaluateBundleFallback(ctx context.Context, secret []byte, bundle Bundle, expiresAt time.Time, failureMode string, now time.Time, input map[string]string) (Decision, error) {
	if VerifyBundle(secret, bundle) != nil {
		return Decision{}, ErrRejected
	}
	if now.After(expiresAt) {
		if failureMode == "open" {
			return Decision{Action: ActionMonitor}, nil
		}
		if failureMode == "closed" {
			return Decision{Action: ActionBlock, Matched: true}, nil
		}
		return Decision{}, ErrRejected
	}
	for _, compiled := range bundle.Policies {
		decision, err := Evaluate(ctx, compiled, input)
		if err != nil {
			return Decision{}, ErrRejected
		}
		if decision.Matched {
			return decision, nil
		}
	}
	return Decision{Action: ActionMonitor}, nil
}

func MeasureDecisionP95(ctx context.Context, compiled CompiledPolicy, input map[string]string, attempts int) (time.Duration, error) {
	if attempts < 1 || attempts > 10_000 {
		return 0, ErrRejected
	}
	values := make([]time.Duration, attempts)
	for i := range attempts {
		start := time.Now()
		if _, err := Evaluate(ctx, compiled, input); err != nil {
			return 0, ErrRejected
		}
		values[i] = time.Since(start)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[(len(values)*95-1)/100], nil
}

func ApplyDecisionEvidence(current string, decision RuntimeDecision) string {
	if current == "verified" && decision.Result == "block" && bounded(decision.PolicyID, 128) && bounded(decision.EnvironmentID, 128) && bounded(decision.CorrelationID, 128) {
		return "blocked"
	}
	return current
}

type M6GateFixture struct{ Created, Simulated, Monitored, Enforced, Retested, OutageEnforced bool }
type M6GateReport struct {
	Status string
	Checks int
}

func EvaluateM6Gate(value M6GateFixture) (M6GateReport, error) {
	if !value.Created || !value.Simulated || !value.Monitored || !value.Enforced || !value.Retested || !value.OutageEnforced {
		return M6GateReport{}, ErrRejected
	}
	return M6GateReport{Status: "PASS", Checks: 6}, nil
}

func correlationID(value ActionContext) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{value.PrincipalID, value.AgentID, value.SessionID, value.Action, value.Resource, value.EnvironmentID}, "\x00")))
	return "correlation-" + hex.EncodeToString(digest[:8])
}
