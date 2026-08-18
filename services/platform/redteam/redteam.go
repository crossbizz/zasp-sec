package redteam

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrRejected = errors.New("red team operation rejected")

type Verdict string

const (
	VerdictPass        Verdict = "pass"
	VerdictFail        Verdict = "fail"
	VerdictEngineError Verdict = "engine_error"
)

type SafetyMetadata struct {
	Environment         string   `json:"environment"`
	CredentialClass     string   `json:"credential_class"`
	ExpectedSideEffects []string `json:"expected_side_effects"`
}

type TestDefinition struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	TargetID   string         `json:"target_id"`
	Categories []string       `json:"categories"`
	Safety     SafetyMetadata `json:"safety"`
}

type TestRun struct {
	ID           string `json:"id"`
	DefinitionID string `json:"definition_id"`
	Status       string `json:"status"`
}

type TestAttempt struct {
	Objective, InputArtifactRef, Behavior string
	Verdict                               Verdict
	EngineError                           string
	Evidence                              []string
	At                                    time.Time
}

type PromptfooOutput struct {
	Objective, InputArtifactRef, Behavior string
	Passed                                bool
	EngineError                           string
	Evidence                              []string
	At                                    time.Time
}

func NormalizePromptfoo(value PromptfooOutput) (TestAttempt, error) {
	if !bounded(value.Objective, 512) || !bounded(value.InputArtifactRef, 512) || !bounded(value.Behavior, 2048) || !canonicalTime(value.At) || len(value.Evidence) > 64 {
		return TestAttempt{}, ErrRejected
	}
	verdict := VerdictFail
	if value.EngineError != "" {
		if !bounded(value.EngineError, 512) || value.Passed {
			return TestAttempt{}, ErrRejected
		}
		verdict = VerdictEngineError
	} else if value.Passed {
		verdict = VerdictPass
	}
	if !validStrings(value.Evidence, 512) {
		return TestAttempt{}, ErrRejected
	}
	behavior := value.Behavior
	if strings.Contains(strings.ToLower(behavior), "secret=") {
		behavior = "[REDACTED]"
	}
	return TestAttempt{Objective: value.Objective, InputArtifactRef: value.InputArtifactRef, Behavior: behavior, Verdict: verdict, EngineError: value.EngineError, Evidence: cloneStrings(value.Evidence), At: value.At}, nil
}

type CapabilityProfile struct {
	CanCallTools, ReadsSensitiveData, AcceptsUntrustedInput bool
}

type PackRecommendation struct{ Category, Explanation string }

func SelectCuratedPacks(value CapabilityProfile) []PackRecommendation {
	result := []PackRecommendation{}
	if value.CanCallTools {
		result = append(result, PackRecommendation{Category: "tool_abuse", Explanation: "Agent can invoke tools."})
	}
	if value.ReadsSensitiveData {
		result = append(result, PackRecommendation{Category: "data_leakage", Explanation: "Agent can read sensitive data."})
	}
	if value.AcceptsUntrustedInput {
		result = append(result, PackRecommendation{Category: "prompt_injection", Explanation: "Agent accepts untrusted input."})
	}
	return result
}

type SafetyInput struct {
	Environment, CredentialClass string
	ExpectedSideEffects          []string
}

type SafetyDecision struct {
	Approved bool
	Checks   []string
}

func TestSafetyPreflight(value SafetyInput) (SafetyDecision, error) {
	if value.Environment == "production" || value.CredentialClass == "production_write" || value.Environment == "" || value.CredentialClass == "" || len(value.ExpectedSideEffects) == 0 || !validStrings(value.ExpectedSideEffects, 256) {
		return SafetyDecision{}, ErrRejected
	}
	return SafetyDecision{Approved: true, Checks: []string{"non-production target", "non-production-write credential", "declared side effects"}}, nil
}

type MemoryStore struct {
	mu          sync.Mutex
	definitions map[string]TestDefinition
	runs        map[string]TestRun
	attempts    map[string]TestAttempt
	processing  map[string]bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{definitions: map[string]TestDefinition{}, runs: map[string]TestRun{}, attempts: map[string]TestAttempt{}, processing: map[string]bool{}}
}

func (store *MemoryStore) CreateDefinition(ctx context.Context, value TestDefinition) error {
	if store == nil || !active(ctx) || !validDefinition(value) {
		return ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.definitions[value.ID]; exists {
		return ErrRejected
	}
	value.Categories = cloneStrings(value.Categories)
	value.Safety.ExpectedSideEffects = cloneStrings(value.Safety.ExpectedSideEffects)
	store.definitions[value.ID] = value
	return nil
}

func (store *MemoryStore) ListDefinitions(ctx context.Context) ([]TestDefinition, error) {
	if store == nil || !active(ctx) {
		return nil, ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]TestDefinition, 0, len(store.definitions))
	for _, value := range store.definitions {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (store *MemoryStore) GetDefinition(ctx context.Context, id string) (TestDefinition, error) {
	if store == nil || !active(ctx) || !bounded(id, 128) {
		return TestDefinition{}, ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.definitions[id]
	if !ok {
		return TestDefinition{}, ErrRejected
	}
	return value, nil
}

func (store *MemoryStore) UpdateDefinition(ctx context.Context, value TestDefinition) error {
	if store == nil || !active(ctx) || !validDefinition(value) {
		return ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.definitions[value.ID]; !ok {
		return ErrRejected
	}
	store.definitions[value.ID] = value
	return nil
}

func (store *MemoryStore) CreateRun(ctx context.Context, id, definitionID string) (TestRun, error) {
	if store == nil || !active(ctx) || !bounded(id, 128) || !bounded(definitionID, 128) {
		return TestRun{}, ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.definitions[definitionID]; !ok {
		return TestRun{}, ErrRejected
	}
	if _, exists := store.runs[id]; exists {
		return TestRun{}, ErrRejected
	}
	run := TestRun{ID: id, DefinitionID: definitionID, Status: "queued"}
	store.runs[id] = run
	return run, nil
}

func (store *MemoryStore) ListRuns(ctx context.Context) ([]TestRun, error) {
	if store == nil || !active(ctx) {
		return nil, ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]TestRun, 0, len(store.runs))
	for _, value := range store.runs {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (store *MemoryStore) GetRun(ctx context.Context, id string) (TestRun, error) {
	if store == nil || !active(ctx) || !bounded(id, 128) {
		return TestRun{}, ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.runs[id]
	if !ok {
		return TestRun{}, ErrRejected
	}
	return value, nil
}

func (store *MemoryStore) CancelRun(ctx context.Context, id string) (TestRun, error) {
	if store == nil || !active(ctx) || !bounded(id, 128) {
		return TestRun{}, ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.runs[id]
	if !ok || value.Status == "complete" {
		return TestRun{}, ErrRejected
	}
	value.Status = "cancelled"
	store.runs[id] = value
	return value, nil
}

func (store *MemoryStore) AttemptCount(runID string) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.attempts[runID]; ok {
		return 1
	}
	return 0
}

type ArtifactSummary struct{ RunID, ArtifactRef, Verdict string }

type ArtifactStore interface {
	Put(context.Context, string, PromptfooOutput, TestAttempt) error
}

type MemoryArtifactStore struct {
	mu     sync.Mutex
	values map[string]ArtifactSummary
}

func NewMemoryArtifactStore() *MemoryArtifactStore {
	return &MemoryArtifactStore{values: map[string]ArtifactSummary{}}
}

func (store *MemoryArtifactStore) Put(ctx context.Context, runID string, _ PromptfooOutput, normalized TestAttempt) error {
	if store == nil || !active(ctx) || !bounded(runID, 128) {
		return ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[runID] = ArtifactSummary{RunID: runID, ArtifactRef: normalized.InputArtifactRef, Verdict: string(normalized.Verdict)}
	return nil
}

type Worker struct {
	store     *MemoryStore
	artifacts ArtifactStore
}

func NewWorker(store *MemoryStore, artifacts ArtifactStore) *Worker {
	return &Worker{store: store, artifacts: artifacts}
}

func (worker *Worker) Consume(ctx context.Context, runID string, output PromptfooOutput) error {
	if worker == nil || worker.store == nil || worker.artifacts == nil || !active(ctx) {
		return ErrRejected
	}
	worker.store.mu.Lock()
	if _, done := worker.store.attempts[runID]; done {
		worker.store.mu.Unlock()
		return nil
	}
	if worker.store.processing[runID] {
		worker.store.mu.Unlock()
		return nil
	}
	run, ok := worker.store.runs[runID]
	if ok && run.Status == "queued" {
		worker.store.processing[runID] = true
	}
	worker.store.mu.Unlock()
	if !ok || run.Status != "queued" {
		return ErrRejected
	}
	attempt, err := NormalizePromptfoo(output)
	if err != nil || worker.artifacts.Put(ctx, runID, output, attempt) != nil {
		worker.store.mu.Lock()
		delete(worker.store.processing, runID)
		worker.store.mu.Unlock()
		return ErrRejected
	}
	worker.store.mu.Lock()
	defer worker.store.mu.Unlock()
	if _, done := worker.store.attempts[runID]; done {
		return nil
	}
	worker.store.attempts[runID] = attempt
	delete(worker.store.processing, runID)
	run.Status = "complete"
	worker.store.runs[runID] = run
	return nil
}

type SandboxProvider interface {
	Create(context.Context, FargateSpec) error
	Run(context.Context, string) error
	Cancel(context.Context, string) error
	Destroy(context.Context, string) error
	Capabilities(context.Context) ([]string, error)
}

type SandboxLimits struct {
	CPU, Memory, EphemeralStorage string
	TimeoutSeconds                int
}

type FargateSpec struct {
	RunID, Profile, Namespace, ServiceAccount, SecurityGroupPolicy string
	Labels, Annotations                                            map[string]string
	Limits                                                         SandboxLimits
	Isolation                                                      string
	AllowsDirectEgress                                             bool
}

func BuildFargateSpec(runID string, limits SandboxLimits) (FargateSpec, error) {
	if !bounded(runID, 128) || limits.CPU == "" || limits.Memory == "" || limits.EphemeralStorage == "" || limits.TimeoutSeconds < 1 || limits.TimeoutSeconds > 1800 {
		return FargateSpec{}, ErrRejected
	}
	return FargateSpec{RunID: runID, Profile: "fargate-attack-lab", Namespace: "attack-lab", ServiceAccount: "attack-lab-runner", SecurityGroupPolicy: "attack-lab-egress-proxy", Labels: map[string]string{"zasp.run": runID, "compute": "fargate"}, Annotations: map[string]string{"eks.amazonaws.com/role-arn": "attack-lab-test-role"}, Limits: limits, Isolation: "fargate_pod", AllowsDirectEgress: false}, nil
}

type tokenClaims struct {
	RunID          string `json:"run_id"`
	Hosts, Methods []string
	Expires        int64 `json:"expires"`
}

func SignEgressToken(secret []byte, runID string, hosts, methods []string, expires time.Time) (string, error) {
	if len(secret) < 16 || !bounded(runID, 128) || !validStrings(hosts, 256) || !validStrings(methods, 16) || len(hosts) == 0 || len(methods) == 0 || !canonicalTime(expires) {
		return "", ErrRejected
	}
	claims, _ := json.Marshal(tokenClaims{RunID: runID, Hosts: cloneStrings(hosts), Methods: cloneStrings(methods), Expires: expires.Unix()})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyEgressToken(secret []byte, token, host, method string, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || !canonicalTime(now) {
		return ErrRejected
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		return ErrRejected
	}
	bytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	var claims tokenClaims
	if err != nil || json.Unmarshal(bytes, &claims) != nil || now.Unix() >= claims.Expires || !contains(claims.Hosts, host) || !contains(claims.Methods, method) {
		return ErrRejected
	}
	return nil
}

type AttackLabInput struct {
	Environment, CredentialClass, Destination, SuccessCriterion string
	AllowedDestinations                                         []string
}

func AttackLabPreflight(value AttackLabInput) (SafetyDecision, error) {
	if value.Environment == "production" || value.CredentialClass == "production_write" || value.Environment == "" || value.CredentialClass == "" || !bounded(value.Destination, 256) || !validStrings(value.AllowedDestinations, 256) || !contains(value.AllowedDestinations, value.Destination) || !bounded(value.SuccessCriterion, 512) {
		return SafetyDecision{}, ErrRejected
	}
	return SafetyDecision{Approved: true, Checks: []string{"target", "credential", "destination", "success criterion"}}, nil
}

type Canary struct{ RunID, Resource, CredentialClass, ExpectedTouch string }

func BuildCanary(runID, resource, credentialClass, expectedTouch string) (Canary, error) {
	if !bounded(runID, 128) || !bounded(resource, 256) || credentialClass != "test_write" || !bounded(expectedTouch, 512) {
		return Canary{}, ErrRejected
	}
	return Canary{RunID: runID, Resource: resource, CredentialClass: credentialClass, ExpectedTouch: expectedTouch}, nil
}

type EvidenceInput struct{ Semantic, Gateway, Egress, Kubernetes, CloudSideEffect string }
type AttackLabEvidence struct {
	Sources  []string
	UsesEBPF bool
}

func CollectAttackLabEvidence(value EvidenceInput) (AttackLabEvidence, error) {
	values := []string{value.Semantic, value.Gateway, value.Egress, value.Kubernetes, value.CloudSideEffect}
	if !validStrings(values, 1024) {
		return AttackLabEvidence{}, ErrRejected
	}
	return AttackLabEvidence{Sources: []string{"semantic:" + value.Semantic, "gateway:" + value.Gateway, "egress:" + value.Egress, "kubernetes:" + value.Kubernetes, "cloud:" + value.CloudSideEffect}, UsesEBPF: false}, nil
}

func validDefinition(value TestDefinition) bool {
	if !bounded(value.ID, 128) || !bounded(value.Name, 256) || !bounded(value.TargetID, 128) || len(value.Categories) == 0 || !validStrings(value.Categories, 64) {
		return false
	}
	_, err := TestSafetyPreflight(SafetyInput(value.Safety))
	return err == nil
}

func active(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }
func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000_000 == 0
}
func bounded(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func validStrings(values []string, limit int) bool {
	for _, value := range values {
		if !bounded(value, limit) {
			return false
		}
	}
	return true
}
func cloneStrings(values []string) []string { return append([]string(nil), values...) }
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
