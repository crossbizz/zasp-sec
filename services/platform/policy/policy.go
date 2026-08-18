package policy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
)

var ErrRejected = errors.New("policy operation rejected")

type Action string

const (
	ActionMonitor Action = "monitor"
	ActionBlock   Action = "block"
)

type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}
type Policy struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Scope       string      `json:"scope"`
	Trigger     string      `json:"trigger"`
	Conditions  []Condition `json:"conditions"`
	Action      Action      `json:"action"`
	Rollout     string      `json:"rollout"`
	FailureMode string      `json:"failure_mode"`
}
type Capabilities struct {
	Triggers, Fields []string
	Actions          []Action
}

func Validate(value Policy, capabilities Capabilities) error {
	if !bounded(value.ID, 128) || !bounded(value.Name, 256) || value.Scope != "environment" || !contains(capabilities.Triggers, value.Trigger) || !contains(capabilities.Actions, value.Action) || (value.Action != ActionMonitor && value.Action != ActionBlock) || !contains([]string{"draft", "monitor", "enforced", "disabled"}, value.Rollout) || (value.FailureMode != "open" && value.FailureMode != "closed") || len(value.Conditions) == 0 || len(value.Conditions) > 32 {
		return ErrRejected
	}
	for _, condition := range value.Conditions {
		if !contains(capabilities.Fields, condition.Field) || condition.Operator != "equals" || !bounded(condition.Value, 256) {
			return ErrRejected
		}
	}
	return nil
}

type CompiledPolicy struct {
	ID, Rego, Digest string
	Action           Action
	Conditions       []Condition
}

func Compile(value Policy) (CompiledPolicy, error) {
	if !bounded(value.ID, 128) || !bounded(value.Trigger, 64) || len(value.Conditions) == 0 || (value.Action != ActionMonitor && value.Action != ActionBlock) {
		return CompiledPolicy{}, ErrRejected
	}
	conditions := append([]Condition(nil), value.Conditions...)
	sort.Slice(conditions, func(i, j int) bool {
		if conditions[i].Field != conditions[j].Field {
			return conditions[i].Field < conditions[j].Field
		}
		return conditions[i].Value < conditions[j].Value
	})
	bytes, err := json.Marshal(struct {
		ID, Trigger string
		Conditions  []Condition
		Action      Action
	}{value.ID, value.Trigger, conditions, value.Action})
	if err != nil {
		return CompiledPolicy{}, ErrRejected
	}
	digest := sha256.Sum256(bytes)
	rego := "package zasp.runtime\n# deterministic product policy\npolicy := " + string(bytes) + "\n"
	return CompiledPolicy{ID: value.ID, Rego: rego, Digest: hex.EncodeToString(digest[:]), Action: value.Action, Conditions: conditions}, nil
}

type Decision struct {
	Action  Action
	Matched bool
}

func Evaluate(ctx context.Context, compiled CompiledPolicy, input map[string]string) (Decision, error) {
	if ctx == nil || ctx.Err() != nil || !bounded(compiled.ID, 128) || len(compiled.Conditions) == 0 {
		return Decision{}, ErrRejected
	}
	for _, condition := range compiled.Conditions {
		if input[condition.Field] != condition.Value {
			return Decision{Action: ActionMonitor, Matched: false}, nil
		}
	}
	return Decision{Action: compiled.Action, Matched: true}, nil
}

type Bundle struct {
	EnvironmentID, Manifest, Signature string
	Policies                           []CompiledPolicy
}

func SignBundle(secret []byte, environmentID string, policies []CompiledPolicy) (Bundle, error) {
	if len(secret) < 16 || !bounded(environmentID, 128) || len(policies) == 0 {
		return Bundle{}, ErrRejected
	}
	digests := make([]string, len(policies))
	for i, p := range policies {
		if verifyCompiled(p) != nil {
			return Bundle{}, ErrRejected
		}
		digests[i] = p.ID + ":" + p.Digest
	}
	sort.Strings(digests)
	manifestBytes, _ := json.Marshal(struct {
		EnvironmentID string   `json:"environment_id"`
		Digests       []string `json:"digests"`
	}{environmentID, digests})
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(manifestBytes)
	return Bundle{EnvironmentID: environmentID, Manifest: string(manifestBytes), Signature: hex.EncodeToString(mac.Sum(nil)), Policies: append([]CompiledPolicy(nil), policies...)}, nil
}
func VerifyBundle(secret []byte, bundle Bundle) error {
	if len(secret) < 16 {
		return ErrRejected
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(bundle.Manifest))
	sig, err := hex.DecodeString(bundle.Signature)
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return ErrRejected
	}
	var value struct {
		EnvironmentID string   `json:"environment_id"`
		Digests       []string `json:"digests"`
	}
	if json.Unmarshal([]byte(bundle.Manifest), &value) != nil || value.EnvironmentID != bundle.EnvironmentID {
		return ErrRejected
	}
	digests := make([]string, len(bundle.Policies))
	for i, policy := range bundle.Policies {
		if verifyCompiled(policy) != nil {
			return ErrRejected
		}
		digests[i] = policy.ID + ":" + policy.Digest
	}
	sort.Strings(digests)
	if !equal(value.Digests, digests) {
		return ErrRejected
	}
	return nil
}

type BundleCache struct {
	mu     sync.RWMutex
	secret []byte
	values map[string]Bundle
}

func NewBundleCache(secret []byte) *BundleCache {
	return &BundleCache{secret: append([]byte(nil), secret...), values: map[string]Bundle{}}
}
func (cache *BundleCache) Store(bundle Bundle) error {
	if cache == nil || !bounded(bundle.EnvironmentID, 128) || bundle.Manifest == "" || bundle.Signature == "" || VerifyBundle(cache.secret, bundle) != nil {
		return ErrRejected
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.values[bundle.EnvironmentID] = cloneBundle(bundle)
	return nil
}
func (cache *BundleCache) Load(environmentID string) Bundle {
	if cache == nil {
		return Bundle{}
	}
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return cloneBundle(cache.values[environmentID])
}
func GetPolicyBundle(cache *BundleCache, environmentID, runtimeEnvironmentID string) (Bundle, error) {
	if environmentID != runtimeEnvironmentID || !bounded(environmentID, 128) {
		return Bundle{}, ErrRejected
	}
	bundle := cache.Load(environmentID)
	if bundle.EnvironmentID == "" {
		return Bundle{}, ErrRejected
	}
	return bundle, nil
}

type MemoryStore struct {
	mu       sync.RWMutex
	values   map[string]Policy
	rollouts []RolloutRecord
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{values: map[string]Policy{}} }
func (store *MemoryStore) Create(ctx context.Context, value Policy, capabilities Capabilities) error {
	if store == nil || ctx == nil || ctx.Err() != nil || Validate(value, capabilities) != nil {
		return ErrRejected
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.values[value.ID]; ok {
		return ErrRejected
	}
	store.values[value.ID] = value
	return nil
}
func (store *MemoryStore) List(ctx context.Context) ([]Policy, error) {
	if store == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrRejected
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]Policy, 0, len(store.values))
	for _, value := range store.values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func (store *MemoryStore) Get(ctx context.Context, id string) (Policy, error) {
	if store == nil || ctx == nil || ctx.Err() != nil || !bounded(id, 128) {
		return Policy{}, ErrRejected
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, ok := store.values[id]
	if !ok {
		return Policy{}, ErrRejected
	}
	return value, nil
}

func bounded(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func contains[T comparable](values []T, wanted T) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func equal[T comparable](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func verifyCompiled(value CompiledPolicy) error {
	const prefix = "package zasp.runtime\n# deterministic product policy\npolicy := "
	if !bounded(value.ID, 128) || len(value.Digest) != 64 || !strings.HasPrefix(value.Rego, prefix) || !strings.HasSuffix(value.Rego, "\n") {
		return ErrRejected
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(value.Rego, prefix), "\n")
	digest := sha256.Sum256([]byte(payload))
	if hex.EncodeToString(digest[:]) != value.Digest {
		return ErrRejected
	}
	var decoded struct {
		ID, Trigger string
		Conditions  []Condition
		Action      Action
	}
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(&struct{}{}) == nil || decoded.ID != value.ID || decoded.Action != value.Action || !equal(decoded.Conditions, value.Conditions) {
		return ErrRejected
	}
	return nil
}

func cloneBundle(value Bundle) Bundle {
	result := value
	result.Policies = append([]CompiledPolicy(nil), value.Policies...)
	for i := range result.Policies {
		result.Policies[i].Conditions = append([]Condition(nil), result.Policies[i].Conditions...)
	}
	return result
}
