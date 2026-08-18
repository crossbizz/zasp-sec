package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const maximumBundleSnapshotBytes = 1024 * 1024

func WriteBundleArtifact(ctx context.Context, secret []byte, store artifactstore.ArtifactStore, scope domain.Scope, reference domain.EvidenceRef, bundle Bundle) (artifact artifactstore.Artifact, resultErr error) {
	if ctx == nil || ctx.Err() != nil || nilPolicyInterface(store) || scope.Validate() != nil || reference.Validate() != nil || VerifyBundle(secret, bundle) != nil {
		return artifactstore.Artifact{}, ErrRejected
	}
	body, err := json.Marshal(bundle)
	if err != nil || len(body) == 0 || len(body) > maximumBundleSnapshotBytes {
		return artifactstore.Artifact{}, ErrRejected
	}
	locator := artifactstore.Locator{Scope: scope, Reference: reference}
	request := artifactstore.PutRequest{Locator: locator, MediaType: "application/json", Body: bytes.Clone(body)}
	defer func() {
		if recover() != nil {
			artifact = artifactstore.Artifact{}
			resultErr = ErrRejected
		}
	}()
	returned, err := store.Put(ctx, request)
	wantedDigest := sha256.Sum256(body)
	if err != nil || returned.Locator != locator || returned.MediaType != request.MediaType || returned.Size != int64(len(body)) || returned.SHA256 != wantedDigest || !bytes.Equal(returned.Body, body) {
		return artifactstore.Artifact{}, ErrRejected
	}
	return returned, nil
}

type bundleSnapshot struct {
	Version int      `json:"version"`
	Bundles []Bundle `json:"bundles"`
}

func (cache *BundleCache) Snapshot() ([]byte, error) {
	if cache == nil || len(cache.secret) < 16 {
		return nil, ErrRejected
	}
	cache.mu.RLock()
	values := make([]Bundle, 0, len(cache.values))
	for _, bundle := range cache.values {
		values = append(values, cloneBundle(bundle))
	}
	cache.mu.RUnlock()
	sort.Slice(values, func(i, j int) bool { return values[i].EnvironmentID < values[j].EnvironmentID })
	for _, bundle := range values {
		if VerifyBundle(cache.secret, bundle) != nil {
			return nil, ErrRejected
		}
	}
	encoded, err := json.Marshal(bundleSnapshot{Version: 1, Bundles: values})
	if err != nil || len(encoded) == 0 || len(encoded) > maximumBundleSnapshotBytes {
		return nil, ErrRejected
	}
	return encoded, nil
}

func RestoreBundleCache(secret, source []byte) (*BundleCache, error) {
	if len(secret) < 16 || len(source) == 0 || len(source) > maximumBundleSnapshotBytes {
		return nil, ErrRejected
	}
	var snapshot bundleSnapshot
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil || decoder.Decode(&struct{}{}) == nil || snapshot.Version != 1 || len(snapshot.Bundles) > 256 {
		return nil, ErrRejected
	}
	cache := NewBundleCache(secret)
	for _, bundle := range snapshot.Bundles {
		if _, exists := cache.values[bundle.EnvironmentID]; exists || cache.Store(bundle) != nil {
			return nil, ErrRejected
		}
	}
	return cache, nil
}

type bundleHTTPHandler struct {
	cache     *BundleCache
	tokenHash [sha256.Size]byte
}

func NewBundleHTTPHandler(cache *BundleCache, runtimeToken string) (http.Handler, error) {
	if cache == nil || len(cache.secret) < 16 || !bounded(runtimeToken, 512) || len(runtimeToken) < 16 {
		return nil, ErrRejected
	}
	return &bundleHTTPHandler{cache: cache, tokenHash: sha256.Sum256([]byte(runtimeToken))}, nil
}

func (handler *bundleHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler == nil || request == nil || request.Method != http.MethodGet || request.URL.Path != "/internal/v1/policy-bundle" || request.URL.RawQuery == "" {
		http.Error(response, "request rejected", http.StatusBadRequest)
		return
	}
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || subtle.ConstantTimeCompare(handler.tokenHash[:], sha256Digest(strings.TrimPrefix(authorization, "Bearer "))) != 1 {
		http.Error(response, "forbidden", http.StatusForbidden)
		return
	}
	query := request.URL.Query()
	environments, ok := query["environment_id"]
	if !ok || len(query) != 1 || len(environments) != 1 {
		http.Error(response, "request rejected", http.StatusBadRequest)
		return
	}
	environmentID := environments[0]
	bundle, err := GetPolicyBundle(handler.cache, environmentID, request.Header.Get("X-Zasp-Runtime-Environment"))
	if err != nil {
		http.Error(response, "request rejected", http.StatusBadRequest)
		return
	}
	body, err := json.Marshal(bundle)
	if err != nil || len(body) > maximumBundleSnapshotBytes {
		http.Error(response, "request rejected", http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
}

type OpenSearchPolicyHistory interface {
	SearchPolicyActions(context.Context, string, int) ([]ActionContext, error)
}

func (store *MemoryStore) SimulateOpenSearch(ctx context.Context, policyID, environmentID string, history OpenSearchPolicyHistory) (result SimulationResult, resultErr error) {
	if store == nil || ctx == nil || ctx.Err() != nil || !bounded(environmentID, 128) || nilPolicyInterface(history) {
		return SimulationResult{}, ErrRejected
	}
	defer func() {
		if recover() != nil {
			result = SimulationResult{}
			resultErr = ErrRejected
		}
	}()
	events, err := history.SearchPolicyActions(ctx, environmentID, 100)
	if err != nil || len(events) == 0 || len(events) > 100 || ctx.Err() != nil {
		return SimulationResult{}, ErrRejected
	}
	for _, event := range events {
		normalized, err := NormalizeActionContext(event)
		if err != nil || normalized.EnvironmentID != environmentID {
			return SimulationResult{}, ErrRejected
		}
	}
	return store.Simulate(ctx, policyID, events)
}

func sha256Digest(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

func nilPolicyInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
