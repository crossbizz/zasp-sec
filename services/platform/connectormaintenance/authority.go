package connectormaintenance

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var (
	ErrDenied        = errors.New("connector maintenance authorization denied")
	ErrUnavailable   = errors.New("connector maintenance unavailable")
	ErrConfiguration = errors.New("connector maintenance configuration refused")
)

type Phase uint8

const (
	BeforeMetadata Phase = iota + 1
	BeforeSecrets
	BeforeProvider
	BeforeSecretFailure
)

// Reference binds a reservation to the immutable authenticated enqueue intent.
// It is not an API grant and cannot authorize an originless effect.
type Reference struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	Effect       string `json:"effect_id"`
	Integration  string `json:"integration_id"`
	Owner        string `json:"lease_owner"`
	Token        string `json:"lease_token"`
	IntentDigest string `json:"intent_digest"`
}

type Facts struct {
	ContextDigest          string    `json:"context_digest"`
	Profile                string    `json:"profile_checksum"`
	Reference              Reference `json:"reference"`
	Task                   string    `json:"task_id"`
	Purpose                string    `json:"purpose"`
	Grantor                string    `json:"grantor_id"`
	Service                string    `json:"principal_id"`
	SourceProfile          string    `json:"source_profile"`
	SourceProofDigest      string    `json:"source_proof_digest"`
	CommittedRequestDigest string    `json:"committed_request_digest"`
	CommittedEffectDigest  string    `json:"committed_effect_digest"`
	Operation              string    `json:"operation"`
	Attempt                int       `json:"attempt"`
	Expires                time.Time `json:"lease_expires_at"`
	SessionUser            string    `json:"session_user"`
}

// Source supplies registered native facts, never caller-provided task/grant
// fields. The concrete executor must check its catalog, role, key version,
// reservation and live purpose at every call. SQL installation and runtime
// selection remain separate required gates; this package supplies no fallback.
type Source interface {
	Facts(context.Context, Reference) (Facts, error)
	Revision(context.Context, string) (authorization.Revision, error)
}

type Authority struct {
	source                         Source
	checker                        authorization.Checker
	store, model, profile, version string
	key                            []byte
	keyMu                          sync.RWMutex
}

// NewAuthority accepts a source selected by the registered executor. It cannot
// issue a task or activate projection; both identities must already be native.
func NewAuthority(source Source, checker authorization.Checker, store, model, profile string, key []byte) (*Authority, error) {
	if missing(source) || missing(checker) || len(key) != 32 || !digest(profile) || !ulid(store) || !ulid(model) {
		return nil, ErrConfiguration
	}
	h := sha256.Sum256(key)
	return &Authority{source: source, checker: checker, store: store, model: model, profile: profile, version: hex.EncodeToString(h[:]), key: append([]byte(nil), key...)}, nil
}

// Close erases this authority's private signing-key copy. It never closes the
// shared pool/checker; their owners retain their original cleanup obligations.
func (a *Authority) Close() {
	if a == nil {
		return
	}
	a.keyMu.Lock()
	defer a.keyMu.Unlock()
	clear(a.key)
	a.key = nil
}

func (a *Authority) keySnapshot() ([]byte, error) {
	if a == nil {
		return nil, ErrUnavailable
	}
	a.keyMu.RLock()
	defer a.keyMu.RUnlock()
	if len(a.key) != 32 {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), a.key...), nil
}

func (a *Authority) Authorize(ctx context.Context, ref Reference, phase Phase) ([]byte, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !validReference(ref) || phase < BeforeMetadata || phase > BeforeSecretFailure {
		return nil, ErrUnavailable
	}
	key, err := a.keySnapshot()
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(key)
	f, err := a.source.Facts(ctx, ref)
	if err != nil || !validFacts(f, ref, a.profile) || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	r, err := a.source.Revision(ctx, ref.Organization)
	if err != nil || r.OrganizationID != ref.Organization || r.Desired < 1 || r.Desired != r.Applied || r.Generation < 1 || r.StoreID != a.store || r.ModelID != a.model {
		return nil, ErrUnavailable
	}
	// The authenticated source targets exactly this integration. A new native
	// connector task delegates only that original manage_workflows purpose;
	// live grantor authorization is repeated independently of service authority.
	for _, principal := range []struct{ kind, id, task string }{{"user", f.Grantor, ""}, {"service", f.Service, f.Task}} {
		request := authorization.CheckRequest{PrincipalKind: principal.kind, PrincipalID: principal.id, TaskID: principal.task, OrganizationID: ref.Organization, WorkspaceID: ref.Workspace, EnvironmentID: ref.Environment, ResourceType: "integration", ResourceID: ref.Integration, Permission: "manage_workflows"}
		if _, err := authorization.Map(request); err != nil {
			return nil, ErrUnavailable
		}
		decision, err := a.checker.Check(ctx, request)
		if err != nil || decision.ModelID != r.ModelID || ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		if !decision.Allowed {
			return nil, ErrDenied
		}
	}
	after, err := a.source.Revision(ctx, ref.Organization)
	if err != nil || after != r {
		return nil, ErrUnavailable
	}
	fresh, err := a.source.Facts(ctx, ref)
	if err != nil || fresh != f || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	now := time.Now()
	expires := now.Add(60 * time.Second)
	if bound := f.Expires.Add(-100 * time.Millisecond); bound.Before(expires) {
		expires = bound
	}
	if !expires.After(now) {
		return nil, ErrUnavailable
	}
	phaseName := [...]string{"", "before_metadata", "before_secrets", "before_provider", "before_secret_failure"}[phase]
	body, err := json.Marshal(struct {
		Purpose  string                 `json:"purpose"`
		Version  string                 `json:"key_version"`
		Phase    string                 `json:"phase"`
		Facts    Facts                  `json:"facts"`
		Revision authorization.Revision `json:"revision"`
		Issued   int64                  `json:"issued_at"`
		Expires  int64                  `json:"expires_at"`
	}{"connector-forward", a.version, phaseName, f, r, now.UnixMilli(), expires.UnixMilli()})
	if err != nil {
		return nil, ErrUnavailable
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("zasp-connector-forward-v1\x00"))
	_, _ = mac.Write(body)
	proof, err := json.Marshal(struct {
		Body    string `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}{base64.StdEncoding.EncodeToString(body), a.version, hex.EncodeToString(mac.Sum(nil))})
	if err != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	stillOpen, err := a.keySnapshot()
	if err != nil {
		clear(proof)
		return nil, ErrUnavailable
	}
	clear(stillOpen)
	return proof, nil
}

func validFacts(f Facts, r Reference, profile string) bool {
	return f.Reference == r && digest(f.ContextDigest) && f.Purpose == "connector_reconciliation" && f.Profile == profile && f.SourceProfile == migrations.ProductionAuthorizationEnforcement().Checksum() && validID(f.Task) && validID(f.Grantor) && validID(f.Service) && digest(f.SourceProofDigest) && digest(f.CommittedRequestDigest) && digest(f.CommittedEffectDigest) && f.CommittedEffectDigest == r.IntentDigest && f.Attempt >= 0 && f.Attempt < 100 && f.Expires.After(time.Now()) && f.SessionUser != "" && (f.Operation == "authorize" || f.Operation == "revoke" || f.Operation == "pkce_cleanup")
}
func missing(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func validReference(r Reference) bool {
	return validID(r.Organization) && validID(r.Workspace) && validID(r.Environment) && validID(r.Effect) && validID(r.Integration) && len(r.Owner) >= 3 && len(r.Owner) <= 128 && digest(r.Token) && digest(r.IntentDigest)
}
func validID(s string) bool { _, err := domain.ParseProductID(s); return err == nil }
func digest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func ulid(s string) bool {
	if len(s) != 26 || s[0] < '0' || s[0] > '7' {
		return false
	}
	for _, c := range s {
		if !bytes.ContainsRune([]byte("0123456789ABCDEFGHJKMNPQRSTVWXYZ"), c) {
			return false
		}
	}
	return true
}

// decodeObject closes native result grammar before encoding/json's
// case-insensitive struct mapping, and refuses scalar null and trailing bytes.
func decodeObject(raw []byte, out any, fields ...string) error {
	if len(raw) == 0 || len(raw) > 131072 {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return ErrUnavailable
	}
	allowed := make(map[string]bool, len(fields))
	for _, k := range fields {
		allowed[k] = true
	}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		t, err := d.Token()
		k, ok := t.(string)
		if err != nil || !ok || !allowed[k] || seen[k] {
			return ErrUnavailable
		}
		seen[k] = true
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return ErrUnavailable
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') || len(seen) != len(allowed) {
		return ErrUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrUnavailable
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrUnavailable
	}
	return nil
}
