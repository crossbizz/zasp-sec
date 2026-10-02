package multisteppricing

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var ErrUnavailable = errors.New("private planner pricing unavailable")
var ErrRejected = errors.New("private planner pricing rejected")

type Database interface {
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
}
type Repository struct {
	database Database
	kind     string
}

func New(db Database, kind string) (*Repository, error) {
	if db == nil || reflect.ValueOf(db).Kind() == reflect.Ptr && reflect.ValueOf(db).IsNil() || (kind != "admin" && kind != "worker") {
		return nil, ErrRejected
	}
	r := &Repository{database: db, kind: kind}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.ready(ctx); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Repository) ready(ctx context.Context) error {
	if r == nil || r.database == nil || ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	raw, err := r.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.pricing_ready($1,$2,$3)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), r.kind)
	var v struct {
		Release   bool `json:"release"`
		Principal bool `json:"principal"`
	}
	if err != nil || !decode(raw, AdminBytes, []string{"release", "principal"}, &v) || !v.Release || !v.Principal {
		return ErrUnavailable
	}
	return nil
}
func (r *Repository) Admin(ctx context.Context, raw json.RawMessage) (AdminReceipt, error) {
	empty := AdminReceipt{}
	var q adminRequest
	if r == nil || r.kind != "admin" || ctx == nil || ctx.Err() != nil || !decode(raw, AdminBytes, []string{"organization_id", "workspace_id", "environment_id", "actor_id", "fresh_auth_at", "operation", "idempotency_key", "expected_version", "expected_account_version", "policy"}, &q) || !validPolicy(q.Scope, q.Policy) {
		return empty, ErrRejected
	}
	actor, err := domain.ParseProductID(q.ActorID)
	fresh, freshOK := canonicalTime(q.FreshAuthAt)
	now := time.Now()
	if err != nil || actor.String() != q.ActorID || !freshOK || fresh.Before(now.Add(-5*time.Minute)) || fresh.After(now.Add(5*time.Second)) || !keyPattern.MatchString(q.IdempotencyKey) || q.ExpectedVersion < 0 || q.ExpectedVersion > 999999 || q.ExpectedAccountVersion < 0 || q.ExpectedAccountVersion > 1000000 || (q.Operation != "create" && q.Operation != "version" && q.Operation != "disable") || (q.Operation == "create") != (q.ExpectedVersion == 0) || q.Operation != "disable" && q.ExpectedVersion == 999999 {
		return empty, ErrRejected
	}
	expires, _ := canonicalTime(q.Policy.ExpiresAt)
	// SQL applies the effective-time window only to new mutations. Exact saved
	// replay still requires current authentication and unexpired approval.
	if q.Operation != "disable" && !expires.After(now) {
		return empty, ErrRejected
	}
	if err := r.ready(ctx); err != nil {
		return empty, err
	}
	response, err := r.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.pricing_admin($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	var v AdminReceipt
	if err != nil || !decode(response, AdminBytes, []string{"contract_version", "organization_id", "workspace_id", "environment_id", "policy_id", "version", "policy_digest", "account_id", "account_version", "disabled", "policy", "mutation_id"}, &v) {
		return empty, ErrUnavailable
	}
	pid, aid := ids(q.Scope, q.Policy.Provider, q.Policy.Model, q.Policy.AccountProfile)
	accountOK := v.AccountVersion >= 1 && v.AccountVersion <= 1000000 && (v.AccountVersion == q.ExpectedAccountVersion || v.AccountVersion == q.ExpectedAccountVersion+1)
	if q.Operation == "disable" {
		accountOK = accountOK && v.AccountVersion == q.ExpectedAccountVersion
	}
	if v.ContractVersion != 61 || v.Scope != q.Scope || v.PolicyID != pid || v.AccountID != aid || v.Version != q.ExpectedVersion+1 || !accountOK || v.Disabled != (q.Operation == "disable") || v.Policy != q.Policy || v.MutationID != canonicalID(q.Scope, "security_agent_pricing_mutation", q.ActorID+"\x1f"+q.IdempotencyKey) || v.PolicyDigest != policyDigest(v.Scope, v.PolicyID, v.Version, v.AccountID, v.AccountVersion, v.Disabled, v.Policy) || fresh.Before(time.Now().Add(-5*time.Minute)) || q.Operation != "disable" && !expires.After(time.Now()) {
		return empty, ErrUnavailable
	}
	return v, nil
}
func (r *Repository) Lookup(ctx context.Context, raw json.RawMessage) (Bound, error) {
	empty := Bound{}
	var q LookupRequest
	if r == nil || r.kind != "worker" || ctx == nil || ctx.Err() != nil || !decode(raw, LookupBytes, []string{"organization_id", "workspace_id", "environment_id", "provider", "model", "account_profile", "cost_unit", "credential_reference", "credential_digest", "request_policy_version", "request_token_limit", "body", "body_digest", "policy_id", "policy_version", "policy_digest", "account_id", "account_version"}, &q) || !ValidLookupIdentity(q) || !validBody(q) {
		return empty, ErrRejected
	}
	if err := r.ready(ctx); err != nil {
		return empty, err
	}
	response, err := r.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.pricing_lookup($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	if err != nil {
		return empty, ErrUnavailable
	}
	v, err := ValidateBound(response, q)
	effective, _ := canonicalTime(v.Policy.EffectiveAt)
	expires, _ := canonicalTime(v.Policy.ExpiresAt)
	if err != nil || effective.After(time.Now()) || !expires.After(time.Now()) {
		return empty, ErrUnavailable
	}
	return v, nil
}

// ValidateBound checks the complete returned pricing identity and policy
// digest. The caller owns current-time checks; retained terminal evidence can
// remain readable after its original pricing authorization expires.
func ValidateBound(response json.RawMessage, q LookupRequest) (Bound, error) {
	empty := Bound{}
	var v Bound
	if !ValidLookupIdentity(q) || !validBody(q) || !decode(response, AdminBytes, []string{"contract_version", "organization_id", "workspace_id", "environment_id", "policy_id", "policy_version", "policy_digest", "account_id", "account_version", "body_digest", "policy", "maximum_tokens", "maximum_cost_nano_credits", "cost_policy_version"}, &v) || !validPolicy(v.Scope, v.Policy) {
		return empty, ErrUnavailable
	}
	p := v.Policy
	if v.ContractVersion != 61 || v.Scope != q.Scope || v.PolicyID != q.PolicyID || v.PolicyVersion != q.PolicyVersion || v.PolicyDigest != q.PolicyDigest || v.AccountID != q.AccountID || v.AccountVersion != q.AccountVersion || v.BodyDigest != q.BodyDigest || v.PolicyDigest != policyDigest(v.Scope, v.PolicyID, v.PolicyVersion, v.AccountID, v.AccountVersion, false, p) || p.Provider != q.Provider || p.Model != q.Model || p.AccountProfile != q.AccountProfile || p.CostUnit != q.CostUnit || p.CredentialReference != q.CredentialReference || p.CredentialDigest != q.CredentialDigest || p.RequestPolicyVersion != q.RequestPolicyVersion || p.RequestTokenLimit != q.RequestTokenLimit || v.MaximumTokens != p.MaximumTokens || v.MaximumCostNanoCredits != p.MaximumCostNanoCredits || v.CostPolicyVersion != costVersion(v.PolicyVersion, v.PolicyDigest) {
		return empty, ErrUnavailable
	}
	return v, nil
}
