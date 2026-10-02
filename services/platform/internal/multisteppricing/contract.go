// Package multisteppricing is an internal release61 approval-ceiling boundary.
// It has no provider, reservation, public route, or default runtime wiring.
package multisteppricing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	AdminBytes  = 8192
	LookupBytes = 524288 // 64 KiB body, with JSON string escaping and metadata.
	BodyBytes   = 65536
	TimeFormat  = "2006-01-02T15:04:05.000000Z"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var modelPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var referencePattern = regexp.MustCompile(`^secret_ref_planner/[A-Za-z0-9_/-]{1,220}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

type Scope struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
}
type Policy struct {
	Provider               string `json:"provider"`
	Model                  string `json:"model"`
	AccountProfile         string `json:"account_profile"`
	CostUnit               string `json:"cost_unit"`
	MaximumTokens          int64  `json:"maximum_tokens"`
	MaximumCostNanoCredits int64  `json:"maximum_cost_nano_credits"`
	RequestPolicyVersion   string `json:"request_policy_version"`
	RequestTokenLimit      int64  `json:"request_token_limit"`
	CredentialReference    string `json:"credential_reference"`
	CredentialDigest       string `json:"credential_digest"`
	EffectiveAt            string `json:"effective_at"`
	ExpiresAt              string `json:"expires_at"`
}
type adminRequest struct {
	Scope
	ActorID                string `json:"actor_id"`
	FreshAuthAt            string `json:"fresh_auth_at"`
	Operation              string `json:"operation"`
	IdempotencyKey         string `json:"idempotency_key"`
	ExpectedVersion        int64  `json:"expected_version"`
	ExpectedAccountVersion int64  `json:"expected_account_version"`
	Policy                 Policy `json:"policy"`
}
type AdminReceipt struct {
	Scope
	ContractVersion int    `json:"contract_version"`
	PolicyID        string `json:"policy_id"`
	Version         int64  `json:"version"`
	PolicyDigest    string `json:"policy_digest"`
	AccountID       string `json:"account_id"`
	AccountVersion  int64  `json:"account_version"`
	Disabled        bool   `json:"disabled"`
	Policy          Policy `json:"policy"`
	MutationID      string `json:"mutation_id"`
}
type LookupRequest struct {
	Scope
	Provider             string `json:"provider"`
	Model                string `json:"model"`
	AccountProfile       string `json:"account_profile"`
	CostUnit             string `json:"cost_unit"`
	CredentialReference  string `json:"credential_reference"`
	CredentialDigest     string `json:"credential_digest"`
	RequestPolicyVersion string `json:"request_policy_version"`
	RequestTokenLimit    int64  `json:"request_token_limit"`
	Body                 string `json:"body"`
	BodyDigest           string `json:"body_digest"`
	PolicyID             string `json:"policy_id"`
	PolicyVersion        int64  `json:"policy_version"`
	PolicyDigest         string `json:"policy_digest"`
	AccountID            string `json:"account_id"`
	AccountVersion       int64  `json:"account_version"`
}

// ValidLookupIdentity validates every field that identifies an authorized
// lookup without performing database or provider I/O. Body validation remains
// separate because a release preflight has no prepared request body yet.
func ValidLookupIdentity(q LookupRequest) bool {
	if !validScope(q.Scope) || q.Provider != "openrouter" || q.CostUnit != "openrouter_credit" || len(q.Model) > 128 || !modelPattern.MatchString(q.Model) || !boundedToken(q.AccountProfile, 128) || !boundedToken(q.RequestPolicyVersion, 63) || !validReference(q.Scope, q.CredentialReference) || !digestPattern.MatchString(q.CredentialDigest) || !digestPattern.MatchString(q.PolicyDigest) || q.PolicyVersion < 1 || q.PolicyVersion > 999999 || q.AccountVersion < 1 || q.AccountVersion > 1000000 || q.RequestTokenLimit < 1 || q.RequestTokenLimit > 4096 {
		return false
	}
	policyID, accountID := ids(q.Scope, q.Provider, q.Model, q.AccountProfile)
	return q.PolicyID == policyID && q.AccountID == accountID
}

type Bound struct {
	Scope
	ContractVersion        int    `json:"contract_version"`
	PolicyID               string `json:"policy_id"`
	PolicyVersion          int64  `json:"policy_version"`
	PolicyDigest           string `json:"policy_digest"`
	AccountID              string `json:"account_id"`
	AccountVersion         int64  `json:"account_version"`
	BodyDigest             string `json:"body_digest"`
	Policy                 Policy `json:"policy"`
	MaximumTokens          int64  `json:"maximum_tokens"`
	MaximumCostNanoCredits int64  `json:"maximum_cost_nano_credits"`
	CostPolicyVersion      string `json:"cost_policy_version"`
}

func validScope(s Scope) bool {
	for _, id := range []string{s.OrganizationID, s.WorkspaceID, s.EnvironmentID} {
		p, err := domain.ParseProductID(id)
		if err != nil || p.String() != id {
			return false
		}
	}
	return true
}
func boundedToken(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && tokenPattern.MatchString(s)
}
func canonicalTime(s string) (time.Time, bool) {
	v, e := time.Parse(time.RFC3339Nano, s)
	return v, e == nil && s == v.UTC().Format(TimeFormat)
}
func validReference(s Scope, ref string) bool {
	return referencePattern.MatchString(ref) && !strings.Contains(ref, "//") && strings.HasPrefix(ref, "secret_ref_planner/"+s.OrganizationID+"/"+s.WorkspaceID+"/"+s.EnvironmentID+"/") && len(ref) > len("secret_ref_planner/"+s.OrganizationID+"/"+s.WorkspaceID+"/"+s.EnvironmentID+"/")
}
func validPolicy(s Scope, p Policy) bool {
	effective, ok := canonicalTime(p.EffectiveAt)
	expires, ok2 := canonicalTime(p.ExpiresAt)
	return validScope(s) && p.Provider == "openrouter" && p.CostUnit == "openrouter_credit" && len(p.Model) <= 128 && modelPattern.MatchString(p.Model) && boundedToken(p.AccountProfile, 128) && boundedToken(p.RequestPolicyVersion, 63) && p.MaximumTokens >= 1 && p.MaximumTokens <= 12000 && p.MaximumCostNanoCredits >= 1 && p.MaximumCostNanoCredits <= 1000000000000 && p.RequestTokenLimit >= 1 && p.RequestTokenLimit <= 4096 && p.RequestTokenLimit <= p.MaximumTokens && validReference(s, p.CredentialReference) && digestPattern.MatchString(p.CredentialDigest) && ok && ok2 && expires.After(effective) && !expires.After(effective.Add(30*24*time.Hour))
}
func canonicalID(s Scope, kind, native string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{s.OrganizationID, s.WorkspaceID, s.EnvironmentID, kind, native}, "\x1f")))
	v := hex.EncodeToString(h[:])
	return fmt.Sprintf("pid_%s-%s-4%s-8%s-%s", v[:8], v[8:12], v[13:16], v[17:20], v[20:32])
}
func ids(s Scope, provider, model, profile string) (string, string) {
	return canonicalID(s, "security_agent_pricing_policy", strings.Join([]string{provider, model, profile}, "\x1f")), canonicalID(s, "security_agent_pricing_account", provider+"\x1f"+profile)
}
func digest(v []byte) string { h := sha256.Sum256(v); return "sha256:" + hex.EncodeToString(h[:]) }
func policyDigest(s Scope, pid string, version int64, aid string, av int64, disabled bool, p Policy) string {
	value := map[string]any{"organization_id": s.OrganizationID, "workspace_id": s.WorkspaceID, "environment_id": s.EnvironmentID, "policy_id": pid, "version": version, "account_id": aid, "account_version": av, "disabled": disabled, "policy": p}
	// Use JSON values so nested policy keys have the same sorted canonical form
	// as the SQL deployment_json function, not Go struct declaration order.
	raw, _ := json.Marshal(value)
	var canonical any
	if json.Unmarshal(raw, &canonical) != nil {
		return ""
	}
	raw, _ = json.Marshal(canonical)
	return digest(raw)
}
func costVersion(version int64, pin string) string {
	return "pricing61-" + strconv.FormatInt(version, 10) + "-" + pin[7:39]
}

func decode(raw []byte, limit int, keys []string, v any) bool {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if !uniqueValue(d, 0) {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		field, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
			return false
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v) == nil
}
func uniqueValue(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			s, ok := key.(string)
			if err != nil || !ok || keys[s] || !uniqueValue(d, depth+1) {
				return false
			}
			keys[s] = true
		}
		last, err := d.Token()
		return err == nil && last == json.Delim('}')
	case '[':
		for d.More() {
			if !uniqueValue(d, depth+1) {
				return false
			}
		}
		last, err := d.Token()
		return err == nil && last == json.Delim(']')
	}
	return false
}
func validBody(q LookupRequest) bool {
	var body struct {
		Model     string `json:"model"`
		MaxTokens int64  `json:"max_tokens"`
		Messages  []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Provider struct {
			DataCollection    string `json:"data_collection"`
			RequireParameters bool   `json:"require_parameters"`
		} `json:"provider"`
		Response struct {
			Type   string `json:"type"`
			Schema struct {
				Name   string         `json:"name"`
				Strict bool           `json:"strict"`
				Schema map[string]any `json:"schema"`
			} `json:"json_schema"`
		} `json:"response_format"`
	}
	return digest([]byte(q.Body)) == q.BodyDigest && decode([]byte(q.Body), BodyBytes, []string{"model", "max_tokens", "messages", "provider", "response_format"}, &body) && body.Model == q.Model && body.MaxTokens == q.RequestTokenLimit && len(body.Messages) == 2 && body.Messages[0].Role == "system" && len(body.Messages[0].Content) >= 1 && len(body.Messages[0].Content) <= 4096 && body.Messages[1].Role == "user" && len(body.Messages[1].Content) >= 1 && len(body.Messages[1].Content) <= 49152 && body.Provider.DataCollection == "deny" && body.Provider.RequireParameters && body.Response.Type == "json_schema" && body.Response.Schema.Name == "security_response_plan" && body.Response.Schema.Strict && body.Response.Schema.Schema != nil
}
