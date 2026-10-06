package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

type orderedDispatchPlanner struct {
	Provider             string `json:"provider"`
	Model                string `json:"model"`
	RequestPolicyVersion string `json:"request_policy_version"`
	RequestTokenLimit    int    `json:"request_token_limit"`
	CredentialDigest     string `json:"credential_digest"`
}
type orderedDispatchClaim struct {
	WorkerID     string                 `json:"worker_id"`
	LeaseToken   string                 `json:"lease_token"`
	LeaseSeconds int                    `json:"lease_seconds"`
	Limit        int                    `json:"limit"`
	Planner      orderedDispatchPlanner `json:"planner"`
}
type orderedDispatchAuthority struct {
	WorkerID        string `json:"worker_id"`
	LeaseToken      string `json:"lease_token"`
	DispatchID      string `json:"dispatch_id"`
	RunVersion      int64  `json:"run_version"`
	DispatchVersion int64  `json:"dispatch_version"`
}
type orderedDispatchPricing struct {
	orderedDispatchPlanner
	AccountProfile      string `json:"account_profile"`
	CostUnit            string `json:"cost_unit"`
	CredentialReference string `json:"credential_reference"`
	PolicyID            string `json:"policy_id"`
	PolicyVersion       int64  `json:"policy_version"`
	PolicyDigest        string `json:"policy_digest"`
	AccountID           string `json:"account_id"`
	AccountVersion      int64  `json:"account_version"`
}
type orderedDispatchItem struct {
	DispatchID string `json:"dispatch_id"`
	multisteppricing.Scope
	RunID             string                 `json:"run_id"`
	DefinitionID      string                 `json:"definition_id"`
	DefinitionVersion int64                  `json:"definition_version"`
	RunVersion        int64                  `json:"run_version"`
	State             string                 `json:"state"`
	DispatchVersion   int64                  `json:"dispatch_version"`
	LeaseExpiresAt    string                 `json:"lease_expires_at"`
	Pricing           orderedDispatchPricing `json:"pricing"`
}
type orderedDispatchResult struct {
	ContractVersion int                  `json:"contract_version"`
	Outcome         string               `json:"outcome"`
	Item            *orderedDispatchItem `json:"item"`
}
type orderedDispatchRepository struct{ database multisteppricing.Database }

var dispatchWorkerPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var dispatchTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{16,128}$`)
var dispatchDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func validDispatchPlanner(q orderedDispatchPlanner) bool {
	return q.Provider == "openrouter" && q.Model == "openai/gpt-5-mini" && q.RequestPolicyVersion == "security-agent-planner-v1" && q.RequestTokenLimit >= 1 && q.RequestTokenLimit <= 4096 && dispatchDigestPattern.MatchString(q.CredentialDigest)
}
func validDispatchWorker(w, t string) bool {
	return dispatchWorkerPattern.MatchString(w) && dispatchTokenPattern.MatchString(t) && strings.Trim(t, "0") != ""
}
func validDispatchVersion(v int64) bool { return v >= 1 && v <= 1000000 }
func (r *orderedDispatchRepository) configured(ctx context.Context) bool {
	if r == nil || r.database == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	v := reflect.ValueOf(r.database)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Func, reflect.Interface, reflect.Slice:
		if v.IsNil() {
			return false
		}
	}
	return true
}
func (r *orderedDispatchRepository) claim(ctx context.Context, q orderedDispatchClaim) (orderedDispatchResult, error) {
	if !r.configured(ctx) || !validDispatchWorker(q.WorkerID, q.LeaseToken) || q.LeaseSeconds < 30 || q.LeaseSeconds > 300 || q.Limit != 1 || !validDispatchPlanner(q.Planner) {
		return orderedDispatchResult{}, apiserver.ErrRepositoryOperation
	}
	raw, err := r.query(ctx, struct {
		Operation string `json:"operation"`
		orderedDispatchClaim
	}{"claim", q})
	if err != nil {
		return orderedDispatchResult{}, err
	}
	v, err := decodeDispatchResult(raw, "claim", nil)
	if err == nil && v.Item != nil && v.Item.Pricing.orderedDispatchPlanner != q.Planner {
		return orderedDispatchResult{}, apiserver.ErrRepositoryUnavailable
	}
	return v, err
}

// No caller can supply a tenant or run. Mutation authority is the opaque
// dispatch identity and exact versions returned by the server.
func (r *orderedDispatchRepository) heartbeat(ctx context.Context, q orderedDispatchAuthority, seconds int) (orderedDispatchResult, error) {
	return r.mutate(ctx, "heartbeat", q, seconds)
}
func (r *orderedDispatchRepository) finish(ctx context.Context, q orderedDispatchAuthority) (orderedDispatchResult, error) {
	return r.mutate(ctx, "finish", q, 0)
}
func (r *orderedDispatchRepository) abandon(ctx context.Context, q orderedDispatchAuthority) (orderedDispatchResult, error) {
	return r.mutate(ctx, "abandon", q, 0)
}
func (r *orderedDispatchRepository) mutate(ctx context.Context, op string, q orderedDispatchAuthority, seconds int) (orderedDispatchResult, error) {
	if !r.configured(ctx) || !validDispatchWorker(q.WorkerID, q.LeaseToken) || !validSecurityAgentPlannerProductID(q.DispatchID) || !validDispatchVersion(q.RunVersion) || !validDispatchVersion(q.DispatchVersion) || op == "heartbeat" && (seconds < 30 || seconds > 300) {
		return orderedDispatchResult{}, apiserver.ErrRepositoryOperation
	}
	var request any = struct {
		Operation string `json:"operation"`
		orderedDispatchAuthority
	}{op, q}
	if op == "heartbeat" {
		request = struct {
			Operation string `json:"operation"`
			orderedDispatchAuthority
			LeaseSeconds int `json:"lease_seconds"`
		}{op, q, seconds}
	}
	raw, err := r.query(ctx, request)
	if err != nil {
		return orderedDispatchResult{}, err
	}
	return decodeDispatchResult(raw, op, &q)
}
func (r *orderedDispatchRepository) ready(ctx context.Context) error {
	if !r.configured(ctx) {
		return apiserver.ErrRepositoryOperation
	}
	raw, err := r.query(ctx, struct {
		Operation string `json:"operation"`
	}{"ready"})
	if err != nil {
		return err
	}
	var v struct {
		ContractVersion int  `json:"contract_version"`
		Ready           bool `json:"ready"`
	}
	if !dispatchDecode(raw, &v, "contract_version", "ready") || v.ContractVersion != 63 || !v.Ready {
		return apiserver.ErrRepositoryUnavailable
	}
	return nil
}
func (r *orderedDispatchRepository) query(ctx context.Context, q any) (json.RawMessage, error) {
	raw, err := json.Marshal(q)
	if err != nil || len(raw) > 4096 {
		return nil, apiserver.ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := r.database.QueryJSON(bounded, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, migrations.SecurityAgentWorkerChecksum(), migrations.SecurityAgentWorkerFingerprint(), json.RawMessage(raw))
	if err != nil || bounded.Err() != nil {
		return nil, apiserver.ErrRepositoryUnavailable
	}
	return response, nil
}
func dispatchDecode(raw json.RawMessage, out any, keys ...string) bool {
	if len(raw) > 8192 || !utf8.Valid(raw) {
		return false
	}
	fields, ok := securityAgentOrderedJSONObject(raw)
	if !ok || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, present := fields[key]; !present {
			return false
		}
	}
	for k, v := range fields {
		if k != "item" && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out) == nil && jsonDecoderAtEOF(decoder)
}
func decodeDispatchResult(raw json.RawMessage, op string, authority *orderedDispatchAuthority) (orderedDispatchResult, error) {
	var v orderedDispatchResult
	fail := func() (orderedDispatchResult, error) {
		return orderedDispatchResult{}, apiserver.ErrRepositoryUnavailable
	}
	if !dispatchDecode(raw, &v, "contract_version", "outcome", "item") || v.ContractVersion != 63 {
		return fail()
	}
	switch op {
	case "claim":
		if v.Outcome != "claimed" && v.Outcome != "empty" {
			return fail()
		}
	case "heartbeat":
		if v.Outcome != "extended" {
			return fail()
		}
	case "finish":
		if v.Outcome != "finished" {
			return fail()
		}
	case "abandon":
		if v.Outcome != "recovery_deferred" && v.Outcome != "reconciled" {
			return fail()
		}
	default:
		return fail()
	}
	requires := v.Outcome == "claimed" || v.Outcome == "extended"
	if (v.Item != nil) != requires {
		return fail()
	}
	if !requires {
		return v, nil
	}
	fields, _ := securityAgentOrderedJSONObject(raw)
	var item orderedDispatchItem
	if !dispatchDecode(fields["item"], &item, "dispatch_id", "organization_id", "workspace_id", "environment_id", "run_id", "definition_id", "definition_version", "run_version", "state", "dispatch_version", "lease_expires_at", "pricing") {
		return fail()
	}
	nested, _ := securityAgentOrderedJSONObject(fields["item"])
	var p orderedDispatchPricing
	if !dispatchDecode(nested["pricing"], &p, "provider", "model", "request_policy_version", "request_token_limit", "credential_digest", "account_profile", "cost_unit", "credential_reference", "policy_id", "policy_version", "policy_digest", "account_id", "account_version") {
		return fail()
	}
	for _, id := range []string{item.DispatchID, item.OrganizationID, item.WorkspaceID, item.EnvironmentID, item.RunID, item.DefinitionID, p.PolicyID, p.AccountID} {
		if !validSecurityAgentPlannerProductID(id) {
			return fail()
		}
	}
	if item.OrganizationID == item.WorkspaceID || item.WorkspaceID == item.EnvironmentID || item.OrganizationID == item.EnvironmentID || !validDispatchVersion(item.DefinitionVersion) || !validDispatchVersion(item.RunVersion) || !validDispatchVersion(item.DispatchVersion) || !validDispatchVersion(p.PolicyVersion) || !validDispatchVersion(p.AccountVersion) || !validDispatchPlanner(p.orderedDispatchPlanner) || !dispatchWorkerPattern.MatchString(p.AccountProfile) || p.CostUnit != "openrouter_credit" || !dispatchDigestPattern.MatchString(p.PolicyDigest) {
		return fail()
	}
	prefix := "secret_ref_planner/" + item.OrganizationID + "/" + item.WorkspaceID + "/" + item.EnvironmentID + "/"
	if !strings.HasPrefix(p.CredentialReference, prefix) || len(p.CredentialReference) <= len(prefix) || len(p.CredentialReference) > 239 || strings.Contains(p.CredentialReference, "..") || strings.Contains(p.CredentialReference, "//") {
		return fail()
	}
	for _, c := range strings.TrimPrefix(p.CredentialReference, prefix) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '/') {
			return fail()
		}
	}
	expires, err := time.Parse("2006-01-02T15:04:05.000000Z", item.LeaseExpiresAt)
	if err != nil || expires.UTC().Format("2006-01-02T15:04:05.000000Z") != item.LeaseExpiresAt || !expires.After(time.Now()) || expires.After(time.Now().Add(301*time.Second)) {
		return fail()
	}
	switch item.State {
	case "planning", "waiting_approval", "running", "verifying", "contained", "remediated", "needs_human", "cancelled":
	default:
		return fail()
	}
	if op == "claim" && (item.State != "planning" || item.RunVersion != 2) {
		return fail()
	}
	if authority != nil && (item.DispatchID != authority.DispatchID || item.RunVersion != authority.RunVersion || item.DispatchVersion != authority.DispatchVersion+1) {
		return fail()
	}
	return v, nil
}
