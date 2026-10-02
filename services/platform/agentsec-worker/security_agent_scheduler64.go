package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"regexp"
	"time"
)

type orderedScheduleIdentity struct {
	WorkerID             string `json:"worker_id"`
	ScheduleToken        string `json:"schedule_token"`
	ActionWorkerID       string `json:"action_worker_id"`
	ActionLeaseToken     string `json:"action_lease_token"`
	DeploymentWorkerID   string `json:"deployment_worker_id"`
	DeploymentLeaseToken string `json:"deployment_lease_token"`
}
type orderedScheduleClaim struct {
	orderedScheduleIdentity
	LeaseSeconds         int `json:"lease_seconds"`
	ExecutorLeaseSeconds int `json:"executor_lease_seconds"`
	Limit                int `json:"limit"`
}
type orderedScheduleAuthority struct {
	orderedScheduleIdentity
	ScheduleID      string `json:"schedule_id"`
	RunVersion      int64  `json:"run_version"`
	ScheduleVersion int64  `json:"schedule_version"`
}
type orderedScheduleItem struct {
	multisteppricing.Scope
	ScheduleID        string                 `json:"schedule_id"`
	RunID             string                 `json:"run_id"`
	DefinitionID      string                 `json:"definition_id"`
	DefinitionVersion int64                  `json:"definition_version"`
	RunVersion        int64                  `json:"run_version"`
	ScheduleVersion   int64                  `json:"schedule_version"`
	State             string                 `json:"state"`
	StateClass        string                 `json:"state_class"`
	LeaseExpiresAt    string                 `json:"lease_expires_at"`
	Pricing           orderedDispatchPricing `json:"pricing"`
}
type orderedScheduleResult struct {
	ContractVersion int                  `json:"contract_version"`
	Outcome         string               `json:"outcome"`
	Item            *orderedScheduleItem `json:"item"`
}
type orderedScheduleRepository struct{ database multisteppricing.Database }

var scheduleWorkerPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,127}$`)
var scheduleActionTokenPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func validScheduleIdentity(q orderedScheduleIdentity) bool {
	return scheduleWorkerPattern.MatchString(q.WorkerID) && scheduleWorkerPattern.MatchString(q.ActionWorkerID) && scheduleWorkerPattern.MatchString(q.DeploymentWorkerID) && validDispatchWorker(q.WorkerID, q.ScheduleToken) && validDispatchWorker(q.ActionWorkerID, q.ActionLeaseToken) && validDispatchWorker(q.DeploymentWorkerID, q.DeploymentLeaseToken) && scheduleActionTokenPattern.MatchString(q.ActionLeaseToken) && q.ScheduleToken != q.ActionLeaseToken && q.ScheduleToken != q.DeploymentLeaseToken && q.ActionLeaseToken != q.DeploymentLeaseToken
}
func (r *orderedScheduleRepository) configured(ctx context.Context) bool {
	return r != nil && !nilWorkerDependency(r.database) && ctx != nil && ctx.Err() == nil
}
func (r *orderedScheduleRepository) claim(ctx context.Context, q orderedScheduleClaim) (orderedScheduleResult, error) {
	if !r.configured(ctx) || !validScheduleIdentity(q.orderedScheduleIdentity) || q.LeaseSeconds < 30 || q.LeaseSeconds > 300 || q.ExecutorLeaseSeconds < 30 || q.ExecutorLeaseSeconds > 300 || q.Limit != 1 {
		return orderedScheduleResult{}, apiserver.ErrRepositoryOperation
	}
	raw, err := r.query(ctx, orderedScheduleWire{Operation: "claim", orderedScheduleIdentity: &q.orderedScheduleIdentity, LeaseSeconds: q.LeaseSeconds, ExecutorLeaseSeconds: q.ExecutorLeaseSeconds, Limit: q.Limit})
	if err != nil {
		return orderedScheduleResult{}, err
	}
	return decodeScheduleResult(raw, "claim", q.orderedScheduleIdentity, nil)
}

// Every wire key has a typed field; callers have no raw JSON entry point.
type orderedScheduleWire struct {
	Operation string `json:"operation"`
	*orderedScheduleIdentity
	ScheduleID           string `json:"schedule_id,omitempty"`
	RunVersion           int64  `json:"run_version,omitempty"`
	ScheduleVersion      int64  `json:"schedule_version,omitempty"`
	LeaseSeconds         int    `json:"lease_seconds,omitempty"`
	ExecutorLeaseSeconds int    `json:"executor_lease_seconds,omitempty"`
	Limit                int    `json:"limit,omitempty"`
}

func (r *orderedScheduleRepository) query(ctx context.Context, q orderedScheduleWire) (json.RawMessage, error) {
	raw, err := json.Marshal(q)
	if err != nil || len(raw) > 4096 {
		return nil, apiserver.ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := r.database.QueryJSON(bounded, `SELECT zasp_ordered_scheduler64.scheduler($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentScheduler().Checksum(), migrations.SecurityAgentSchedulerFingerprint(), json.RawMessage(raw))
	if err != nil || bounded.Err() != nil {
		return nil, apiserver.ErrRepositoryUnavailable
	}
	return response, nil
}
func (r *orderedScheduleRepository) ready(ctx context.Context) error {
	if !r.configured(ctx) {
		return apiserver.ErrRepositoryOperation
	}
	raw, err := r.query(ctx, orderedScheduleWire{Operation: "ready"})
	if err != nil {
		return err
	}
	var v struct {
		ContractVersion int  `json:"contract_version"`
		Ready           bool `json:"ready"`
	}
	if !dispatchDecode(raw, &v, "contract_version", "ready") || v.ContractVersion != 64 || !v.Ready {
		return apiserver.ErrRepositoryUnavailable
	}
	return nil
}
func (r *orderedScheduleRepository) heartbeat(ctx context.Context, q orderedScheduleAuthority, seconds int) (orderedScheduleResult, error) {
	return r.mutate(ctx, "heartbeat", q, seconds)
}
func (r *orderedScheduleRepository) finish(ctx context.Context, q orderedScheduleAuthority) (orderedScheduleResult, error) {
	return r.mutate(ctx, "finish", q, 0)
}
func (r *orderedScheduleRepository) abandon(ctx context.Context, q orderedScheduleAuthority) (orderedScheduleResult, error) {
	return r.mutate(ctx, "abandon", q, 0)
}
func (r *orderedScheduleRepository) mutate(ctx context.Context, op string, q orderedScheduleAuthority, seconds int) (orderedScheduleResult, error) {
	if !r.configured(ctx) || !validScheduleIdentity(q.orderedScheduleIdentity) || !validSecurityAgentPlannerProductID(q.ScheduleID) || !validDispatchVersion(q.RunVersion) || !validDispatchVersion(q.ScheduleVersion) || q.ScheduleVersion >= 1000000 || op == "heartbeat" && (seconds < 30 || seconds > 300) {
		return orderedScheduleResult{}, apiserver.ErrRepositoryOperation
	}
	raw, err := r.query(ctx, orderedScheduleWire{Operation: op, orderedScheduleIdentity: &q.orderedScheduleIdentity, ScheduleID: q.ScheduleID, RunVersion: q.RunVersion, ScheduleVersion: q.ScheduleVersion, LeaseSeconds: seconds})
	if err != nil {
		return orderedScheduleResult{}, err
	}
	return decodeScheduleResult(raw, op, q.orderedScheduleIdentity, &q)
}

func decodeScheduleResult(raw json.RawMessage, op string, identity orderedScheduleIdentity, authority *orderedScheduleAuthority) (orderedScheduleResult, error) {
	fail := func() (orderedScheduleResult, error) {
		return orderedScheduleResult{}, apiserver.ErrRepositoryUnavailable
	}
	var result orderedScheduleResult
	if !dispatchDecode(raw, &result, "contract_version", "outcome", "item") || result.ContractVersion != 64 {
		return fail()
	}
	switch op {
	case "claim":
		if result.Outcome != "claimed" && result.Outcome != "empty" {
			return fail()
		}
	case "heartbeat":
		if result.Outcome != "extended" {
			return fail()
		}
	case "finish":
		if result.Outcome != "finished" {
			return fail()
		}
	case "abandon":
		if result.Outcome != "released" && result.Outcome != "recovery_deferred" {
			return fail()
		}
	default:
		return fail()
	}
	itemRequired := result.Outcome == "claimed" || result.Outcome == "extended"
	if (result.Item != nil) != itemRequired {
		return fail()
	}
	if !itemRequired {
		return result, nil
	}
	fields, _ := securityAgentOrderedJSONObject(raw)
	var item orderedScheduleItem
	if !dispatchDecode(fields["item"], &item, "schedule_id", "organization_id", "workspace_id", "environment_id", "run_id", "definition_id", "definition_version", "run_version", "schedule_version", "state", "state_class", "lease_expires_at", "pricing") {
		return fail()
	}
	nested, _ := securityAgentOrderedJSONObject(fields["item"])
	var p orderedDispatchPricing
	if !dispatchDecode(nested["pricing"], &p, "provider", "model", "request_policy_version", "request_token_limit", "credential_digest", "account_profile", "cost_unit", "credential_reference", "policy_id", "policy_version", "policy_digest", "account_id", "account_version") {
		return fail()
	}
	for _, id := range []string{item.ScheduleID, item.OrganizationID, item.WorkspaceID, item.EnvironmentID, item.RunID, item.DefinitionID} {
		if !validSecurityAgentPlannerProductID(id) {
			return fail()
		}
	}
	if item.OrganizationID == item.WorkspaceID || item.OrganizationID == item.EnvironmentID || item.WorkspaceID == item.EnvironmentID || !validDispatchVersion(item.DefinitionVersion) || item.RunVersion < 3 || !validDispatchVersion(item.RunVersion) || !validDispatchVersion(item.ScheduleVersion) {
		return fail()
	}
	lookup := multisteppricing.LookupRequest{Scope: item.Scope, Provider: p.Provider, Model: p.Model, RequestPolicyVersion: p.RequestPolicyVersion, RequestTokenLimit: int64(p.RequestTokenLimit), CredentialDigest: p.CredentialDigest, AccountProfile: p.AccountProfile, CostUnit: p.CostUnit, CredentialReference: p.CredentialReference, PolicyID: p.PolicyID, PolicyVersion: p.PolicyVersion, PolicyDigest: p.PolicyDigest, AccountID: p.AccountID, AccountVersion: p.AccountVersion}
	if !validDispatchPlanner(p.orderedDispatchPlanner) || !multisteppricing.ValidLookupIdentity(lookup) {
		return fail()
	}
	o, _ := domain.ParseProductID(item.OrganizationID)
	w, _ := domain.ParseProductID(item.WorkspaceID)
	e, _ := domain.ParseProductID(item.EnvironmentID)
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		return fail()
	}
	digest := sha256.Sum256([]byte(identity.ScheduleToken))
	expected, _ := apiserver.CanonicalDiscoveryID(scope, "ordered_scheduler64", item.RunID+"\x1f"+identity.WorkerID+"\x1f"+hex.EncodeToString(digest[:]))
	if item.ScheduleID != expected {
		return fail()
	}
	expires, err := time.Parse("2006-01-02T15:04:05.000000Z", item.LeaseExpiresAt)
	if err != nil || expires.UTC().Format("2006-01-02T15:04:05.000000Z") != item.LeaseExpiresAt || !expires.After(time.Now()) || expires.After(time.Now().Add(301*time.Second)) {
		return fail()
	}
	live := item.State == "waiting_approval" || item.State == "running" || item.State == "verifying"
	terminal := item.State == "contained" || item.State == "remediated" || item.State == "needs_human" || item.State == "cancelled"
	switch item.StateClass {
	case "application":
		if item.State != "running" || item.RunVersion < 4 {
			return fail()
		}
	case "successor":
		if item.State != "running" || item.RunVersion < 6 {
			return fail()
		}
	case "test":
		if (item.State != "running" && item.State != "verifying") || item.RunVersion < 8 {
			return fail()
		}
	case "stop":
		if !live {
			return fail()
		}
	case "recovery":
		if !live && !terminal {
			return fail()
		}
	case "cleanup":
		if !terminal {
			return fail()
		}
	case "approval":
		if op == "claim" || item.State != "waiting_approval" {
			return fail()
		}
	case "terminal":
		if op == "claim" || !terminal {
			return fail()
		}
	default:
		return fail()
	}
	if authority != nil && (item.ScheduleID != authority.ScheduleID || item.RunVersion != authority.RunVersion || item.ScheduleVersion != authority.ScheduleVersion+1) {
		return fail()
	}
	return result, nil
}
