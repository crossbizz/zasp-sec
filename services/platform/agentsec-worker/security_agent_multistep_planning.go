package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Private composition only. Neither the default worker nor any CLI/API route
// constructs this configuration. Credential and catalog installation are gates.
type orderedPlanningConfig struct {
	Database                    multisteppricing.Database
	Store                       artifactstore.ArtifactStore
	Planner                     *productionSecurityAgentPlanner
	Selection                   securityAgentMultistepPricingBinding
	RunID, WorkerID, LeaseToken string
}
type orderedPlanningJob struct {
	multisteppricing.Scope
	RunID            string                          `json:"run_id"`
	WorkerID         string                          `json:"worker_id"`
	LeaseExpiresAt   time.Time                       `json:"lease_expires_at"`
	BudgetStartedAt  time.Time                       `json:"budget_started_at"`
	BudgetDeadlineAt time.Time                       `json:"budget_deadline_at"`
	RunVersion       int64                           `json:"run_version"`
	Attempt          int                             `json:"attempt"`
	State            string                          `json:"state"`
	ContextValue     json.RawMessage                 `json:"context_value"`
	InputBody        string                          `json:"input_body"`
	InputDigest      string                          `json:"input_digest"`
	InputSize        int64                           `json:"input_size"`
	InputArtifactID  string                          `json:"input_artifact_id"`
	OutputArtifactID string                          `json:"output_artifact_id"`
	ReservationID    string                          `json:"reservation_id"`
	RequestBody      string                          `json:"request_body"`
	RequestDigest    string                          `json:"request_digest"`
	LookupRequest    *multisteppricing.LookupRequest `json:"lookup_request"`
	PricingBound     *multisteppricing.Bound         `json:"pricing_bound"`
	InputVersion     string                          `json:"input_version"`
	RawResult        string                          `json:"raw_result"`
	ResultValue      json.RawMessage                 `json:"result_value"`
	ProviderDigest   string                          `json:"provider_digest"`
	OutputBody       string                          `json:"output_body"`
	OutputDigest     string                          `json:"output_digest"`
	OutputVersion    string                          `json:"output_version"`
	Receipt          json.RawMessage                 `json:"receipt"`
	SendPermit       bool                            `json:"send_permit,omitempty"`
}

// This wrapper belongs to one serial private planning invocation. It also
// bounds the prerequisite pricing lookup without changing that shared API.
type orderedPlanningSQLDatabase struct {
	multisteppricing.Database
	authorityDeadline time.Time
	parent            context.Context
}

func (d *orderedPlanningSQLDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	deadline := time.Now().Add(30 * time.Second)
	if !d.authorityDeadline.IsZero() && d.authorityDeadline.Before(deadline) {
		deadline = d.authorityDeadline
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// The shared pricing constructor has its own readiness context. Keep it
	// bounded by—and cancellable with—this private invocation as well.
	if d.parent != nil {
		stop := context.AfterFunc(d.parent, cancel)
		defer stop()
		if d.parent.Err() != nil {
			cancel()
		}
	}
	return d.Database.QueryJSON(bounded, q, args...)
}

func runSecurityAgentOrderedPlanning(ctx context.Context, c orderedPlanningConfig) (json.RawMessage, error) {
	return advanceSecurityAgentOrderedPlanning(ctx, c, 8)
}

// The dormant runtime selects zero for a fresh claim, or one for one retained
// job transition. Start/send/result remains one journaled operation: the fresh
// send permit is never exported, retained across ticks, or reconstructed.
func advanceSecurityAgentOrderedPlanning(ctx context.Context, c orderedPlanningConfig, transitionsLimit int) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil || c.Database == nil || c.Store == nil || c.Planner == nil || !validSecurityAgentPlannerProductID(c.RunID) {
		return nil, errWorkerExecution
	}
	database := &orderedPlanningSQLDatabase{Database: c.Database, parent: ctx}
	c.Database = database
	call := func(operation string, payload any) (json.RawMessage, error) {
		q, err := json.Marshal(map[string]any{"organization_id": c.Selection.OrganizationID, "workspace_id": c.Selection.WorkspaceID, "environment_id": c.Selection.EnvironmentID, "run_id": c.RunID, "worker_id": c.WorkerID, "lease_token": c.LeaseToken, "operation": operation, "payload": payload})
		if err != nil {
			return nil, errWorkerExecution
		}
		raw, err := c.Database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.planning($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), json.RawMessage(q))
		if err != nil {
			return nil, errWorkerExecution
		}
		return raw, nil
	}
	raw, err := call("claim", map[string]any{})
	if err != nil {
		return nil, err
	}
	if transitionsLimit == 0 {
		return raw, nil
	}
	for transitions := 0; transitions < transitionsLimit; transitions++ {
		job, value, scope, err := decodeOrderedPlanningJob(raw, c)
		if err != nil {
			return nil, err
		}
		deadline := orderedPlanningDeadline(ctx, job)
		database.authorityDeadline = deadline
		operationCtx, cancel := context.WithDeadline(ctx, deadline)
		if operationCtx.Err() != nil {
			cancel()
			return nil, errWorkerExecution
		}
		switch job.State {
		case "claimed":
			artifact, putErr := orderedPlanningArtifact(operationCtx, c.Store, scope, job.InputArtifactID, "", job.InputBody)
			cancel()
			if putErr != nil {
				return nil, errWorkerExecution
			}
			c.Planner.mu.RLock()
			selection := multisteppricing.LookupRequest{Scope: c.Selection.Scope, Provider: "openrouter", Model: c.Planner.model, AccountProfile: c.Selection.AccountProfile, CostUnit: "openrouter_credit", CredentialReference: c.Selection.CredentialReference, CredentialDigest: orderedPlanningDigest(c.Planner.token), RequestPolicyVersion: c.Planner.policyVersion, RequestTokenLimit: int64(c.Planner.maximumTokens), PolicyID: c.Selection.PolicyID, PolicyVersion: c.Selection.PolicyVersion, PolicyDigest: c.Selection.PolicyDigest, AccountID: c.Selection.AccountID, AccountVersion: c.Selection.AccountVersion}
			closed := c.Planner.closed
			c.Planner.mu.RUnlock()
			if closed {
				return nil, errWorkerExecution
			}
			encoded, _ := json.Marshal(selection)
			var fields map[string]json.RawMessage
			json.Unmarshal(encoded, &fields)
			delete(fields, "body")
			delete(fields, "body_digest")
			raw, err = call("prepare", map[string]any{"pricing": fields, "input_version": artifact.VersionID})
		case "prepared":
			_, readErr := orderedPlanningArtifact(operationCtx, c.Store, scope, job.InputArtifactID, job.InputVersion, job.InputBody)
			if readErr != nil {
				cancel()
				return nil, errWorkerExecution
			}
			prepared, prepareErr := orderedPlanningPrepared(operationCtx, c.Planner, job, value)
			if prepareErr != nil {
				cancel()
				return nil, errWorkerExecution
			}
			bound, lookupErr := lookupSecurityAgentMultistepCost(operationCtx, c.Database, prepared, c.Selection)
			if lookupErr != nil || bound == nil || !bound.expiresAt.Equal(mustOrderedPricingExpiry(job)) || !deadline.After(time.Now().Add(31*time.Second)) {
				cancel()
				return nil, errWorkerExecution
			}
			startRaw, startErr := call("start", map[string]any{})
			if startErr != nil {
				cancel()
				return nil, errWorkerExecution
			}
			started, _, _, startErr := decodeOrderedPlanningJob(startRaw, c)
			if startErr != nil || started.State != "started" || !started.SendPermit || started.RequestDigest != job.RequestDigest || !started.LeaseExpiresAt.Equal(job.LeaseExpiresAt) || !started.BudgetStartedAt.Equal(job.BudgetStartedAt) || !started.BudgetDeadlineAt.Equal(job.BudgetDeadlineAt) || *started.PricingBound != *job.PricingBound || !deadline.After(time.Now().Add(31*time.Second)) || operationCtx.Err() != nil {
				cancel()
				return nil, errWorkerExecution
			}
			providerRaw, sendErr := sendSecurityAgentOrdered(operationCtx, prepared, job.LookupRequest.CredentialDigest)
			cancel()
			if sendErr != nil {
				return nil, errWorkerExecution
			}
			raw, err = call("result", map[string]any{"raw": string(providerRaw)})
		case "started":
			// An unknown non-idempotent outcome is never re-sent on restart.
			cancel()
			return nil, errWorkerExecution
		case "completed":
			cancel()
			raw, err = call("settle", map[string]any{})
		case "settled":
			_, readErr := orderedPlanningArtifact(operationCtx, c.Store, scope, job.InputArtifactID, job.InputVersion, job.InputBody)
			if readErr != nil {
				cancel()
				return nil, errWorkerExecution
			}
			artifact, putErr := orderedPlanningArtifact(operationCtx, c.Store, scope, job.OutputArtifactID, "", job.OutputBody)
			cancel()
			if putErr != nil {
				return nil, errWorkerExecution
			}
			raw, err = call("artifacts", map[string]any{"input_version": job.InputVersion, "output_version": artifact.VersionID, "output_digest": job.OutputDigest})
		case "artifacts", "admitted":
			_, readErr := orderedPlanningArtifact(operationCtx, c.Store, scope, job.InputArtifactID, job.InputVersion, job.InputBody)
			if readErr == nil {
				_, readErr = orderedPlanningArtifact(operationCtx, c.Store, scope, job.OutputArtifactID, job.OutputVersion, job.OutputBody)
			}
			cancel()
			if readErr != nil {
				return nil, errWorkerExecution
			}
			receipt, admitErr := call("admit", map[string]any{})
			if admitErr != nil {
				return nil, errWorkerExecution
			}
			if !validOrderedPlanningReceipt(receipt, job, scope) {
				return nil, errWorkerExecution
			}
			return receipt, nil
		default:
			cancel()
			return nil, errWorkerExecution
		}
		if err != nil {
			return nil, errWorkerExecution
		}
	}
	if transitionsLimit == 1 {
		return raw, nil
	}
	return nil, errWorkerExecution
}

func orderedPlanningDigest(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// The decoder validates these fields before any operation context is created.
func mustOrderedPricingExpiry(job orderedPlanningJob) time.Time {
	if job.PricingBound == nil {
		return time.Time{}
	}
	expires, _ := time.Parse(multisteppricing.TimeFormat, job.PricingBound.Policy.ExpiresAt)
	return expires
}

func orderedPlanningDeadline(ctx context.Context, job orderedPlanningJob) time.Time {
	deadline := job.LeaseExpiresAt
	for _, limit := range []time.Time{job.BudgetDeadlineAt, mustOrderedPricingExpiry(job)} {
		if !limit.IsZero() && limit.Before(deadline) {
			deadline = limit
		}
	}
	if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
		deadline = caller
	}
	return deadline
}

func decodeOrderedPlanningJob(raw json.RawMessage, c orderedPlanningConfig) (orderedPlanningJob, securityAgentOrderedContext, domain.Scope, error) {
	var job orderedPlanningJob
	var value securityAgentOrderedContext
	var scope domain.Scope
	fail := func() (orderedPlanningJob, securityAgentOrderedContext, domain.Scope, error) {
		return orderedPlanningJob{}, value, scope, errWorkerExecution
	}
	fields, ok := securityAgentOrderedJSONObject(raw)
	if !ok || len(raw) > 524288 || len(fields) < 30 || len(fields) > 31 {
		return fail()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&job) != nil || !jsonDecoderAtEOF(decoder) || job.Scope != c.Selection.Scope || job.RunID != c.RunID || job.WorkerID != c.WorkerID || job.Attempt != 1 || job.RunVersion != 2 || !job.LeaseExpiresAt.After(time.Now()) || job.LeaseExpiresAt.After(time.Now().Add(301*time.Second)) || len(job.InputBody) > 65536 || orderedPlanningDigest([]byte(job.InputBody)) != job.InputDigest {
		return fail()
	}
	if job.InputSize != int64(len(job.InputBody)) {
		return fail()
	}
	o, err := domain.ParseProductID(job.OrganizationID)
	if err != nil {
		return fail()
	}
	w, err := domain.ParseProductID(job.WorkspaceID)
	if err != nil {
		return fail()
	}
	e, err := domain.ParseProductID(job.EnvironmentID)
	if err != nil {
		return fail()
	}
	scope, err = domain.NewScope(o, w, e)
	if err != nil {
		return fail()
	}
	for kind, actual := range map[string]string{"security_agent_planning_input": job.InputArtifactID, "security_agent_planning_output": job.OutputArtifactID, "security_agent_planning_reservation": job.ReservationID} {
		want, _ := apiserver.CanonicalDiscoveryID(scope, kind, job.RunID)
		if actual != want {
			return fail()
		}
	}
	var bodyContext, retainedContext any
	if json.Unmarshal([]byte(job.InputBody), &bodyContext) != nil || json.Unmarshal(job.ContextValue, &retainedContext) != nil {
		return fail()
	}
	a, _ := json.Marshal(bodyContext)
	b, _ := json.Marshal(retainedContext)
	if !bytes.Equal(a, b) {
		return fail()
	}
	var envelope struct {
		Definition struct {
			MaximumDurationSeconds int64 `json:"max_duration_seconds"`
		} `json:"definition"`
		Context struct {
			Purpose        string                             `json:"purpose"`
			OperatorGoal   string                             `json:"operator_goal"`
			CatalogVersion string                             `json:"catalog_version"`
			MaximumSteps   int                                `json:"maximum_steps"`
			AllowedActions []string                           `json:"allowed_actions"`
			AllowedTargets []string                           `json:"allowed_targets"`
			ExistingTest   *securityAgentOrderedTestReference `json:"existing_test"`
			Evidence       []securityAgentOrderedEvidence     `json:"untrusted_evidence"`
			Scope          multisteppricing.Scope             `json:"scope"`
			Run            struct {
				RunID             string `json:"run_id"`
				DefinitionID      string `json:"definition_id"`
				DefinitionVersion int64  `json:"definition_version"`
				Attempt           int    `json:"attempt"`
			} `json:"run"`
		} `json:"context"`
	}
	if json.Unmarshal(job.ContextValue, &envelope) != nil {
		return fail()
	}
	duration := envelope.Definition.MaximumDurationSeconds
	if duration < 1 || duration > 86400 || job.BudgetStartedAt.IsZero() || job.BudgetStartedAt.After(time.Now()) || !job.BudgetDeadlineAt.After(time.Now()) || !job.BudgetDeadlineAt.Equal(job.BudgetStartedAt.Add(time.Duration(duration)*time.Second)) {
		return fail()
	}
	v := envelope.Context
	value = securityAgentOrderedContext{Context: securityAgentOrderedPlannerContext{OrganizationID: v.Scope.OrganizationID, WorkspaceID: v.Scope.WorkspaceID, EnvironmentID: v.Scope.EnvironmentID, RunID: v.Run.RunID, DefinitionID: v.Run.DefinitionID, Purpose: v.Purpose, OperatorGoal: v.OperatorGoal, CatalogVersion: v.CatalogVersion, MaximumSteps: v.MaximumSteps, AllowedActions: v.AllowedActions, AllowedTargets: v.AllowedTargets, ExistingTest: v.ExistingTest, Evidence: v.Evidence}, Autonomy: "supervised", BudgetMaximumSteps: 2, DefinitionVersion: v.Run.DefinitionVersion, Attempt: v.Run.Attempt}
	if v.Scope != job.Scope || v.Run.RunID != job.RunID || v.Run.Attempt != job.Attempt || !validSecurityAgentOrderedContext(value) {
		return fail()
	}
	if job.State == "claimed" && (job.PricingBound != nil || job.LookupRequest != nil) {
		return fail()
	}
	if job.State != "claimed" {
		if job.LookupRequest == nil || job.PricingBound == nil || job.LookupRequest.Scope != job.Scope || job.RequestBody != job.LookupRequest.Body || job.RequestDigest != job.LookupRequest.BodyDigest || orderedPlanningDigest([]byte(job.RequestBody)) != job.RequestDigest || job.InputVersion == "" {
			return fail()
		}
		expires, expiryErr := time.Parse(multisteppricing.TimeFormat, job.PricingBound.Policy.ExpiresAt)
		effective, effectiveErr := time.Parse(multisteppricing.TimeFormat, job.PricingBound.Policy.EffectiveAt)
		if expiryErr != nil || effectiveErr != nil || expires.Format(multisteppricing.TimeFormat) != job.PricingBound.Policy.ExpiresAt || effective.Format(multisteppricing.TimeFormat) != job.PricingBound.Policy.EffectiveAt || !expires.After(time.Now()) || !expires.After(effective) || effective.After(time.Now()) {
			return fail()
		}
	}
	if job.RawResult != "" && (orderedPlanningDigest([]byte(job.RawResult)) != job.ProviderDigest || orderedPlanningDigest([]byte(job.OutputBody)) != job.OutputDigest) {
		return fail()
	}
	return job, value, scope, nil
}

func orderedPlanningPrepared(ctx context.Context, p *productionSecurityAgentPlanner, job orderedPlanningJob, value securityAgentOrderedContext) (*securityAgentOrderedPreparedPlan, error) {
	return orderedPlanningPreparedRequest(ctx, p, job.LookupRequest, job.RequestBody, job.RequestDigest, value)
}

func orderedPlanningPreparedRequest(ctx context.Context, p *productionSecurityAgentPlanner, q *multisteppricing.LookupRequest, body, digest string, value securityAgentOrderedContext) (*securityAgentOrderedPreparedPlan, error) {
	if q == nil || len(body) > 65536 {
		return nil, errWorkerExecution
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || p.model != q.Model || p.policyVersion != q.RequestPolicyVersion || int64(p.maximumTokens) != q.RequestTokenLimit || orderedPlanningDigest(p.token) != q.CredentialDigest {
		return nil, errWorkerExecution
	}
	return &securityAgentOrderedPreparedPlan{planner: p, preparationContext: ctx, contextValue: cloneSecurityAgentOrderedPlannerContext(value.Context), body: body, client: p.client, identity: securityAgentOrderedRequestIdentity{BodyDigest: digest, Model: p.model, Endpoint: p.endpoint, PolicyVersion: p.policyVersion, MaximumTokens: p.maximumTokens}}, nil
}

func orderedPlanningArtifact(ctx context.Context, store artifactstore.ArtifactStore, scope domain.Scope, id, version, body string) (artifactstore.Artifact, error) {
	pid, err := domain.ParseProductID(id)
	if err != nil || len(body) == 0 || len(body) > 524288 {
		return artifactstore.Artifact{}, errWorkerExecution
	}
	reference, err := domain.NewEvidenceRef(pid)
	if err != nil {
		return artifactstore.Artifact{}, errWorkerExecution
	}
	locator := artifactstore.Locator{Scope: scope, Reference: reference, VersionID: version}
	var a artifactstore.Artifact
	if version == "" {
		a, err = store.Put(ctx, artifactstore.PutRequest{Locator: locator, MediaType: "application/json", Body: []byte(body)})
		if err != nil {
			return artifactstore.Artifact{}, errWorkerExecution
		}
		locator.VersionID = a.VersionID
	}
	a, err = store.Get(ctx, locator)
	if err != nil || a.Locator != locator || a.VersionID == "" || a.MediaType != "application/json" || a.Size != int64(len(body)) || a.SHA256 != sha256.Sum256([]byte(body)) || !bytes.Equal(a.Body, []byte(body)) {
		return artifactstore.Artifact{}, errWorkerExecution
	}
	return a, nil
}

func validOrderedPlanningReceipt(raw json.RawMessage, job orderedPlanningJob, scope domain.Scope) bool {
	return validOrderedPlanningReceiptBinding(raw, scope, job.RunID, job.RunVersion, job.ReservationID)
}

func validOrderedPlanningReceiptBinding(raw json.RawMessage, scope domain.Scope, run string, runVersion int64, reservation string) bool {
	fields, ok := securityAgentOrderedClosedObject(raw, "contract_version", "outcome", "organization_id", "workspace_id", "environment_id", "run_id", "version", "plan_hash", "step_ids", "step_states", "approval_id", "dependency_id", "provider_reservation_id")
	if !ok {
		return false
	}
	var v struct {
		ContractVersion int    `json:"contract_version"`
		Outcome         string `json:"outcome"`
		multisteppricing.Scope
		RunID         string   `json:"run_id"`
		Version       int64    `json:"version"`
		PlanHash      string   `json:"plan_hash"`
		StepIDs       []string `json:"step_ids"`
		StepStates    []string `json:"step_states"`
		ApprovalID    string   `json:"approval_id"`
		DependencyID  string   `json:"dependency_id"`
		ReservationID string   `json:"provider_reservation_id"`
	}
	wantScope := multisteppricing.Scope{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String()}
	if json.Unmarshal(raw, &v) != nil || v.ContractVersion != 61 || v.Outcome != "admitted" || v.Scope != wantScope || v.RunID != run || v.Version != runVersion+1 || v.ReservationID != reservation || len(v.StepIDs) != 2 || string(fields["step_states"]) == "null" || len(v.StepStates) != 2 || v.StepStates[0] != "waiting_approval" || v.StepStates[1] != "dependency_blocked" || !providerAckPattern.MatchString(v.PlanHash) {
		return false
	}
	s0, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", run+"\x1f0")
	s1, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", run+"\x1f1")
	approval, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_approval", run+"\x1f"+s0)
	dependency, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_dependency", run+"\x1f"+s1)
	return v.StepIDs[0] == s0 && v.StepIDs[1] == s1 && v.ApprovalID == approval && v.DependencyID == dependency
}

// Called only after a positively acknowledged, committed private61 send permit.
// There is no provider idempotency guarantee. Never retry this operation after
// an error, crash, partial response or lost acknowledgement.
func sendSecurityAgentOrdered(ctx context.Context, prepared *securityAgentOrderedPreparedPlan, credential string) (raw []byte, err error) {
	defer func() {
		if recover() != nil {
			raw = nil
			err = errWorkerExecution
		}
	}()
	if ctx == nil || ctx.Err() != nil || prepared == nil {
		return nil, errWorkerExecution
	}
	current, ok := orderedPreparedCredential(prepared)
	if !ok || current != credential || !prepared.consumed.CompareAndSwap(false, true) {
		return nil, errWorkerExecution
	}
	p := prepared.planner
	p.mu.RLock()
	if p.closed || p.client != prepared.client || p.model != prepared.identity.Model || p.policyVersion != prepared.identity.PolicyVersion || p.maximumTokens != prepared.identity.MaximumTokens || p.endpoint != prepared.identity.Endpoint || orderedPlanningDigest(p.token) != credential {
		p.mu.RUnlock()
		return nil, errWorkerExecution
	}
	token := string(p.token)
	p.mu.RUnlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, prepared.identity.Endpoint, strings.NewReader(prepared.body))
	if err != nil {
		return nil, errWorkerExecution
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Zasp-Data-Policy", prepared.identity.PolicyVersion)
	response, err := prepared.client.Do(request)
	if err != nil || response == nil {
		return nil, errWorkerExecution
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errWorkerExecution
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, securityAgentPlannerResponseLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > securityAgentPlannerResponseLimit || !utf8.Valid(raw) || ctx.Err() != nil {
		return nil, errWorkerExecution
	}
	return raw, nil
}
