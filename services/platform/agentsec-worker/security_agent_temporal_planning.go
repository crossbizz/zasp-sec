package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This operation composes the real planner transport and object store with
// durable68 intent. Workflow registration remains separate. There is no worker
// lease, Activity-attempt identity, scheduler claim or resend on recovery.
func (p *productionSecurityAgentPlanner) RunTemporalPlanning(ctx context.Context, db apiserver.JSONDatabase, store artifactstore.ArtifactStore, selection securityAgentMultistepPricingBinding, run string, version int64) (json.RawMessage, error) {
	return p.runTemporalPlanning(ctx, db, store, selection, run, version, false)
}

// The family is chosen by production composition, never a workflow payload.
// Only the raw one-send transport and artifact accounting algorithm are shared.
func (p *productionSecurityAgentPlanner) RunSingleTestPlanning(ctx context.Context, db apiserver.JSONDatabase, store artifactstore.ArtifactStore, selection securityAgentMultistepPricingBinding, run string, version int64) (json.RawMessage, error) {
	return p.runTemporalPlanning(ctx, db, store, selection, run, version, true)
}

type temporalPlanningOwner uint8

const (
	temporalPlanningOrdered temporalPlanningOwner = iota
	temporalPlanningSingleTest
	temporalPlanningFinding
)

func (p *productionSecurityAgentPlanner) runTemporalPlanning(ctx context.Context, db apiserver.JSONDatabase, store artifactstore.ArtifactStore, selection securityAgentMultistepPricingBinding, run string, version int64, singleTest bool) (json.RawMessage, error) {
	owner := temporalPlanningOrdered
	if singleTest {
		owner = temporalPlanningSingleTest
	}
	return p.runTemporalPlanningOwned(ctx, db, store, selection, run, version, owner)
}

func (p *productionSecurityAgentPlanner) runTemporalPlanningOwned(ctx context.Context, db apiserver.JSONDatabase, store artifactstore.ArtifactStore, selection securityAgentMultistepPricingBinding, run string, version int64, owner temporalPlanningOwner) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(db) || nilWorkerDependency(store) || !release61PlannerAvailable(p, selection) || !validSecurityAgentPlannerProductID(run) || version < 1 || version > 1000000 {
		return nil, errWorkerExecution
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	query := func(callCtx context.Context, statement string, args ...any) (json.RawMessage, error) {
		bounded, done := context.WithTimeout(callCtx, 10*time.Second)
		defer done()
		return db.QueryJSON(bounded, statement, args...)
	}
	readySQL, readSQL, planSQL := `SELECT to_jsonb(zasp_temporal68.ready($1,$2))`, `SELECT zasp_temporal68.status($1::jsonb)->'planning'`, `SELECT zasp_temporal68.plan($1::jsonb)`
	checksum, fingerprint := migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint()
	validReceipt := validOrderedPlanningReceiptBinding
	if owner == temporalPlanningSingleTest {
		readySQL, readSQL, planSQL = `SELECT to_jsonb(zasp_temporal74.client_ready($1,$2))`, `SELECT zasp_temporal74.planning_state($1::jsonb)`, `SELECT zasp_temporal74.plan($1::jsonb)`
		checksum, fingerprint = migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint()
		validReceipt = validSingleTestPlanningReceipt
	}
	if owner == temporalPlanningFinding {
		readySQL, readSQL, planSQL = `SELECT to_jsonb(zasp_temporal78.client_ready($1,$2))`, `SELECT zasp_temporal78.planning_state($1::jsonb)`, `SELECT zasp_temporal78.plan($1::jsonb)`
		checksum, fingerprint = migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint()
		validReceipt = validFindingResponsePlanningReceipt
	}
	decodeJob := func(raw json.RawMessage) (temporalPlanningJob, securityAgentOrderedContext, domain.Scope, error) {
		return decodeTemporalPlanningJobOwned(raw, selection, run, version, owner)
	}
	ready, err := query(ctx, readySQL, checksum, fingerprint)
	if err != nil || !bytes.Equal(bytes.TrimSpace(ready), []byte("true")) {
		return nil, errWorkerExecution
	}
	identity := map[string]any{"organization_id": selection.OrganizationID, "workspace_id": selection.WorkspaceID, "environment_id": selection.EnvironmentID, "run_id": run, "definition_version": version}
	readAt := func(callCtx context.Context) (json.RawMessage, error) {
		raw, _ := json.Marshal(identity)
		return query(callCtx, readSQL, raw)
	}
	read := func() (json.RawMessage, error) { return readAt(ctx) }
	call := func(callCtx context.Context, op string, payload any) (json.RawMessage, error) {
		q := map[string]any{}
		for k, v := range identity {
			q[k] = v
		}
		q["operation"] = op
		if op != "load" {
			q["payload"] = payload
		}
		raw, _ := json.Marshal(q)
		return query(callCtx, planSQL, raw)
	}
	raw, err := read()
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		raw, err = call(ctx, "load", nil)
		if err != nil {
			return nil, err
		}
	}
	recoverKnown := func(body []byte) (json.RawMessage, error) {
		// An already-sent response must survive Activity cancellation. This
		// detached, bounded path can only reconcile that retained intent; it
		// cannot load, prepare, send, or admit a new plan.
		recoveryCtx, finish := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer finish()
		if recovery, ok := db.(capturedPlanningRecovery); ok {
			encoded, _ := json.Marshal(identity)
			if err := recovery.RecoverCapturedPlanning(recoveryCtx, encoded, body); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"outcome":"needs_human"}`), nil
		}
		priorRaw, err := readAt(recoveryCtx)
		if err != nil {
			return nil, err
		}
		prior, _, _, err := decodeJob(priorRaw)
		if err != nil {
			return nil, err
		}
		payload := map[string]any{}
		if len(body) > 0 && prior.State != "needs_human" {
			payload["raw"] = string(body)
		}
		if _, err := call(recoveryCtx, "reconcile", payload); err != nil {
			return nil, err
		}
		if prior.State == "needs_human" && len(body) > 0 && (prior.RawResult == "" || bytes.Contains(prior.ResultValue, []byte(`"usage": null`)) || bytes.Contains(prior.ResultValue, []byte(`"usage":null`))) {
			var response struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(body, &response) != nil || response.ID == "" || prior.LookupRequest == nil {
				return nil, errWorkerExecution
			}
			q := map[string]any{}
			for k, v := range identity {
				q[k] = v
			}
			q["operation"] = "late_usage"
			q["payload"] = map[string]any{"raw": string(body), "request_digest": prior.RequestDigest, "credential_digest": prior.LookupRequest.CredentialDigest, "reservation_id": prior.ReservationID, "response_id": response.ID, "response_digest": orderedPlanningDigest(body)}
			encoded, _ := json.Marshal(q)
			if owner != temporalPlanningOrdered {
				if _, err := query(recoveryCtx, planSQL, encoded); err != nil {
					return nil, err
				}
			} else {
				repository, err := apiserver.NewSecurityAgentTemporalExecutorRepository(db)
				if err != nil {
					return nil, err
				}
				if _, err := repository.TemporalPlannerLateUsage(recoveryCtx, encoded); err != nil {
					return nil, err
				}
			}
		}
		return readAt(recoveryCtx)
	}
	for n := 0; n < 8; n++ {
		if _, captured := db.(capturedPlanningRecovery); captured && bytes.Equal(bytes.TrimSpace(raw), []byte(`{"outcome":"needs_human"}`)) {
			return bytes.Clone(raw), nil
		}
		job, value, scope, err := decodeJob(raw)
		if err != nil {
			return nil, err
		}
		if job.State == "admitted" {
			if !validReceipt(job.Receipt, scope, run, job.RunVersion, job.ReservationID) {
				return nil, errWorkerExecution
			}
			return bytes.Clone(job.Receipt), nil
		}
		if job.State == "needs_human" {
			return json.RawMessage(`{"outcome":"needs_human"}`), nil
		}
		if job.State == "started" {
			raw, err = recoverKnown(nil)
			if err != nil {
				return nil, err
			}
			continue
		}
		deadline := job.BudgetDeadlineAt
		if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
			deadline = callerDeadline
		}
		if job.PricingBound != nil {
			expires, _ := time.Parse(multisteppricing.TimeFormat, job.PricingBound.Policy.ExpiresAt)
			if expires.Before(deadline) {
				deadline = expires
			}
		}
		if !deadline.After(time.Now()) {
			raw, err = recoverKnown(nil)
			if err != nil {
				return nil, err
			}
			continue
		}
		operationCtx, done := context.WithDeadline(ctx, deadline)
		switch job.State {
		case "loaded":
			artifact, putErr := orderedPlanningArtifact(operationCtx, store, scope, job.InputArtifactID, "", job.InputBody)
			if putErr != nil {
				done()
				return nil, putErr
			}
			p.mu.RLock()
			lookup := multisteppricing.LookupRequest{Scope: selection.Scope, Provider: "openrouter", Model: p.model, AccountProfile: selection.AccountProfile, CostUnit: "openrouter_credit", CredentialReference: selection.CredentialReference, CredentialDigest: orderedPlanningDigest(p.token), RequestPolicyVersion: p.policyVersion, RequestTokenLimit: int64(p.maximumTokens), PolicyID: selection.PolicyID, PolicyVersion: selection.PolicyVersion, PolicyDigest: selection.PolicyDigest, AccountID: selection.AccountID, AccountVersion: selection.AccountVersion}
			closed := p.closed
			p.mu.RUnlock()
			if closed {
				done()
				return nil, errWorkerExecution
			}
			encoded, _ := json.Marshal(lookup)
			var fields map[string]json.RawMessage
			json.Unmarshal(encoded, &fields)
			delete(fields, "body")
			delete(fields, "body_digest")
			raw, err = call(operationCtx, "prepare", map[string]any{"pricing": fields, "input_version": artifact.VersionID})
			if err != nil {
				done()
				// Projection lag or a changed proof is retryable. It does not
				// mean a captured unsent intent should be terminated.
				if errors.Is(err, authorization.ErrPending) || errors.Is(err, authorization.ErrConflict) {
					return nil, err
				}
				raw, err = recoverKnown(nil)
				if err != nil {
					return nil, err
				}
				continue
			}
		case "prepared":
			if _, err := orderedPlanningArtifact(operationCtx, store, scope, job.InputArtifactID, job.InputVersion, job.InputBody); err != nil {
				done()
				return nil, err
			}
			prepared, prepareErr := orderedPlanningPreparedRequest(operationCtx, p, job.LookupRequest, job.RequestBody, job.RequestDigest, value)
			if prepareErr != nil || !deadline.After(time.Now().Add(31*time.Second)) {
				done()
				raw, err = recoverKnown(nil)
				if err != nil {
					return nil, err
				}
				continue
			}
			startedRaw, startErr := call(operationCtx, "start", map[string]any{})
			if startErr != nil {
				done()
				// A server refusal did not commit this start. Reconciliation still
				// reads the durable state under locks before releasing anything.
				// An ambiguous transport failure is left for the next recovery call.
				var refusal interface{ SQLState() string }
				_, captured := db.(capturedPlanningRecovery)
				if errors.As(startErr, &refusal) && (refusal.SQLState() == "42501" || refusal.SQLState() == "40001") || captured && (errors.Is(startErr, authorization.ErrDenied) || errors.Is(startErr, authorization.ErrConflict)) {
					raw, err = recoverKnown(nil)
					if err != nil {
						return nil, err
					}
					continue
				}
				return nil, startErr
			}
			started, _, _, decodeErr := decodeJob(startedRaw)
			expected := job
			expected.State = "started"
			expected.SendPermit = started.SendPermit
			if decodeErr != nil || !reflect.DeepEqual(expected, started) || !deadline.After(time.Now().Add(31*time.Second)) {
				done()
				return nil, errWorkerExecution
			}
			if !started.SendPermit {
				done()
				raw, err = recoverKnown(nil)
				if err != nil {
					return nil, err
				}
				continue
			}
			providerRaw, sendErr := sendSecurityAgentOrdered(operationCtx, prepared, job.LookupRequest.CredentialDigest)
			if sendErr != nil {
				done()
				raw, err = recoverKnown(nil)
				if err != nil {
					return nil, err
				}
				continue
			}
			raw, err = call(operationCtx, "result", map[string]any{"raw": string(providerRaw)})
			if err != nil {
				done()
				raw, err = recoverKnown(providerRaw)
				if err != nil {
					return nil, err
				}
				continue
			}
		case "completed":
			raw, err = call(operationCtx, "settle", map[string]any{})
		case "settled":
			if _, err := orderedPlanningArtifact(operationCtx, store, scope, job.InputArtifactID, job.InputVersion, job.InputBody); err != nil {
				done()
				return nil, err
			}
			artifact, putErr := orderedPlanningArtifact(operationCtx, store, scope, job.OutputArtifactID, "", job.OutputBody)
			if putErr != nil {
				done()
				return nil, putErr
			}
			raw, err = call(operationCtx, "artifacts", map[string]any{"input_version": job.InputVersion, "output_version": artifact.VersionID, "output_digest": job.OutputDigest})
		case "artifacts":
			if _, err := orderedPlanningArtifact(operationCtx, store, scope, job.InputArtifactID, job.InputVersion, job.InputBody); err != nil {
				done()
				return nil, err
			}
			if _, err := orderedPlanningArtifact(operationCtx, store, scope, job.OutputArtifactID, job.OutputVersion, job.OutputBody); err != nil {
				done()
				return nil, err
			}
			receipt, admitErr := call(operationCtx, "admit", map[string]any{})
			done()
			if admitErr != nil || !validReceipt(receipt, scope, run, job.RunVersion, job.ReservationID) {
				return nil, errWorkerExecution
			}
			return receipt, nil
		default:
			done()
			return nil, errWorkerExecution
		}
		done()
		if err != nil {
			return nil, err
		}
	}
	return nil, errWorkerExecution
}

// Exact68 wire type: intentionally has no legacy lease/worker/attempt fields.
type temporalPlanningJob struct {
	multisteppricing.Scope
	RunID             string                          `json:"run_id"`
	DefinitionVersion int64                           `json:"definition_version"`
	RunVersion        int64                           `json:"run_version"`
	State             string                          `json:"state"`
	BudgetStartedAt   time.Time                       `json:"budget_started_at"`
	BudgetDeadlineAt  time.Time                       `json:"budget_deadline_at"`
	ContextValue      json.RawMessage                 `json:"context_value"`
	InputBody         string                          `json:"input_body"`
	InputDigest       string                          `json:"input_digest"`
	InputArtifactID   string                          `json:"input_artifact_id"`
	OutputArtifactID  string                          `json:"output_artifact_id"`
	ReservationID     string                          `json:"reservation_id"`
	RequestBody       string                          `json:"request_body"`
	RequestDigest     string                          `json:"request_digest"`
	LookupRequest     *multisteppricing.LookupRequest `json:"lookup_request"`
	PricingBound      *multisteppricing.Bound         `json:"pricing_bound"`
	InputVersion      string                          `json:"input_version"`
	RawResult         string                          `json:"raw_result"`
	ResultValue       json.RawMessage                 `json:"result_value"`
	ProviderDigest    string                          `json:"provider_digest"`
	OutputBody        string                          `json:"output_body"`
	OutputDigest      string                          `json:"output_digest"`
	OutputVersion     string                          `json:"output_version"`
	Receipt           json.RawMessage                 `json:"receipt"`
	SendPermit        bool                            `json:"send_permit,omitempty"`
}

func decodeTemporalPlanningJob(raw json.RawMessage, selection securityAgentMultistepPricingBinding, run string, version int64) (temporalPlanningJob, securityAgentOrderedContext, domain.Scope, error) {
	return decodeTemporalPlanningJobForOwner(raw, selection, run, version, false)
}

func decodeTemporalPlanningJobForOwner(raw json.RawMessage, selection securityAgentMultistepPricingBinding, run string, version int64, singleTest bool) (temporalPlanningJob, securityAgentOrderedContext, domain.Scope, error) {
	owner := temporalPlanningOrdered
	if singleTest {
		owner = temporalPlanningSingleTest
	}
	return decodeTemporalPlanningJobOwned(raw, selection, run, version, owner)
}

func decodeTemporalPlanningJobOwned(raw json.RawMessage, selection securityAgentMultistepPricingBinding, run string, version int64, owner temporalPlanningOwner) (temporalPlanningJob, securityAgentOrderedContext, domain.Scope, error) {
	var job temporalPlanningJob
	var value securityAgentOrderedContext
	var scope domain.Scope
	fail := func() (temporalPlanningJob, securityAgentOrderedContext, domain.Scope, error) {
		return temporalPlanningJob{}, value, scope, errWorkerExecution
	}
	fields, ok := securityAgentOrderedJSONObject(raw)
	if !ok || len(raw) > 524288 || len(fields) < 27 || len(fields) > 28 || !attackLabJSONKeys(json.NewDecoder(bytes.NewReader(raw)), nil, 0) || decodeStrictWorkerJSON(raw, &job) != nil || job.Scope != selection.Scope || job.RunID != run || job.DefinitionVersion != version || job.RunVersion != 2 || len(job.InputBody) == 0 || len(job.InputBody) > 65536 || orderedPlanningDigest([]byte(job.InputBody)) != job.InputDigest {
		return fail()
	}
	for _, k := range []string{"request_body", "request_digest", "lookup_request", "pricing_bound", "input_version", "raw_result", "result_value", "provider_digest", "output_body", "output_digest", "output_version", "receipt"} {
		if len(fields[k]) == 0 {
			return fail()
		}
	}
	for _, k := range []string{"organization_id", "workspace_id", "environment_id", "run_id", "definition_version", "run_version", "state", "budget_started_at", "budget_deadline_at", "context_value", "input_body", "input_digest", "input_artifact_id", "output_artifact_id", "reservation_id"} {
		if len(fields[k]) == 0 || bytes.Equal(bytes.TrimSpace(fields[k]), []byte("null")) {
			return fail()
		}
	}
	ids := make([]domain.ProductID, 3)
	var err error
	for i, id := range []string{job.OrganizationID, job.WorkspaceID, job.EnvironmentID} {
		ids[i], err = domain.ParseProductID(id)
		if err != nil {
			return fail()
		}
	}
	scope, err = domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		return fail()
	}
	for kind, actual := range map[string]string{"security_agent_planning_input": job.InputArtifactID, "security_agent_planning_output": job.OutputArtifactID, "security_agent_planning_reservation": job.ReservationID} {
		want, _ := apiserver.CanonicalDiscoveryID(scope, kind, run)
		if want != actual {
			return fail()
		}
	}
	var bodyContext, retainedContext any
	if json.Unmarshal([]byte(job.InputBody), &bodyContext) != nil || json.Unmarshal(job.ContextValue, &retainedContext) != nil || !reflect.DeepEqual(bodyContext, retainedContext) {
		return fail()
	}
	var envelope struct {
		Definition struct {
			MaximumDurationSeconds int64  `json:"max_duration_seconds"`
			Autonomy               string `json:"autonomy"`
		} `json:"definition"`
		Context struct {
			Purpose          string                             `json:"purpose"`
			OperatorGoal     string                             `json:"operator_goal"`
			CatalogVersion   string                             `json:"catalog_version"`
			MaximumSteps     int                                `json:"maximum_steps"`
			AllowedActions   []string                           `json:"allowed_actions"`
			AllowedTargets   []string                           `json:"allowed_targets"`
			AllowedAssignees []string                           `json:"allowed_assignees"`
			ExistingTest     *securityAgentOrderedTestReference `json:"existing_test"`
			Evidence         []securityAgentOrderedEvidence     `json:"untrusted_evidence"`
			ManualTrigger    json.RawMessage                    `json:"manual_trigger"`
			Scope            multisteppricing.Scope             `json:"scope"`
			Run              struct {
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
	if duration < 1 || duration > 86400 || job.BudgetStartedAt.IsZero() || job.BudgetStartedAt.After(time.Now()) || !job.BudgetDeadlineAt.Equal(job.BudgetStartedAt.Add(time.Duration(duration)*time.Second)) {
		return fail()
	}
	v := envelope.Context
	value = securityAgentOrderedContext{Context: securityAgentOrderedPlannerContext{OrganizationID: v.Scope.OrganizationID, WorkspaceID: v.Scope.WorkspaceID, EnvironmentID: v.Scope.EnvironmentID, RunID: v.Run.RunID, DefinitionID: v.Run.DefinitionID, Purpose: v.Purpose, OperatorGoal: v.OperatorGoal, CatalogVersion: v.CatalogVersion, MaximumSteps: v.MaximumSteps, AllowedActions: v.AllowedActions, AllowedTargets: v.AllowedTargets, ExistingTest: v.ExistingTest, Evidence: v.Evidence}, Autonomy: "supervised", BudgetMaximumSteps: 2, DefinitionVersion: v.Run.DefinitionVersion, Attempt: v.Run.Attempt}
	validContext := validSecurityAgentOrderedContext(value)
	if owner == temporalPlanningSingleTest {
		value.Autonomy, value.BudgetMaximumSteps, value.Context.ManualTrigger = envelope.Definition.Autonomy, 1, v.ManualTrigger
		validContext = validSingleTestPlanningContext(value)
	}
	if owner == temporalPlanningFinding {
		value.Autonomy, value.BudgetMaximumSteps = envelope.Definition.Autonomy, 1
		var contextFields map[string]json.RawMessage
		var envelopeFields map[string]json.RawMessage
		if json.Unmarshal(job.ContextValue, &envelopeFields) != nil || json.Unmarshal(envelopeFields["context"], &contextFields) != nil {
			return fail()
		}
		_, closed := securityAgentOrderedClosedObject(envelopeFields["context"], "purpose", "operator_goal", "catalog_version", "scope", "run", "maximum_steps", "allowed_actions", "allowed_targets", "allowed_assignees", "untrusted_evidence")
		validContext = closed && validFindingResponsePlanningContext(value, v.AllowedAssignees)
	}
	if v.Scope != job.Scope || v.Run.RunID != run || v.Run.DefinitionVersion != version || v.Run.Attempt != 1 || !validContext {
		return fail()
	}
	if job.State == "loaded" || job.State == "needs_human" && job.LookupRequest == nil {
		if job.LookupRequest != nil || job.PricingBound != nil || job.RequestBody != "" || job.RequestDigest != "" || job.InputVersion != "" || job.SendPermit || job.RawResult != "" || job.ProviderDigest != "" || job.OutputBody != "" || job.OutputDigest != "" || job.OutputVersion != "" || !bytes.Equal(bytes.TrimSpace(job.ResultValue), []byte("null")) || !bytes.Equal(bytes.TrimSpace(job.Receipt), []byte("null")) {
			return fail()
		}
	} else {
		if job.LookupRequest == nil || job.PricingBound == nil || job.LookupRequest.Scope != job.Scope || job.RequestBody != job.LookupRequest.Body || job.RequestDigest != job.LookupRequest.BodyDigest || orderedPlanningDigest([]byte(job.RequestBody)) != job.RequestDigest || job.InputVersion == "" {
			return fail()
		}
		q := job.LookupRequest
		if q.AccountProfile != selection.AccountProfile || q.CredentialReference != selection.CredentialReference || q.PolicyID != selection.PolicyID || q.PolicyVersion != selection.PolicyVersion || q.PolicyDigest != selection.PolicyDigest || q.AccountID != selection.AccountID || q.AccountVersion != selection.AccountVersion {
			return fail()
		}
		if _, err := multisteppricing.ValidateBound(fields["pricing_bound"], *q); err != nil {
			return fail()
		}
	}
	switch job.State {
	case "loaded", "prepared", "started", "completed", "settled", "artifacts", "admitted", "needs_human":
	default:
		return fail()
	}
	if job.SendPermit && job.State != "started" {
		return fail()
	}
	if job.RawResult != "" && (orderedPlanningDigest([]byte(job.RawResult)) != job.ProviderDigest || orderedPlanningDigest([]byte(job.OutputBody)) != job.OutputDigest) {
		return fail()
	}
	if (job.State == "completed" || job.State == "settled" || job.State == "artifacts" || job.State == "admitted") && (job.RawResult == "" || len(job.ResultValue) == 0 || string(job.ResultValue) == "null") {
		return fail()
	}
	if (job.State == "artifacts" || job.State == "admitted") && job.OutputVersion == "" {
		return fail()
	}
	return job, value, scope, nil
}
