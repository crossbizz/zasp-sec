package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// All resource bodies and provider results stay in this Activity-side adapter.
// Each method binds immutable admission again before touching a product effect.
type temporalSecurityAgentProduct struct {
	executor, compensation            apiserver.JSONDatabase
	workerForward, workerCompensation *authorization.WorkerExecutor
	planner                           *productionSecurityAgentPlanner
	runner                            *productionRedTeamRunner
	store                             artifactstore.ArtifactStore
	bindings                          []securityAgentMultistepPricingBinding
	signing                           func() (string, ed25519.PrivateKey, policy.GatewayPolicyKeys, error)
	orderedPolicyKeyID                string
	orderedPolicyKeys                 policy.GatewayPolicyKeys
	orderedPolicySigner               authorization.OrderedPolicySigner
	workerID                          string
	singleTestEnabled                 bool
	findingResponseEnabled            bool
	testSelectorEnabled               bool
	automaticSourcesEnabled           bool
	singleTestDiagnostic              func(orchestration.SingleTestProduct) orchestration.SingleTestProduct
}
type temporalProductState struct {
	Start struct {
		OrganizationID    string `json:"organization_id"`
		WorkspaceID       string `json:"workspace_id"`
		EnvironmentID     string `json:"environment_id"`
		RunID             string `json:"run_id"`
		DefinitionVersion int64  `json:"definition_version"`
		InputDigest       string `json:"input_digest"`
	} `json:"start"`
	StartEventID    string  `json:"start_event_id"`
	RunState        string  `json:"run_state"`
	RunVersion      int64   `json:"run_version"`
	Admitted        bool    `json:"admitted"`
	PlanningState   *string `json:"planning_state"`
	Terminal        bool    `json:"terminal"`
	CleanupRequired bool    `json:"cleanup_required"`
	Projection      struct {
		OrganizationID    string `json:"organization_id"`
		WorkspaceID       string `json:"workspace_id"`
		EnvironmentID     string `json:"environment_id"`
		RunID             string `json:"run_id"`
		DefinitionID      string `json:"definition_id"`
		DefinitionVersion int64  `json:"definition_version"`
		ContractVersion   int    `json:"contract_version"`
		State             string `json:"state"`
		Version           int64  `json:"version"`
		Admitted          bool   `json:"admitted"`
		Verification      string `json:"verification"`
		Steps             []struct {
			StepID     string `json:"step_id"`
			Index      int    `json:"index"`
			Action     string `json:"action"`
			State      string `json:"state"`
			Version    int64  `json:"version"`
			Dependency struct {
				Predecessor *string `json:"predecessor_step_id"`
				Required    *string `json:"required_receipt_kind"`
				Satisfied   bool    `json:"satisfied"`
				Blocked     bool    `json:"blocked"`
				Ready       bool    `json:"ready"`
			} `json:"dependency"`
			Authorization json.RawMessage `json:"authorization"`
			Approval      json.RawMessage `json:"approval"`
			Receipt       *struct {
				Kind      string `json:"kind"`
				Version   int64  `json:"version"`
				Digest    string `json:"digest"`
				Reference string `json:"reference"`
			} `json:"receipt"`
			Settlement string          `json:"settlement"`
			Cleanup    json.RawMessage `json:"cleanup"`
		} `json:"steps"`
	} `json:"projection"`
	Effects []struct {
		StepID     string `json:"step_id"`
		State      string `json:"state"`
		Action     string `json:"action_key"`
		EffectKey  string `json:"effect_key"`
		Generation int64  `json:"generation"`
	} `json:"effects"`
	Markers []struct {
		DeviceID     string    `json:"device_id"`
		SourceDigest string    `json:"source_digest"`
		ExpiresAt    time.Time `json:"expires_at"`
	} `json:"cleanup_markers"`
}

func temporalStartFields(q orchestration.StartRequest) map[string]any {
	return map[string]any{"organization_id": q.Ref.OrganizationID, "workspace_id": q.Ref.WorkspaceID, "environment_id": q.Ref.EnvironmentID, "run_id": q.Ref.RunID, "definition_version": q.DefinitionVersion, "input_digest": q.InputDigest}
}
func temporalEffectFields(q orchestration.StartRequest, step, op string, payload any) map[string]any {
	v := temporalStartFields(q)
	delete(v, "definition_version")
	delete(v, "input_digest")
	v["step_id"], v["generation"], v["operation"], v["payload"] = step, 1, op, payload
	return v
}
func temporalQuery(ctx context.Context, db apiserver.JSONDatabase, sql string, q any) (json.RawMessage, error) {
	if ctx == nil || nilWorkerDependency(db) {
		return nil, orchestration.ErrInvalid
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return nil, orchestration.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return db.QueryJSON(bounded, sql, json.RawMessage(raw))
}
func (p *temporalSecurityAgentProduct) inspect(ctx context.Context, q orchestration.StartRequest, db apiserver.JSONDatabase) (temporalProductState, error) {
	var v temporalProductState
	if _, err := orchestration.WorkflowID(q.Ref); err != nil {
		return v, err
	}
	raw, err := p.lifecycleQuery(ctx, db, `SELECT zasp_temporal69.inspect($1::jsonb)`, q.Ref, temporalStartFields(q))
	if err != nil {
		return v, err
	}
	if len(raw) > 32768 || decodeStrictWorkerJSON(raw, &v) != nil || v.Start.OrganizationID != q.Ref.OrganizationID || v.Start.WorkspaceID != q.Ref.WorkspaceID || v.Start.EnvironmentID != q.Ref.EnvironmentID || v.Start.RunID != q.Ref.RunID || v.Start.DefinitionVersion != q.DefinitionVersion || v.Start.InputDigest != q.InputDigest || !validSecurityAgentPlannerProductID(v.StartEventID) || v.RunVersion < 1 || v.Projection.RunID != q.Ref.RunID || v.Projection.OrganizationID != q.Ref.OrganizationID || v.Projection.WorkspaceID != q.Ref.WorkspaceID || v.Projection.EnvironmentID != q.Ref.EnvironmentID || v.Projection.DefinitionVersion != q.DefinitionVersion || v.Projection.State != v.RunState || v.Projection.Version != v.RunVersion || v.Projection.Admitted != v.Admitted || len(v.Effects) > 2 || len(v.Markers) > 100 {
		return v, orchestration.ErrConflict
	}
	if v.Admitted && len(v.Projection.Steps) != 2 || !v.Admitted && len(v.Projection.Steps) != 0 {
		return v, orchestration.ErrConflict
	}
	return v, nil
}
func temporalPhase(v temporalProductState) (string, error) {
	if v.Terminal {
		return "terminal", nil
	}
	if !v.Admitted {
		if v.RunState == "queued" || v.RunState == "planning" {
			return "planning", nil
		}
		return "", orchestration.ErrConflict
	}
	a, b := v.Projection.Steps[0], v.Projection.Steps[1]
	if a.Index != 0 || a.Action != "create_temporary_policy" || b.Index != 1 || b.Action != "run_test" {
		return "", orchestration.ErrConflict
	}
	if a.State == "waiting_approval" || a.State == "succeeded" && b.State == "waiting_approval" {
		if a.State == "waiting_approval" && !a.Dependency.Ready || b.State == "waiting_approval" && !b.Dependency.Ready {
			return "permission_lost", nil
		}
		return "waiting_approval", nil
	}
	if a.State == "authorized" || a.State == "executing" {
		return "apply", nil
	}
	if a.State != "succeeded" || a.Receipt == nil || a.Receipt.Kind != "temporary_policy_applied.v1" || !b.Dependency.Satisfied {
		return "", orchestration.ErrConflict
	}
	if b.State == "blocked" {
		return "advance", nil
	}
	if b.State == "authorized" || b.State == "executing" {
		return "test", nil
	}
	return "pending", nil
}
func temporalProductError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, apiserver.ErrRepositoryOperation) || errors.Is(err, apiserver.ErrRepositoryNotFound) || errors.Is(err, authorization.ErrDenied) || errors.Is(err, authorization.ErrInvalid) {
		return orchestration.ErrInvalid
	}
	// Pending projections and changed revisions need a fresh authority check.
	// They remain retryable; no database or provider detail enters history.
	return err
}
func (p *temporalSecurityAgentProduct) Observe(ctx context.Context, q orchestration.StartRequest) (state orchestration.RunState, result error) {
	defer func() { result = temporalProductError(ctx, result) }()
	v, err := p.inspect(ctx, q, p.executor)
	if err != nil {
		return orchestration.RunState{}, err
	}
	phase, err := temporalPhase(v)
	return orchestration.RunState{Phase: phase}, err
}
func (p *temporalSecurityAgentProduct) Plan(ctx context.Context, q orchestration.StartRequest) (result error) {
	defer func() { result = temporalProductError(ctx, result) }()
	v, err := p.inspect(ctx, q, p.executor)
	if err != nil {
		return err
	}
	phase, err := temporalPhase(v)
	if err != nil {
		return err
	}
	if phase != "planning" {
		return nil
	}
	for _, selection := range p.bindings {
		if selection.OrganizationID == q.Ref.OrganizationID && selection.WorkspaceID == q.Ref.WorkspaceID && selection.EnvironmentID == q.Ref.EnvironmentID {
			_, err := p.planner.RunTemporalPlanning(ctx, p.executor, p.store, selection, q.Ref.RunID, q.DefinitionVersion)
			return err
		}
	}
	return orchestration.ErrInvalid
}
func (p *temporalSecurityAgentProduct) Advance(ctx context.Context, q orchestration.StartRequest) (result error) {
	defer func() { result = temporalProductError(ctx, result) }()
	v, err := p.inspect(ctx, q, p.executor)
	if err != nil {
		return err
	}
	phase, err := temporalPhase(v)
	if err != nil {
		return err
	}
	if phase != "advance" {
		return nil
	}
	fields := temporalStartFields(q)
	delete(fields, "definition_version")
	delete(fields, "input_digest")
	fields["step_id"], fields["operation"], fields["actor_id"], fields["run_version"], fields["approval_version"], fields["fresh_auth_at"] = v.Projection.Steps[1].StepID, "progress", p.workerID, v.RunVersion, 1, time.Now().UTC().Format(time.RFC3339Nano)
	_, err = temporalQuery(ctx, p.orderedTestDatabase(q), `SELECT zasp_temporal68.progress($1::jsonb)`, fields)
	return err
}
func temporalScope(q orchestration.StartRequest) (domain.Scope, error) {
	o, err := domain.ParseProductID(q.Ref.OrganizationID)
	if err != nil {
		return domain.Scope{}, err
	}
	w, err := domain.ParseProductID(q.Ref.WorkspaceID)
	if err != nil {
		return domain.Scope{}, err
	}
	e, err := domain.ParseProductID(q.Ref.EnvironmentID)
	if err != nil {
		return domain.Scope{}, err
	}
	return domain.NewScope(o, w, e)
}
func (p *temporalSecurityAgentProduct) Test(ctx context.Context, q orchestration.StartRequest) (result error) {
	defer func() { result = temporalProductError(ctx, result) }()
	v, err := p.inspect(ctx, q, p.executor)
	if err != nil {
		return err
	}
	phase, err := temporalPhase(v)
	if err != nil {
		return err
	}
	if phase != "test" {
		return nil
	}
	scope, err := temporalScope(q)
	if err != nil {
		return err
	}
	_, err = p.runner.RunTemporalTest(ctx, p.orderedTestDatabase(q), scope, q.Ref.RunID, v.Projection.Steps[1].StepID, q.DefinitionVersion)
	return err
}
func (p *temporalSecurityAgentProduct) Apply(ctx context.Context, q orchestration.StartRequest) (result error) {
	defer func() { result = temporalProductError(ctx, result) }()
	v, err := p.inspect(ctx, q, p.executor)
	if err != nil {
		return err
	}
	phase, err := temporalPhase(v)
	if err != nil {
		return err
	}
	if phase != "apply" {
		return nil
	}
	step := v.Projection.Steps[0].StepID
	found := false
	effectDB := p.executor
	if p.workerForward != nil || p.workerCompensation != nil {
		capture, err := json.Marshal(temporalEffectFields(q, step, "reserve", map[string]any{}))
		if err != nil {
			return orchestration.ErrInvalid
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = p.workerForward.PrepareOrdered68Operation(bounded, "ordered68.effect.reserve", capture)
		cancel()
		if err != nil {
			return err
		}
		effectDB = &workerOrderedPolicyDatabase{forward: p.workerForward, compensation: p.workerCompensation, start: q, step: step}
	}
	for _, effect := range v.Effects {
		if effect.StepID == step {
			found = true
		}
	}
	if !found {
		if _, err := temporalQuery(ctx, effectDB, `SELECT zasp_temporal68.effect($1::jsonb)`, temporalEffectFields(q, step, "reserve", map[string]any{})); err != nil {
			return err
		}
	}
	if _, err := temporalQuery(ctx, effectDB, `SELECT zasp_temporal68.effect($1::jsonb)`, temporalEffectFields(q, step, "start", map[string]any{})); err != nil {
		return err
	}
	return p.policy(ctx, q, step, false, v)
}
func (p *temporalSecurityAgentProduct) Cleanup(ctx context.Context, q orchestration.CleanupRequest) (result error) {
	defer func() { result = temporalProductError(ctx, result) }()
	v, err := p.inspect(ctx, q.Start, p.compensation)
	if err != nil {
		return err
	}
	if q.Reason != "terminal" {
		fields := temporalStartFields(q.Start)
		fields["reason"] = q.Reason
		if _, err := p.lifecycleQuery(ctx, p.compensation, `SELECT zasp_temporal69.stop($1::jsonb)`, q.Start.Ref, fields); err != nil {
			return err
		}
		v, err = p.inspect(ctx, q.Start, p.compensation)
		if err != nil {
			return err
		}
	}
	if !v.Terminal {
		return orchestration.ErrConflict
	}
	if !v.CleanupRequired {
		return nil
	}
	step := v.Projection.Steps[0].StepID
	cleanupDB := p.compensation
	if p.workerForward != nil || p.workerCompensation != nil {
		cleanupDB = &workerOrderedPolicyDatabase{forward: p.workerForward, compensation: p.workerCompensation, start: q.Start, step: step, cleanup: true}
	}
	if _, err := temporalQuery(ctx, cleanupDB, `SELECT zasp_temporal68.cleanup($1::jsonb)`, temporalEffectFields(q.Start, step, "prepare", map[string]any{})); err != nil {
		return err
	}
	v, err = p.inspect(ctx, q.Start, p.compensation)
	if err != nil {
		return err
	}
	return p.policy(ctx, q.Start, step, true, v)
}

func (p *temporalSecurityAgentProduct) policy(ctx context.Context, q orchestration.StartRequest, step string, cleanup bool, state temporalProductState) error {
	if p == nil {
		return orchestration.ErrInvalid
	}
	named := p.workerForward != nil || p.workerCompensation != nil
	var keyID string
	var key ed25519.PrivateKey
	var keys policy.GatewayPolicyKeys
	if named {
		if p.workerForward == nil || p.workerCompensation == nil || p.orderedPolicySigner == nil || !p.orderedPolicyKeys.HasKeyID(p.orderedPolicyKeyID) {
			return orchestration.ErrInvalid
		}
		keyID, keys = p.orderedPolicyKeyID, p.orderedPolicyKeys
	} else {
		if p.signing == nil {
			return orchestration.ErrInvalid
		}
		var err error
		keyID, key, keys, err = p.signing()
		defer clear(key)
		if err != nil {
			return err
		}
		if len(key) != ed25519.PrivateKeySize || !keys.Valid() {
			return orchestration.ErrInvalid
		}
	}
	db, phase, sql := p.executor, "apply", `SELECT zasp_temporal68.application($1::jsonb)`
	if cleanup {
		db, phase, sql = p.compensation, "cleanup", `SELECT zasp_temporal68.cleanup($1::jsonb)`
	}
	if named {
		db = &workerOrderedPolicyDatabase{forward: p.workerForward, compensation: p.workerCompensation, start: q, step: step, cleanup: cleanup}
	}
	repo, err := apiserver.NewSecurityAgentTemporalExecutorRepository(db)
	if err != nil {
		return err
	}
	source := repo.TemporalApplication
	if cleanup {
		source = repo.TemporalCleanupSource
	}
	fields := func(op string, payload any) json.RawMessage {
		raw, _ := json.Marshal(temporalEffectFields(q, step, op, payload))
		return raw
	}
	raw, err := source(ctx, fields("read", map[string]any{}), keys)
	if err != nil {
		return err
	}
	var targets struct {
		TTL     int               `json:"ttl_seconds"`
		Targets []release61Source `json:"targets"`
	}
	if json.Unmarshal(raw, &targets) != nil || targets.TTL < 60 || targets.TTL > 3600 || len(targets.Targets) < 1 {
		return orchestration.ErrConflict
	}
	sign := func(device string, seq int64, expires time.Time, policies []policy.CompiledPolicy) (policy.GatewayPolicyEnvelope, error) {
		now := time.Now().UTC().Truncate(time.Second)
		return policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: keyID, Binding: policy.GatewayPolicyBinding{OrganizationID: q.Ref.OrganizationID, WorkspaceID: q.Ref.WorkspaceID, EnvironmentID: q.Ref.EnvironmentID, DeviceID: device}, Sequence: uint64(seq), PolicyVersion: uint64(seq), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: policies}, key)
	}
	for _, target := range targets.Targets {
		renew := false
		if cleanup && target.State != "planned" {
			for _, marker := range state.Markers {
				if marker.DeviceID == target.DeviceID && !marker.ExpiresAt.After(time.Now()) {
					renew = true
				}
			}
		}
		if named && (target.State == "planned" || renew) {
			op := "ordered68.application.source"
			nativeOp := "source"
			payload := map[string]any{"device_id": target.DeviceID}
			if cleanup {
				op = "ordered68.cleanup.source"
			}
			if renew {
				op, nativeOp = "ordered68.cleanup.renew", "renew"
				payload["source_digest"] = target.EnvelopeDigest
			}
			if _, err := p.signOrderedPolicy(ctx, authorization.WorkerOperation(op), fields(nativeOp, payload), cleanup); err != nil {
				return err
			}
		} else if target.State == "planned" || renew {
			policies, err := temporaryContainmentPolicies("create_temporary_policy", "", phase)
			if err != nil {
				return err
			}
			envelope, err := sign(target.DeviceID, target.Sequence, time.Now().UTC().Truncate(time.Second).Add(time.Duration(targets.TTL)*time.Second), policies)
			if err != nil {
				return err
			}
			converted, err := temporaryPolicyRepositoryEnvelope(apiserver.TemporaryPolicyTarget{DeviceID: target.DeviceID, CredentialID: target.CredentialID, Sequence: target.Sequence, PolicyVersion: target.PolicyVersion}, phase, envelope)
			if err != nil {
				return err
			}
			payload := map[string]any{"device_id": target.DeviceID, "credential_id": target.CredentialID, "sequence": target.Sequence, "policy_version": target.PolicyVersion, "key_id": converted.KeyID, "issued_at": converted.IssuedAt, "expires_at": converted.ExpiresAt, "failure_mode": converted.FailureMode, "payload_digest": converted.PayloadDigest, "policies": converted.Policies, "signature": base64.StdEncoding.EncodeToString(converted.Signature), "envelope_digest": converted.EnvelopeDigest}
			op := "source"
			if renew {
				op = "renew"
				payload = map[string]any{"source_digest": target.EnvelopeDigest, "envelope": payload}
			}
			if _, err := source(ctx, fields(op, payload), keys); err != nil {
				return err
			}
		}
		payload := map[string]any{"device_id": target.DeviceID, "phase": phase}
		delivery, err := repo.TemporalDelivery(ctx, fields("prepare", payload), keys)
		if err != nil {
			return err
		}
		var d struct {
			State       string `json:"state"`
			Sequence    int64  `json:"sequence"`
			Digest      string `json:"envelope_digest"`
			Composition struct {
				Policies  []policy.CompiledPolicy `json:"policies"`
				ExpiresAt time.Time               `json:"expires_at"`
			} `json:"composition"`
		}
		if json.Unmarshal(delivery, &d) != nil {
			return orchestration.ErrConflict
		}
		if named && d.State == "prepared" {
			op := "ordered68.delivery.apply.store"
			if cleanup {
				op = "ordered68.delivery.cleanup.store"
			}
			stored, err := p.signOrderedPolicy(ctx, authorization.WorkerOperation(op), fields("store", payload), cleanup)
			if err != nil {
				return err
			}
			var result struct {
				Digest string `json:"envelope_digest"`
			}
			if json.Unmarshal(stored, &result) != nil {
				return orchestration.ErrConflict
			}
			// Repository readback below verifies the stored composition and
			// signature before any acknowledgement is permitted.
			d.Digest = "sha256:" + strings.TrimPrefix(result.Digest, "\\x")
			payload["digest"] = d.Digest
		} else if d.State == "prepared" {
			envelope, err := sign(target.DeviceID, d.Sequence, d.Composition.ExpiresAt, d.Composition.Policies)
			if err != nil {
				return err
			}
			signed, _ := json.Marshal(envelope)
			payload["envelope"], payload["digest"] = envelope, orderedPlanningDigest(signed)
			if _, err := repo.TemporalDelivery(ctx, fields("store", payload), keys); err != nil {
				return err
			}
			d.Digest = payload["digest"].(string)
			delete(payload, "envelope")
		} else {
			d.Digest = "sha256:" + strings.TrimPrefix(d.Digest, "\\x")
			payload["digest"] = d.Digest
		}
		if _, err := repo.TemporalDelivery(ctx, fields("read", payload), keys); err != nil {
			return err
		}
		if _, err := repo.TemporalDelivery(ctx, fields("ack", payload), keys); err != nil {
			return err
		}
	}
	completed, err := temporalQuery(ctx, db, sql, temporalEffectFields(q, step, "complete", map[string]any{}))
	if err != nil {
		return err
	}
	if cleanup {
		var receipt struct {
			State string `json:"state"`
		}
		if json.Unmarshal(completed, &receipt) != nil || receipt.State != "cleaned" {
			return orchestration.ErrConflict
		}
	} else if !bytes.Contains(completed, []byte(`"temporary_policy_applied.v1"`)) {
		return orchestration.ErrConflict
	}
	inspectDB := p.executor
	if cleanup {
		inspectDB = p.compensation
	}
	_, err = p.inspect(ctx, q, inspectDB)
	return err
}

func (p *temporalSecurityAgentProduct) signOrderedPolicy(ctx context.Context, operation authorization.WorkerOperation, request json.RawMessage, cleanup bool) (json.RawMessage, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nil, authorization.ErrInvalid
	}
	executor := p.workerForward
	if cleanup {
		executor = p.workerCompensation
	}
	if executor == nil || p.orderedPolicySigner == nil || !p.orderedPolicyKeys.HasKeyID(p.orderedPolicyKeyID) {
		return nil, authorization.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !cleanup {
		if err := executor.PrepareOrdered68Operation(bounded, operation, request); err != nil {
			return nil, err
		}
	}
	decision, err := executor.Authorize(bounded, operation, request)
	if err != nil {
		return nil, err
	}
	return executor.SignOrderedPolicy(bounded, decision, p.orderedPolicyKeyID, p.orderedPolicyKeys, p.orderedPolicySigner)
}
