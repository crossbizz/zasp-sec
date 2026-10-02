package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// Dormant explicit composition. No default worker constructs this runtime.
type securityAgentRelease61Runtime struct {
	composition                              *apiserver.SecurityAgentRelease61Composition
	planning                                 orderedPlanningConfig
	deploymentWorkerID, deploymentLeaseToken string
	keyID                                    string
	privateKey                               ed25519.PrivateKey
	testRunner                               *productionRedTeamRunner
	journal                                  *redteamadapter.PostgresInvocationJournal
	DeploymentLeaseDuration                  time.Duration
}

func (r *securityAgentRelease61Runtime) deploymentLeaseSeconds() (int, error) {
	if r == nil {
		return 0, errWorkerExecution
	}
	duration := r.DeploymentLeaseDuration
	if duration == 0 {
		return 300, nil
	}
	if duration < 30*time.Second || duration > 300*time.Second || duration%time.Second != 0 {
		return 0, errWorkerExecution
	}
	return int(duration / time.Second), nil
}

func (r *securityAgentRelease61Runtime) Tick(ctx context.Context) (string, error) {
	if ctx == nil || ctx.Err() != nil || r.preflight() != nil {
		return "", errWorkerExecution
	}
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if r.journal == nil || r.journal.Ready(bounded) != nil {
		return "", errWorkerExecution
	}
	state, err := r.read(bounded)
	if err != nil {
		return "", errWorkerExecution
	}
	transition := ""
	if !state.Admitted {
		if state.RunState == "needs_human" {
			return "terminal", nil
		}
		if state.RunState == "queued" && state.Planning.State == "" {
			_, err = advanceSecurityAgentOrderedPlanning(bounded, r.planning, 0)
			transition = "planning_claim"
		} else if state.RunState == "planning" {
			if !state.Planning.Owned {
				if state.Planning.LeaseExpiresAt.IsZero() {
					return "", errWorkerExecution
				}
				if state.Planning.LeaseExpiresAt.After(time.Now()) {
					return "lease_wait", nil
				}
				q := r.scopeRequest()
				q["worker_id"], q["lease_token"], q["operation"], q["payload"] = r.planning.WorkerID, r.planning.LeaseToken, "reconcile", map[string]any{}
				raw, _ := json.Marshal(q)
				_, err = (&orderedPlanningSQLDatabase{Database: r.planning.Database, parent: bounded}).QueryJSON(bounded, `SELECT zasp_sa_multistep_prior.planning($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), json.RawMessage(raw))
				transition = "planning_reconcile"
			} else {
				switch state.Planning.State {
				case "claimed":
					transition = "planning_prepare"
				case "prepared":
					transition = "planning_result"
				case "completed":
					transition = "planning_settle"
				case "settled":
					transition = "planning_artifacts"
				case "artifacts":
					transition = "planning_admit"
				case "started":
					return "uncertain_wait", nil
				default:
					return "", errWorkerExecution
				}
				_, err = advanceSecurityAgentOrderedPlanning(bounded, r.planning, 1)
			}
		} else {
			return "", errWorkerExecution
		}
	} else if state.StopRequired && len(state.Steps) == 2 {
		q := r.scopeRequest()
		q["step_id"], q["operation"], q["actor_id"], q["run_version"], q["approval_version"], q["fresh_auth_at"] = state.Steps[1].StepID, "stop", r.planning.WorkerID, state.RunVersion, 1, time.Now().UTC().Format(time.RFC3339Nano)
		err = r.call(bounded, r.composition.Stop, q)
		transition = "stopped"
	} else if len(state.Steps) == 2 && stringInWorker(state.RunState, "contained", "needs_human", "cancelled", "failed", "inconclusive", "remediated") {
		if state.Cleanup.State == "cleaned" {
			return "terminal", nil
		}
		pending := false
		for _, target := range state.Application.Targets {
			if target.State == "stored" || target.State == "verified" {
				pending = true
			}
		}
		if !pending {
			return "terminal", nil
		}
		if expiry, parseErr := time.Parse(time.RFC3339Nano, state.Application.Delivery.LeaseExpiresAt); parseErr == nil && expiry.After(time.Now()) {
			return "lease_wait", nil
		}
		transition, err = r.applicationTick(bounded, state, true)
	} else if len(state.Steps) == 2 && (state.Steps[0].State == "waiting_approval" || state.Steps[0].State == "succeeded" && state.Steps[1].State == "waiting_approval") {
		return "approval_pause", nil
	} else if len(state.Steps) == 2 && (state.Steps[0].State == "authorized" || state.Steps[0].State == "executing") {
		transition, err = r.applicationTick(bounded, state)
	} else if len(state.Steps) == 2 && state.Steps[0].State == "succeeded" && state.Steps[1].State == "queued" {
		q := r.scopeRequest()
		q["step_id"], q["operation"], q["actor_id"], q["run_version"], q["approval_version"], q["fresh_auth_at"] = state.Steps[1].StepID, "progress", r.planning.WorkerID, state.RunVersion, 1, time.Now().UTC().Format(time.RFC3339Nano)
		err = r.call(bounded, r.composition.Progress, q)
		transition = "successor_ready"
	} else if len(state.Steps) == 2 && (state.Steps[1].State == "authorized" || state.Steps[1].State == "executing") {
		transition, err = r.testTick(bounded, state)
	} else {
		return "", errWorkerExecution
	}
	if err != nil {
		return "", errWorkerExecution
	}
	// Every successful commit is followed by a fresh scoped read. Its output is
	// deliberately not cached on the runtime; the next tick starts over in SQL.
	if _, err = r.read(bounded); err != nil {
		return "", errWorkerExecution
	}
	return transition, nil
}

// preflight is deliberately local: it must complete before journal readiness,
// authoritative state reads, claims, mutations, artifact I/O or provider I/O.
func (r *securityAgentRelease61Runtime) preflight() error {
	if r == nil || r.composition == nil || r.journal == nil || !r.journal.ValidOrderedConfiguration(migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()) || nilWorkerDependency(r.planning.Database) || nilWorkerDependency(r.planning.Store) || r.planning.Planner == nil || r.testRunner == nil {
		return errWorkerExecution
	}
	if _, err := r.deploymentLeaseSeconds(); err != nil {
		return errWorkerExecution
	}
	selection := r.planning.Selection
	if !validSecurityAgentPlannerProductID(selection.OrganizationID) || !validSecurityAgentPlannerProductID(selection.WorkspaceID) || !validSecurityAgentPlannerProductID(selection.EnvironmentID) || !validSecurityAgentPlannerProductID(r.planning.RunID) ||
		!workerIdentityPattern.MatchString(r.planning.WorkerID) || !workerIdentityPattern.MatchString(r.deploymentWorkerID) || !redTeamRunLeasePattern.MatchString(r.planning.LeaseToken) || !redTeamRunLeasePattern.MatchString(r.deploymentLeaseToken) || !release61PlannerAvailable(r.planning.Planner, selection) || !release61TestRunnerAvailable(r.testRunner) || len(r.privateKey) != ed25519.PrivateKeySize {
		return errWorkerExecution
	}
	public, ok := r.privateKey.Public().(ed25519.PublicKey)
	if !ok || r.composition.ValidateSigningKey(r.keyID, public) != nil {
		return errWorkerExecution
	}
	return nil
}

func release61PlannerAvailable(planner *productionSecurityAgentPlanner, selection securityAgentMultistepPricingBinding) bool {
	if planner == nil {
		return false
	}
	planner.mu.RLock()
	defer planner.mu.RUnlock()
	identity := multisteppricing.LookupRequest{Scope: selection.Scope, Provider: "openrouter", Model: planner.model, AccountProfile: selection.AccountProfile, CostUnit: "openrouter_credit", CredentialReference: selection.CredentialReference, CredentialDigest: orderedPlanningDigest(planner.token), RequestPolicyVersion: planner.policyVersion, RequestTokenLimit: int64(planner.maximumTokens), PolicyID: selection.PolicyID, PolicyVersion: selection.PolicyVersion, PolicyDigest: selection.PolicyDigest, AccountID: selection.AccountID, AccountVersion: selection.AccountVersion}
	return !planner.closed && planner.endpoint == "https://openrouter.ai/api/v1/chat/completions" && validSecurityAgentPlannerToken(planner.model, 128, true) && validSecurityAgentPlannerCredential(planner.token) && planner.maximumTokens >= 1 && planner.maximumTokens <= 4096 && validSecurityAgentPlannerToken(planner.policyVersion, 63, false) && planner.client != nil && planner.client.Timeout >= time.Second && planner.client.Timeout <= 30*time.Second && multisteppricing.ValidLookupIdentity(identity)
}

func release61TestRunnerAvailable(runner *productionRedTeamRunner) bool {
	if runner == nil {
		return false
	}
	config := runner.config
	if redTeamRunnerImageDigest(config.RunnerImage) == "" || nilWorkerDependency(config.Artifacts) || nilWorkerDependency(config.Command) || config.NodePath != "/usr/local/bin/node" || config.ScriptPath != "/app/redteam-runner.mjs" || config.PromptfooPath != "/app/dist/src/entrypoint.js" || !redTeamTargetEndpointPattern.MatchString(config.TargetEndpoint) || !filepath.IsAbs(config.TargetTokenFile) || !filepath.IsAbs(config.TargetCAFile) || !filepath.IsAbs(config.TempRoot) || config.Timeout < 30*time.Second || config.Timeout > 15*time.Minute || config.Clock == nil {
		return false
	}
	now := config.Clock()
	return !now.IsZero() && now.Location() == time.UTC && validRedTeamTokenFile(config.TargetTokenFile) && validRedTeamCAFile(config.TargetCAFile)
}

type securityAgentRelease61State struct {
	Test         release61TestState `json:"test"`
	RunState     string             `json:"run_state"`
	RunVersion   int64              `json:"run_version"`
	Admitted     bool               `json:"admitted"`
	StopRequired bool               `json:"stop_required"`
	Planning     struct {
		State          string    `json:"state"`
		Owned          bool      `json:"owned"`
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	} `json:"planning"`
	Steps []struct {
		StepID         string `json:"step_id"`
		State          string `json:"state"`
		EffectState    string `json:"effect_state"`
		EffectVersion  int64  `json:"effect_version"`
		Owned          bool   `json:"owned"`
		LeaseExpiresAt string `json:"lease_expires_at"`
	} `json:"steps"`
	Application release61ApplicationState `json:"application"`
	Cleanup     struct {
		State          string                    `json:"state"`
		Version        int64                     `json:"version"`
		Owned          bool                      `json:"owned"`
		LeaseExpiresAt string                    `json:"lease_expires_at"`
		Application    release61ApplicationState `json:"application"`
	} `json:"cleanup"`
}

type release61ApplicationState struct {
	TTL      int               `json:"ttl_seconds"`
	Targets  []release61Source `json:"targets"`
	Delivery struct {
		DeviceID       string `json:"device_id"`
		Phase          string `json:"phase"`
		Owned          bool   `json:"owned"`
		LeaseExpiresAt string `json:"lease_expires_at"`
		Digest         string `json:"digest"`
		Claim          struct {
			Sequence    int64           `json:"sequence"`
			InputDigest string          `json:"input_digest"`
			Composition json.RawMessage `json:"composition"`
		} `json:"claim"`
	} `json:"delivery"`
}

type release61Source struct {
	DeviceID          string `json:"device_id"`
	CredentialID      string `json:"credential_id"`
	Sequence          int64  `json:"sequence"`
	PolicyVersion     int64  `json:"policy_version"`
	State             string `json:"state"`
	DesiredGeneration int64  `json:"desired_generation"`
	EnvelopeDigest    string `json:"envelope_digest"`
}

func (r *securityAgentRelease61Runtime) call(ctx context.Context, operation func(context.Context, json.RawMessage) (json.RawMessage, error), q map[string]any) error {
	raw, err := json.Marshal(q)
	if err != nil {
		return errWorkerExecution
	}
	_, err = operation(ctx, raw)
	return err
}

func (r *securityAgentRelease61Runtime) applicationTick(ctx context.Context, state securityAgentRelease61State, cleanupMode ...bool) (string, error) {
	step := state.Steps[0]
	cleanup := len(cleanupMode) == 1 && cleanupMode[0]
	apply, deploy, prefix, phase := r.composition.Application, r.composition.Deployment, "", "apply"
	if cleanup {
		apply, deploy, prefix, phase = r.composition.Cleanup, r.composition.CleanupDeployment, "cleanup_", "cleanup"
		state.Application = state.Cleanup.Application
		step.Owned = state.Cleanup.Owned
	}
	q := r.scopeRequest()
	q["step_id"], q["run_version"], q["effect_version"], q["worker_id"], q["lease_token"], q["lease_seconds"], q["envelope"] = step.StepID, state.RunVersion, step.EffectVersion, r.planning.WorkerID, r.planning.LeaseToken, 300, map[string]any{}
	if cleanup {
		q["version"] = state.Cleanup.Version
		if state.Cleanup.State == "" {
			q["operation"] = "claim"
			return "cleanup_claim", r.call(ctx, apply, q)
		}
		// A retained delivery with lost ownership cannot be replayed or kept
		// alive by renewing the independent cleanup lease. Let that lease
		// expire for the reviewed reconciler, then retain its conservative
		// retryable state for explicit recovery rather than resending work.
		delivery := state.Application.Delivery
		if delivery.DeviceID != "" && delivery.Phase != "unclaimed" && !delivery.Owned && release61Expired(delivery.LeaseExpiresAt) {
			if state.Cleanup.State == "retryable" {
				return "cleanup_requires_review", errWorkerExecution
			}
			if step.Owned {
				return "lease_wait", nil
			}
		}
	}
	if step.State == "authorized" && step.EffectVersion == 0 {
		q["operation"] = "claim"
		return "application_claim", r.call(ctx, r.composition.Application, q)
	}
	if !step.Owned {
		if cleanup && state.Cleanup.State == "retryable" {
			q["operation"] = "claim"
			return "cleanup_claim", r.call(ctx, apply, q)
		}
		if cleanup && state.Cleanup.State == "leased" && release61Expired(state.Cleanup.LeaseExpiresAt) {
			if expiry, parseErr := time.Parse(time.RFC3339Nano, state.Application.Delivery.LeaseExpiresAt); parseErr == nil && expiry.After(time.Now()) {
				return "lease_wait", nil
			}
			q["operation"] = "reconcile"
			return "cleanup_reconcile", r.call(ctx, apply, q)
		}
		if !cleanup && step.EffectState == "leased" && release61Expired(step.LeaseExpiresAt) {
			q["operation"] = "claim"
			return "application_claim", r.call(ctx, apply, q)
		}
		return "lease_wait", nil
	}
	ownedCtx, ownedCancel, ownedErr := release61OwnedContext(ctx, step.LeaseExpiresAt)
	if ownedErr != nil {
		return "", ownedErr
	}
	defer ownedCancel()
	ctx = ownedCtx
	if release61HeartbeatDue(step.LeaseExpiresAt) {
		q["operation"] = "heartbeat"
		label := "application_heartbeat"
		if cleanup {
			label = "cleanup_heartbeat"
		}
		return label, r.call(ctx, apply, q)
	}
	for _, target := range state.Application.Targets {
		if target.State != "planned" {
			continue
		}
		compiled, err := temporaryContainmentPolicies("create_temporary_policy", "", phase)
		if err != nil {
			return "", err
		}
		now := time.Now().UTC().Truncate(time.Second)
		signed, err := r.sign(target.DeviceID, target.Sequence, now, now.Add(time.Duration(state.Application.TTL)*time.Second), compiled)
		if err != nil {
			return "", err
		}
		envelope, err := temporaryPolicyRepositoryEnvelope(apiserver.TemporaryPolicyTarget{DeviceID: target.DeviceID, CredentialID: target.CredentialID, Sequence: target.Sequence, PolicyVersion: target.PolicyVersion}, phase, signed)
		if err != nil {
			return "", err
		}
		q["operation"] = "store"
		q["envelope"] = map[string]any{"device_id": target.DeviceID, "credential_id": target.CredentialID, "sequence": target.Sequence, "policy_version": target.PolicyVersion, "key_id": envelope.KeyID, "issued_at": envelope.IssuedAt, "expires_at": envelope.ExpiresAt, "failure_mode": envelope.FailureMode, "payload_digest": envelope.PayloadDigest, "policies": envelope.Policies, "signature": base64.StdEncoding.EncodeToString(envelope.Signature), "envelope_digest": envelope.EnvelopeDigest}
		label := "application_store"
		if cleanup {
			label = "cleanup_store"
		}
		return label, r.call(ctx, apply, q)
	}
	delivery := state.Application.Delivery
	if delivery.DeviceID == "" {
		q["operation"] = "complete"
		label := "application_complete"
		if cleanup {
			label = "cleanup_complete"
		}
		return label, r.call(ctx, apply, q)
	}
	var target release61Source
	for _, value := range state.Application.Targets {
		if value.DeviceID == delivery.DeviceID {
			target = value
			break
		}
	}
	if target.DeviceID == "" {
		return "", errWorkerExecution
	}
	if delivery.Phase != "unclaimed" && !delivery.Owned {
		return "lease_wait", nil
	}
	if delivery.Owned {
		deliveryCtx, cancel, err := release61OwnedContext(ctx, delivery.LeaseExpiresAt)
		if err != nil {
			return "", err
		}
		defer cancel()
		ctx = deliveryCtx
	}
	d := r.scopeRequest()
	d["step_id"], d["run_version"], d["effect_version"], d["action_worker_id"], d["action_lease_token"], d["device_id"], d["credential_id"], d["source_sequence"], d["source_digest"], d["desired_generation"], d["worker_id"], d["lease_token"], d["lease_seconds"], d["sequence"], d["input_digest"], d["composition"], d["envelope"], d["digest"] = step.StepID, state.RunVersion, step.EffectVersion, r.planning.WorkerID, r.planning.LeaseToken, target.DeviceID, target.CredentialID, target.Sequence, target.EnvelopeDigest, target.DesiredGeneration, r.deploymentWorkerID, r.deploymentLeaseToken, 300, 0, "", map[string]any{}, map[string]any{}, ""
	leaseSeconds, err := r.deploymentLeaseSeconds()
	if err != nil {
		return "", err
	}
	d["lease_seconds"] = leaseSeconds
	operation := "claim"
	if delivery.Phase != "unclaimed" {
		d["sequence"], d["input_digest"], d["composition"] = delivery.Claim.Sequence, delivery.Claim.InputDigest, delivery.Claim.Composition
		switch delivery.Phase {
		case "claimed":
			var composition struct {
				Policies  []policy.CompiledPolicy `json:"policies"`
				ExpiresAt time.Time               `json:"expires_at"`
			}
			if json.Unmarshal(delivery.Claim.Composition, &composition) != nil {
				return "", errWorkerExecution
			}
			now := time.Now().UTC().Truncate(time.Second)
			signed, err := r.sign(target.DeviceID, delivery.Claim.Sequence, now, composition.ExpiresAt, composition.Policies)
			if err != nil {
				return "", err
			}
			raw, _ := json.Marshal(signed)
			d["envelope"], d["digest"], operation = signed, orderedPlanningDigest(raw), "store"
		case "stored":
			operation = "read"
		case "read":
			operation = "finish"
			d["digest"] = delivery.Digest
		default:
			return "", errWorkerExecution
		}
	}
	d["operation"] = operation
	return prefix + "deployment_" + operation, r.call(ctx, deploy, d)
}

func release61Expired(value string) bool {
	expiry, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !expiry.After(time.Now())
}

func release61HeartbeatDue(value string) bool {
	expiry, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && expiry.After(time.Now()) && time.Until(expiry) < 90*time.Second
}

func release61OwnedContext(ctx context.Context, values ...string) (context.Context, context.CancelFunc, error) {
	earliest := time.Now().Add(90 * time.Second)
	for _, value := range values {
		expiry, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || !expiry.After(time.Now()) {
			return nil, nil, errWorkerExecution
		}
		if expiry.Before(earliest) {
			earliest = expiry
		}
	}
	bounded, cancel := context.WithDeadline(ctx, earliest)
	return bounded, cancel, nil
}

func (r *securityAgentRelease61Runtime) sign(device string, sequence int64, issued, expires time.Time, compiled []policy.CompiledPolicy) (policy.GatewayPolicyEnvelope, error) {
	if len(r.privateKey) != ed25519.PrivateKeySize {
		return policy.GatewayPolicyEnvelope{}, errWorkerExecution
	}
	return policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: r.keyID, Binding: policy.GatewayPolicyBinding{OrganizationID: r.planning.Selection.OrganizationID, WorkspaceID: r.planning.Selection.WorkspaceID, EnvironmentID: r.planning.Selection.EnvironmentID, DeviceID: device}, Sequence: uint64(sequence), PolicyVersion: uint64(sequence), Now: issued, IssuedAt: issued, ExpiresAt: expires, FailureMode: "closed", Policies: compiled}, r.privateKey)
}

func (r *securityAgentRelease61Runtime) scopeRequest() map[string]any {
	return map[string]any{"organization_id": r.planning.Selection.OrganizationID, "workspace_id": r.planning.Selection.WorkspaceID, "environment_id": r.planning.Selection.EnvironmentID, "run_id": r.planning.RunID}
}
func (r *securityAgentRelease61Runtime) read(ctx context.Context) (securityAgentRelease61State, error) {
	var state securityAgentRelease61State
	q := r.scopeRequest()
	q["worker_id"], q["lease_token"], q["deployment_worker_id"], q["deployment_lease_token"] = r.planning.WorkerID, r.planning.LeaseToken, r.deploymentWorkerID, r.deploymentLeaseToken
	raw, _ := json.Marshal(q)
	response, err := r.composition.State(ctx, raw)
	if err != nil || json.Unmarshal(response, &state) != nil {
		return state, errWorkerExecution
	}
	return state, nil
}
