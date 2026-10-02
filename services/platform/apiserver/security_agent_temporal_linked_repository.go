package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type temporalLinkedState struct {
	EffectKey         string                    `json:"effect_key"`
	Generation        int64                     `json:"generation"`
	TestRunID         string                    `json:"test_run_id"`
	InputDigest       string                    `json:"input_digest"`
	DefinitionID      string                    `json:"definition_id"`
	DefinitionVersion int64                     `json:"definition_version"`
	TargetID          string                    `json:"target_id"`
	TargetKind        string                    `json:"target_kind"`
	Categories        []string                  `json:"categories"`
	TargetResolution  json.RawMessage           `json:"target_resolution"`
	InputManifest     *RedTeamArtifactReference `json:"input_manifest"`
	InputBody         *string                   `json:"input_body"`
	SendPermit        bool                      `json:"send_permit"`
}

// OrderedTestLinkedDispatcher keeps the readback and dispatch under one current
// worker decision. The synchronous callback owns object-store verification;
// its error must prevent dispatch. Historical databases do not implement this.
type OrderedTestLinkedDispatcher interface {
	DispatchOrderedTestLinked(context.Context, json.RawMessage, func(json.RawMessage) error) (json.RawMessage, error)
}

func temporalTestRequest(raw json.RawMessage, maximum int, operations ...string) (temporalEffectRequest, bool) {
	var q temporalEffectRequest
	if _, ok := orderedTestArtifactObject(raw, maximum, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation", "operation", "payload"); !ok || decodeStrictDiscovery(raw, &q) != nil || q.Generation != 1 || !stringIn(q.Operation, operations...) {
		return q, false
	}
	_, valid := orderedTestScope(q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.StepID)
	return q, valid
}

func (repository *securityAgentMultistepAdmissionRepository) temporalReady(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryOperation
	}
	raw, err := repository.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal68.ready($1,$2))`, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint())
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return ErrRepositoryUnavailable
	}
	return nil
}

// TemporalLinked reads the exact immutable artifact before preparing or
// permitting dispatch. Neither a caller's digest nor a SQL row substitutes
// for object-store readback. All database calls are separate autocommits.
func (repository *securityAgentMultistepAdmissionRepository) TemporalLinked(ctx context.Context, raw json.RawMessage, store artifactstore.ObjectReferencingArtifactStore) (json.RawMessage, error) {
	return repository.temporalLinked(ctx, raw, store, "")
}

// SingleTestLinked retains the immutable artifact contract with an explicit
// single-action owner. SQL independently authenticates the persisted action.
func (repository *securityAgentMultistepAdmissionRepository) SingleTestLinked(ctx context.Context, raw json.RawMessage, store artifactstore.ObjectReferencingArtifactStore, action string) (json.RawMessage, error) {
	if !stringIn(action, "run_test", "rerun_test") {
		return nil, ErrRepositoryOperation
	}
	return repository.temporalLinked(ctx, raw, store, action)
}

func (repository *securityAgentMultistepAdmissionRepository) temporalLinked(ctx context.Context, raw json.RawMessage, store artifactstore.ObjectReferencingArtifactStore, action string) (json.RawMessage, error) {
	q, valid := temporalTestRequestForOwner(raw, 131072, action, "read", "input", "dispatch")
	if !valid || repository == nil || nilInterface(repository.database) || nilInterface(store) || ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryOperation
	}
	scope, _ := temporalTestScopeForOwner(q, action)
	inputID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", q.RunID+"\x1f"+q.StepID)
	childAction := action
	if childAction == "" {
		childAction = "run_test"
	}
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", q.RunID+"\x1f"+q.StepID+"\x1f"+childAction)
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := repository.temporalReadyForOwner(bounded, action); err != nil {
		return nil, err
	}
	if q.Operation == "input" {
		var p struct {
			Manifest RedTeamArtifactReference `json:"manifest"`
			Body     string                   `json:"body"`
		}
		fields, ok := orderedTestArtifactObject(q.Payload, 131072, "manifest", "body")
		if !ok || decodeStrictDiscovery(q.Payload, &p) != nil {
			return nil, ErrRepositoryOperation
		}
		if _, ok := securityAgentOrderedClosedObject(fields["manifest"], "reference", "version_id", "sha256", "size_bytes"); !ok {
			return nil, ErrRepositoryOperation
		}
		body, err := base64.StdEncoding.Strict().DecodeString(p.Body)
		input, ok := orderedTestDecodeInput(body)
		if err != nil || len(body) > orderedTestInputBytes || !ok || input.OrganizationID != q.OrganizationID || input.WorkspaceID != q.WorkspaceID || input.EnvironmentID != q.EnvironmentID || input.RunID != child {
			return nil, ErrRepositoryOperation
		}
		actual, err := orderedTestReadArtifact(bounded, store, scope, inputID, p.Manifest, orderedTestInputBytes)
		if err != nil || !bytes.Equal(actual, body) {
			return nil, ErrRepositoryUnavailable
		}
	} else if _, ok := securityAgentOrderedClosedObject(q.Payload); !ok {
		return nil, ErrRepositoryOperation
	}
	var before temporalLinkedState
	composed, useComposed := repository.database.(OrderedTestLinkedDispatcher)
	useComposed = useComposed && action == "" && q.Operation == "dispatch"
	if q.Operation == "dispatch" && !useComposed {
		readQ := q
		readQ.Operation = "read"
		readRaw, _ := json.Marshal(readQ)
		prior, err := repository.temporalLinked(bounded, readRaw, store, action)
		if err != nil || decodeStrictDiscovery(prior, &before) != nil || before.InputManifest == nil {
			return nil, ErrRepositoryUnavailable
		}
	}
	statement := `SELECT zasp_temporal68.linked($1::jsonb)`
	if action != "" {
		statement = `SELECT zasp_temporal74.linked($1::jsonb)`
	}
	var response json.RawMessage
	var err error
	if useComposed {
		verified := false
		response, err = composed.DispatchOrderedTestLinked(bounded, raw, func(prior json.RawMessage) error {
			if verified || bounded.Err() != nil {
				return ErrRepositoryUnavailable
			}
			readQ := q
			readQ.Operation = "read"
			value, err := validateTemporalLinkedResponse(bounded, readQ, action, prior, store)
			if err != nil || value.InputManifest == nil {
				return ErrRepositoryUnavailable
			}
			before = *value
			verified = true
			return nil
		})
		if err == nil && !verified {
			return nil, ErrRepositoryUnavailable
		}
	} else {
		response, err = repository.database.QueryJSON(bounded, statement, raw)
	}
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	result, err := validateTemporalLinkedResponse(bounded, q, action, response, store)
	if err != nil {
		return nil, err
	}
	if q.Operation == "dispatch" {
		before.SendPermit = result.SendPermit
		if !reflect.DeepEqual(before, *result) {
			return nil, ErrRepositoryUnavailable
		}
	}
	return response, nil
}

// Both readback and final responses use the same full identity and artifact
// validation. In particular, a signed SQL digest does not replace store.Get.
func validateTemporalLinkedResponse(bounded context.Context, q temporalEffectRequest, action string, response json.RawMessage, store artifactstore.ObjectReferencingArtifactStore) (*temporalLinkedState, error) {
	scope, _ := temporalTestScopeForOwner(q, action)
	inputID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", q.RunID+"\x1f"+q.StepID)
	childAction := action
	if childAction == "" {
		childAction = "run_test"
	}
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", q.RunID+"\x1f"+q.StepID+"\x1f"+childAction)
	var result temporalLinkedState
	fields, ok := orderedTestArtifactObject(response, 131072, "effect_key", "generation", "test_run_id", "input_digest", "definition_id", "definition_version", "target_id", "target_kind", "categories", "target_resolution", "input_manifest", "input_body", "send_permit")
	if !ok || decodeStrictDiscovery(response, &result) != nil || result.EffectKey != temporalEffectIdentity(q) || result.Generation != 1 || result.TestRunID != child || !validAttackLabDigest(result.InputDigest) || !validProductID(result.DefinitionID) || result.DefinitionVersion < 1 || result.DefinitionVersion > 1000000 || !validProductID(result.TargetID) || !stringIn(result.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || len(result.Categories) < 1 || len(result.Categories) > 6 || result.SendPermit && q.Operation != "dispatch" {
		return nil, ErrRepositoryUnavailable
	}
	for name, value := range fields {
		if name != "input_manifest" && name != "input_body" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrRepositoryUnavailable
		}
	}
	input := orderedTestInput{OrganizationID: q.OrganizationID, WorkspaceID: q.WorkspaceID, EnvironmentID: q.EnvironmentID, RunID: child, DefinitionID: result.DefinitionID, DefinitionVersion: result.DefinitionVersion, TargetID: result.TargetID, TargetKind: result.TargetKind, Categories: result.Categories, InputDigest: result.InputDigest}
	if !orderedTestResolutionValid(result.TargetResolution, input) {
		return nil, ErrRepositoryUnavailable
	}
	if result.InputManifest == nil {
		if result.InputBody != nil || q.Operation != "read" {
			return nil, ErrRepositoryUnavailable
		}
	} else {
		if _, ok := securityAgentOrderedClosedObject(fields["input_manifest"], "reference", "version_id", "sha256", "size_bytes"); !ok || result.InputBody == nil {
			return nil, ErrRepositoryUnavailable
		}
		body, err := orderedTestReadArtifact(bounded, store, scope, inputID, *result.InputManifest, orderedTestInputBytes)
		actual, valid := orderedTestDecodeInput(body)
		input.SchemaVersion, input.RunnerImageDigest = actual.SchemaVersion, actual.RunnerImageDigest
		if err != nil || !valid || string(body) != *result.InputBody || !reflect.DeepEqual(input, actual) {
			return nil, ErrRepositoryUnavailable
		}
	}
	return &result, nil
}

// TemporalTestSettle re-reads both artifact versions and their association.
// The SQL operation then compares every native check to its durable journal.
func (repository *securityAgentMultistepAdmissionRepository) TemporalTestSettle(ctx context.Context, raw json.RawMessage, store artifactstore.ObjectReferencingArtifactStore) (json.RawMessage, error) {
	return repository.temporalTestSettle(ctx, raw, store, "")
}

func (repository *securityAgentMultistepAdmissionRepository) SingleTestChildSettle(ctx context.Context, raw json.RawMessage, store artifactstore.ObjectReferencingArtifactStore, action string) (json.RawMessage, error) {
	if !stringIn(action, "run_test", "rerun_test") {
		return nil, ErrRepositoryOperation
	}
	return repository.temporalTestSettle(ctx, raw, store, action)
}

func (repository *securityAgentMultistepAdmissionRepository) temporalTestSettle(ctx context.Context, raw json.RawMessage, store artifactstore.ObjectReferencingArtifactStore, action string) (json.RawMessage, error) {
	op := "complete"
	if action != "" {
		op = "child"
	}
	q, valid := temporalTestRequestForOwner(raw, 1500000, action, op)
	if !valid || repository == nil || nilInterface(repository.database) || nilInterface(store) || ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryOperation
	}
	var p struct {
		Manifest RedTeamArtifactReference `json:"output_manifest"`
		Body     string                   `json:"output_body"`
	}
	fields, ok := orderedTestArtifactObject(q.Payload, 1500000, "output_manifest", "output_body")
	if !ok || decodeStrictDiscovery(q.Payload, &p) != nil {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(fields["output_manifest"], "reference", "version_id", "sha256", "size_bytes"); !ok {
		return nil, ErrRepositoryOperation
	}
	body, err := base64.StdEncoding.Strict().DecodeString(p.Body)
	if err != nil || len(body) > orderedTestOutputBytes {
		return nil, ErrRepositoryOperation
	}
	scope, _ := temporalTestScopeForOwner(q, action)
	childAction := action
	if childAction == "" {
		childAction = "run_test"
	}
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", q.RunID+"\x1f"+q.StepID+"\x1f"+childAction)
	inputID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", q.RunID+"\x1f"+q.StepID)
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := repository.temporalReadyForOwner(bounded, action); err != nil {
		return nil, err
	}
	actual, err := orderedTestReadArtifact(bounded, store, scope, child, p.Manifest, orderedTestOutputBytes)
	if err != nil || !bytes.Equal(body, actual) {
		return nil, ErrRepositoryUnavailable
	}
	output, ok := orderedTestArtifactObject(body, orderedTestOutputBytes, "schema_version", "input_artifact", "summary", "native_artifact")
	var inputManifest RedTeamArtifactReference
	if !ok || string(output["schema_version"]) != `"red-team-evidence-bundle-v2"` || decodeStrictDiscovery(output["input_artifact"], &inputManifest) != nil {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(output["input_artifact"], "reference", "version_id", "sha256", "size_bytes"); !ok {
		return nil, ErrRepositoryOperation
	}
	inputBody, err := orderedTestReadArtifact(bounded, store, scope, inputID, inputManifest, orderedTestInputBytes)
	input, valid := orderedTestDecodeInput(inputBody)
	if err != nil || !valid || input.OrganizationID != q.OrganizationID || input.WorkspaceID != q.WorkspaceID || input.EnvironmentID != q.EnvironmentID || input.RunID != child {
		return nil, ErrRepositoryUnavailable
	}
	summary, ok := orderedTestArtifactObject(output["summary"], orderedTestOutputBytes, "schema_version", "engine", "engine_version", "run_id", "input_digest", "objective", "behavior", "verdict", "error_code", "evidence")
	if !ok || string(summary["schema_version"]) != `"red-team-evidence-v2"` || string(summary["engine"]) != `"promptfoo"` || string(summary["engine_version"]) != `"0.121.19"` || string(summary["run_id"]) != strconv.Quote(child) || string(summary["input_digest"]) != strconv.Quote(input.InputDigest) || !bytes.Equal(bytes.TrimSpace(summary["error_code"]), []byte("null")) {
		return nil, ErrRepositoryOperation
	}
	var verdict string
	if json.Unmarshal(summary["verdict"], &verdict) != nil || !stringIn(verdict, "pass", "fail") {
		return nil, ErrRepositoryOperation
	}
	statement := `SELECT zasp_temporal68.test_settle($1::jsonb)`
	if action != "" {
		statement = `SELECT zasp_temporal74.test_settle($1::jsonb)`
	}
	response, err := repository.database.QueryJSON(bounded, statement, raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	if action != "" {
		var receipt struct {
			TestRunID      string                   `json:"test_run_id"`
			State          string                   `json:"state"`
			Attempt        int                      `json:"attempt"`
			EffectKey      string                   `json:"effect_key"`
			Manifest       RedTeamArtifactReference `json:"output_manifest"`
			SnapshotDigest string                   `json:"snapshot_digest"`
		}
		if _, ok := securityAgentOrderedClosedObject(response, "test_run_id", "state", "attempt", "effect_key", "output_manifest", "snapshot_digest"); !ok || len(response) > 16384 || decodeStrictDiscovery(response, &receipt) != nil || receipt.TestRunID != child || receipt.State != "complete" || receipt.Attempt != 1 || receipt.EffectKey != temporalEffectIdentity(q) || receipt.Manifest != p.Manifest || !validAttackLabDigest(receipt.SnapshotDigest) {
			return nil, ErrRepositoryUnavailable
		}
		return response, nil
	}
	var result struct {
		EffectKey    string `json:"effect_key"`
		Generation   int64  `json:"generation"`
		TestRunID    string `json:"test_run_id"`
		RunState     string `json:"run_state"`
		Outcome      string `json:"outcome"`
		ResultDigest string `json:"result_digest"`
		InputDigest  string `json:"input_digest"`
		PlanHash     string `json:"plan_hash"`
		Receipt      struct {
			InvocationID   string `json:"invocation_id"`
			SnapshotDigest string `json:"snapshot_digest"`
			ProofDigest    string `json:"proof_digest"`
			Generation     int64  `json:"settlement_generation"`
			Outcome        string `json:"outcome"`
		} `json:"receipt"`
		InputArtifact  RedTeamArtifactReference `json:"input_artifact"`
		OutputArtifact RedTeamArtifactReference `json:"output_artifact"`
	}
	fields, ok = securityAgentOrderedClosedObject(response, "effect_key", "generation", "test_run_id", "run_state", "outcome", "result_digest", "input_digest", "plan_hash", "receipt", "input_artifact", "output_artifact")
	if !ok || len(response) > 16384 || decodeStrictDiscovery(response, &result) != nil {
		return nil, ErrRepositoryUnavailable
	}
	if _, ok := securityAgentOrderedClosedObject(fields["receipt"], "invocation_id", "snapshot_digest", "proof_digest", "settlement_generation", "outcome"); !ok {
		return nil, ErrRepositoryUnavailable
	}
	for _, field := range []string{"input_artifact", "output_artifact"} {
		if _, ok := securityAgentOrderedClosedObject(fields[field], "reference", "version_id", "sha256", "size_bytes"); !ok {
			return nil, ErrRepositoryUnavailable
		}
	}
	stepInput, inputOK := decodeTemporaryPolicyDigest(result.InputDigest)
	_, planOK := decodeTemporaryPolicyDigest(result.PlanHash)
	snapshot, _ := hex.DecodeString(result.Receipt.SnapshotDigest)
	proof, _ := hex.DecodeString(result.Receipt.ProofDigest)
	computed := sha256.Sum256(append(append(bytes.Clone(stepInput), snapshot...), proof...))
	invocation, _ := CanonicalDiscoveryID(scope, "security_agent_temporal_test_invocation", temporalEffectIdentity(q))
	wantOutcome, wantState := "not_reproduced", "contained"
	if verdict == "fail" {
		wantOutcome, wantState = "reproduced", "needs_human"
	}
	if result.EffectKey != temporalEffectIdentity(q) || result.Generation != 1 || result.TestRunID != child || result.RunState != wantState || result.Outcome != wantOutcome || !inputOK || !planOK || !validAttackLabDigest(result.Receipt.SnapshotDigest) || result.Receipt.ProofDigest != p.Manifest.SHA256 || result.Receipt.Generation != 1 || result.Receipt.InvocationID != invocation || result.Receipt.Outcome != wantOutcome || result.ResultDigest != "sha256:"+hex.EncodeToString(computed[:]) || result.InputArtifact != inputManifest || result.OutputArtifact != p.Manifest {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}
