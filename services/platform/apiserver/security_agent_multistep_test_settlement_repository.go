package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These are the existing runner artifact limits, not a new generic wire lane.
// SQL checks the same raw byte and manifest/response limits before commit.
const orderedTestInputBytes = 65536
const orderedTestOutputBytes = 1048576
const orderedTestWireBytes = 16384

func (repository *securityAgentMultistepAdmissionRepository) testSettle(ctx context.Context, raw json.RawMessage, store artifactstore.ObjectReferencingArtifactStore) (json.RawMessage, error) {
	var request orderedTestAction
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > orderedTestWireBytes {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "worker_id", "lease_token", "run_version", "effect_version", "lease_seconds", "payload"); !ok || decodeStrictDiscovery(raw, &request) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedTestScope(request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID)
	token, tokenErr := hex.DecodeString(request.LeaseToken)
	if !valid || request.Operation != "settle" || tokenErr != nil || len(token) != 16 || strings.ToLower(request.LeaseToken) != request.LeaseToken || !redTeamWorkerPattern.MatchString(request.WorkerID) || !validSecurityAgentWorkerLease(request.WorkerID, request.LeaseToken, request.LeaseSeconds) || request.RunVersion < 1 || request.RunVersion > 999998 || request.EffectVersion < 1 || request.EffectVersion > 999998 {
		return nil, ErrRepositoryOperation
	}
	var payload struct {
		InputArtifact  RedTeamArtifactReference `json:"input_artifact"`
		OutputArtifact RedTeamArtifactReference `json:"output_artifact"`
	}
	fields, ok := securityAgentOrderedClosedObject(request.Payload, "input_artifact", "output_artifact")
	if !ok || decodeStrictDiscovery(request.Payload, &payload) != nil {
		return nil, ErrRepositoryOperation
	}
	for _, key := range []string{"input_artifact", "output_artifact"} {
		if _, ok = securityAgentOrderedClosedObject(fields[key], "reference", "version_id", "sha256", "size_bytes"); !ok {
			return nil, ErrRepositoryOperation
		}
	}
	inputID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", request.RunID+"\x1f"+request.StepID)
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", request.RunID+"\x1f"+request.StepID+"\x1frun_test")
	inputBody, err := orderedTestReadArtifact(ctx, store, scope, inputID, payload.InputArtifact, orderedTestInputBytes)
	if err != nil {
		return nil, err
	}
	input, valid := orderedTestDecodeInput(inputBody)
	if !valid || input.OrganizationID != request.OrganizationID || input.WorkspaceID != request.WorkspaceID || input.EnvironmentID != request.EnvironmentID || input.RunID != child {
		return nil, ErrRepositoryOperation
	}
	outputBody, err := orderedTestReadArtifact(ctx, store, scope, child, payload.OutputArtifact, orderedTestOutputBytes)
	if err != nil {
		return nil, err
	}
	output, ok := orderedTestArtifactObject(outputBody, orderedTestOutputBytes, "schema_version", "input_artifact", "summary", "native_artifact")
	if !ok || string(output["schema_version"]) != `"red-team-evidence-bundle-v2"` {
		return nil, ErrRepositoryOperation
	}
	var actualInput RedTeamArtifactReference
	if decodeStrictDiscovery(output["input_artifact"], &actualInput) != nil || actualInput != payload.InputArtifact {
		return nil, ErrRepositoryOperation
	}
	summary, ok := orderedTestArtifactObject(output["summary"], orderedTestOutputBytes, "schema_version", "engine", "engine_version", "run_id", "input_digest", "objective", "behavior", "verdict", "error_code", "evidence")
	if !ok || string(summary["schema_version"]) != `"red-team-evidence-v2"` || string(summary["engine"]) != `"promptfoo"` || string(summary["engine_version"]) != `"0.121.19"` || string(summary["run_id"]) != strconv.Quote(child) || string(summary["input_digest"]) != strconv.Quote(input.InputDigest) || !bytes.Equal(bytes.TrimSpace(summary["error_code"]), []byte("null")) {
		return nil, ErrRepositoryOperation
	}
	var verdict string
	if json.Unmarshal(summary["verdict"], &verdict) != nil || !stringIn(verdict, "pass", "fail") {
		return nil, ErrRepositoryOperation
	}
	inputManifest, _ := json.Marshal(payload.InputArtifact)
	outputManifest, _ := json.Marshal(payload.OutputArtifact)
	response, err := repository.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.test_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14::jsonb,$15)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID, request.WorkerID, request.LeaseToken, request.RunVersion, request.EffectVersion, inputManifest, inputBody, outputManifest, outputBody)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var result orderedTestSettlement
	fields, ok = securityAgentOrderedClosedObject(response, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "test_run_id", "attempt", "run_version", "step_version", "effect_version", "run_state", "step_state", "effect_state", "receipt_kind", "outcome", "plan_hash", "input_digest", "result_digest", "receipt", "input_artifact", "output_artifact")
	if !ok || len(response) > orderedTestWireBytes || decodeStrictDiscovery(response, &result) != nil {
		return nil, ErrRepositoryUnavailable
	}
	if _, ok = securityAgentOrderedClosedObject(fields["receipt"], "invocation_id", "snapshot_digest", "proof_digest", "settlement_generation", "outcome"); !ok {
		return nil, ErrRepositoryUnavailable
	}
	for _, key := range []string{"input_artifact", "output_artifact"} {
		if _, ok = securityAgentOrderedClosedObject(fields[key], "reference", "version_id", "sha256", "size_bytes"); !ok {
			return nil, ErrRepositoryUnavailable
		}
	}
	invocation, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_invocation", request.RunID+"\x1f"+request.StepID+"\x1f"+strconv.Itoa(result.Attempt))
	outcome, state := "not_reproduced", "contained"
	if verdict == "fail" {
		outcome, state = "reproduced", "needs_human"
	}
	stepInput, validInput := decodeTemporaryPolicyDigest(result.InputDigest)
	_, validPlan := decodeTemporaryPolicyDigest(result.PlanHash)
	snapshot, snapshotErr := hex.DecodeString(result.Receipt.SnapshotDigest)
	proof, proofErr := hex.DecodeString(result.Receipt.ProofDigest)
	computed := sha256.Sum256(append(append(bytes.Clone(stepInput), snapshot...), proof...))
	if result.ContractVersion != 61 || result.OrganizationID != request.OrganizationID || result.WorkspaceID != request.WorkspaceID || result.EnvironmentID != request.EnvironmentID || result.RunID != request.RunID || result.StepID != request.StepID || result.TestRunID != child || result.Attempt < 1 || result.Attempt > 5 || result.RunVersion != request.RunVersion+1 || result.StepVersion != 5 || result.EffectVersion != request.EffectVersion+1 || result.RunState != state || result.StepState != "succeeded" || result.EffectState != "verified" || result.ReceiptKind != "existing_test_settled.v1" || result.Outcome != outcome || !validInput || !validPlan || snapshotErr != nil || proofErr != nil || !validAttackLabDigest(result.Receipt.SnapshotDigest) || result.Receipt.ProofDigest != payload.OutputArtifact.SHA256 || result.Receipt.InvocationID != invocation || result.Receipt.Generation != 1 || result.Receipt.Outcome != outcome || result.ResultDigest != "sha256:"+hex.EncodeToString(computed[:]) || result.InputArtifact != payload.InputArtifact || result.OutputArtifact != payload.OutputArtifact {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}

type orderedTestSettlement struct {
	ContractVersion int    `json:"contract_version"`
	OrganizationID  string `json:"organization_id"`
	WorkspaceID     string `json:"workspace_id"`
	EnvironmentID   string `json:"environment_id"`
	RunID           string `json:"run_id"`
	StepID          string `json:"step_id"`
	TestRunID       string `json:"test_run_id"`
	Attempt         int    `json:"attempt"`
	RunVersion      int64  `json:"run_version"`
	StepVersion     int64  `json:"step_version"`
	EffectVersion   int64  `json:"effect_version"`
	RunState        string `json:"run_state"`
	StepState       string `json:"step_state"`
	EffectState     string `json:"effect_state"`
	ReceiptKind     string `json:"receipt_kind"`
	Outcome         string `json:"outcome"`
	PlanHash        string `json:"plan_hash"`
	InputDigest     string `json:"input_digest"`
	ResultDigest    string `json:"result_digest"`
	Receipt         struct {
		InvocationID   string `json:"invocation_id"`
		SnapshotDigest string `json:"snapshot_digest"`
		ProofDigest    string `json:"proof_digest"`
		Generation     int64  `json:"settlement_generation"`
		Outcome        string `json:"outcome"`
	} `json:"receipt"`
	InputArtifact  RedTeamArtifactReference `json:"input_artifact"`
	OutputArtifact RedTeamArtifactReference `json:"output_artifact"`
}

// Artifacts allow explicit null error_code. Unlike authority responses, they
// need recursive duplicate detection without treating that null as omission.
func orderedTestArtifactObject(raw json.RawMessage, maximum int, keys ...string) (map[string]json.RawMessage, bool) {
	if len(raw) > maximum || !utf8.Valid(raw) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if !orderedTestJSONNode(decoder, 0) {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return nil, false
		}
	}
	return fields, true
}

func orderedTestJSONNode(decoder *json.Decoder, depth int) bool {
	if depth > 24 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, valid := key.(string)
				if err != nil || !valid || seen[name] {
					return false
				}
				seen[name] = true
				if !orderedTestJSONNode(decoder, depth+1) {
					return false
				}
			}
			token, err = decoder.Token()
			return err == nil && token == json.Delim('}')
		case '[':
			for decoder.More() {
				if !orderedTestJSONNode(decoder, depth+1) {
					return false
				}
			}
			token, err = decoder.Token()
			return err == nil && token == json.Delim(']')
		default:
			return false
		}
	}
	return true
}
