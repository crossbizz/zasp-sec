package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"
)

// TemporalPlannerLateUsage accepts evidence captured by the registered
// executor/compensation connection. It performs no provider send, artifact
// rewrite, new reservation or admission. SQL appends the authenticated
// association and charges the existing reservation exactly once.
func (repository *securityAgentMultistepAdmissionRepository) TemporalPlannerLateUsage(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var q struct {
		OrganizationID    string `json:"organization_id"`
		WorkspaceID       string `json:"workspace_id"`
		EnvironmentID     string `json:"environment_id"`
		RunID             string `json:"run_id"`
		DefinitionVersion int64  `json:"definition_version"`
		Operation         string `json:"operation"`
		Payload           struct {
			Raw              string `json:"raw"`
			RequestDigest    string `json:"request_digest"`
			CredentialDigest string `json:"credential_digest"`
			ReservationID    string `json:"reservation_id"`
			ResponseID       string `json:"response_id"`
			ResponseDigest   string `json:"response_digest"`
		} `json:"payload"`
	}
	fields, ok := orderedTestArtifactObject(raw, 131072, "organization_id", "workspace_id", "environment_id", "run_id", "definition_version", "operation", "payload")
	if !ok || repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || decodeStrictDiscovery(raw, &q) != nil || q.Operation != "late_usage" || q.DefinitionVersion < 1 || q.DefinitionVersion > 1000000 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(fields["payload"], "raw", "request_digest", "credential_digest", "reservation_id", "response_id", "response_digest"); !ok {
		return nil, ErrRepositoryOperation
	}
	for _, id := range []string{q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.Payload.ReservationID} {
		if !validProductID(id) {
			return nil, ErrRepositoryOperation
		}
	}
	for _, digest := range []string{q.Payload.RequestDigest, q.Payload.CredentialDigest, q.Payload.ResponseDigest} {
		if _, ok := decodeTemporaryPolicyDigest(digest); !ok {
			return nil, ErrRepositoryOperation
		}
	}
	if len(q.Payload.Raw) == 0 || len(q.Payload.Raw) > 65536 || !utf8.ValidString(q.Payload.Raw) || len(q.Payload.ResponseID) < 1 || len(q.Payload.ResponseID) > 256 {
		return nil, ErrRepositoryOperation
	}
	for _, r := range q.Payload.ResponseID {
		if r < '!' || r > '~' {
			return nil, ErrRepositoryOperation
		}
	}
	digest := sha256.Sum256([]byte(q.Payload.Raw))
	if q.Payload.ResponseDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, ErrRepositoryOperation
	}
	var provider map[string]json.RawMessage
	if json.Unmarshal([]byte(q.Payload.Raw), &provider) != nil || provider == nil {
		return nil, ErrRepositoryOperation
	}
	keys := make([]string, 0, len(provider))
	for key := range provider {
		keys = append(keys, key)
	}
	if _, ok := orderedTestArtifactObject([]byte(q.Payload.Raw), 65536, keys...); !ok {
		return nil, ErrRepositoryOperation
	}
	var responseID string
	if json.Unmarshal(provider["id"], &responseID) != nil || responseID != q.Payload.ResponseID {
		return nil, ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := repository.temporalReady(bounded); err != nil {
		return nil, err
	}
	statusRequest, _ := json.Marshal(map[string]any{"organization_id": q.OrganizationID, "workspace_id": q.WorkspaceID, "environment_id": q.EnvironmentID, "run_id": q.RunID, "definition_version": q.DefinitionVersion})
	read := func() (json.RawMessage, error) {
		return repository.database.QueryJSON(bounded, `SELECT zasp_temporal68.status($1::jsonb)->'planning'`, statusRequest)
	}
	before, err := read()
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	job, ok := orderedTestArtifactObject(before, 524288, "organization_id", "workspace_id", "environment_id", "run_id", "definition_version", "run_version", "state", "budget_started_at", "budget_deadline_at", "context_value", "input_body", "input_digest", "input_artifact_id", "output_artifact_id", "reservation_id", "request_body", "request_digest", "lookup_request", "pricing_bound", "input_version", "raw_result", "result_value", "provider_digest", "output_body", "output_digest", "output_version", "receipt")
	if !ok || string(job["state"]) != `"needs_human"` || string(job["definition_version"]) != strconv.FormatInt(q.DefinitionVersion, 10) {
		return nil, ErrRepositoryUnavailable
	}
	for name, want := range map[string]string{"organization_id": q.OrganizationID, "workspace_id": q.WorkspaceID, "environment_id": q.EnvironmentID, "run_id": q.RunID, "reservation_id": q.Payload.ReservationID, "request_digest": q.Payload.RequestDigest} {
		if string(job[name]) != strconv.Quote(want) {
			return nil, ErrRepositoryUnavailable
		}
	}
	var lookup map[string]json.RawMessage
	if json.Unmarshal(job["lookup_request"], &lookup) != nil || string(lookup["credential_digest"]) != strconv.Quote(q.Payload.CredentialDigest) {
		return nil, ErrRepositoryUnavailable
	}
	result, err := repository.database.QueryJSON(bounded, `SELECT zasp_temporal68.plan($1::jsonb)`, raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	after, err := read()
	if err != nil || !bytes.Equal(before, result) || !bytes.Equal(before, after) {
		return nil, ErrRepositoryUnavailable
	}
	return result, nil
}
