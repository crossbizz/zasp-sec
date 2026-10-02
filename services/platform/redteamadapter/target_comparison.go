package redteamadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// TargetComparison is the database-pinned, redacted evaluation target identity.
type TargetComparison struct {
	Schema            string   `json:"schema_version"`
	Organization      string   `json:"organization_id"`
	Workspace         string   `json:"workspace_id"`
	Environment       string   `json:"environment_id"`
	Definition        string   `json:"test_definition_id"`
	DefinitionVersion int64    `json:"test_definition_version"`
	Target            string   `json:"target_id"`
	Kind              string   `json:"target_kind"`
	Categories        []string `json:"categories"`
	Safety            string   `json:"safety_digest"`
	Endpoint          string   `json:"endpoint_digest"`
	Configuration     string   `json:"configuration_digest"`
	Credential        string   `json:"credential_binding_id"`
	CredentialVersion int64    `json:"credential_binding_version"`
	CredentialDigest  string   `json:"credential_binding_digest"`
}

// Retain the database-owned comparison tuple without endpoint or credential
// reference plaintext. Canonical bytes make receipt comparisons deterministic.
func decodeTargetComparison(body []byte, r JournalRequest) (json.RawMessage, error) {
	fields, err := exactJournalObject(body, "schema_version organization_id workspace_id environment_id test_definition_id test_definition_version target_id target_kind categories safety_digest endpoint_digest configuration_digest credential_binding_id credential_binding_version credential_binding_digest")
	if err != nil || len(fields) != 15 {
		return nil, ErrAdapter
	}
	var value TargetComparison
	if json.Unmarshal(body, &value) != nil || value.Schema != "red-team-target-comparison-v1" || value.Organization != r.Invocation.Scope.OrganizationID().String() || value.Workspace != r.Invocation.Scope.WorkspaceID().String() || value.Environment != r.Invocation.Scope.EnvironmentID().String() || value.Target != r.Invocation.Binding.TargetID || value.Kind != r.Invocation.Binding.TargetKind || value.DefinitionVersion < 1 || value.CredentialVersion < 1 || len(value.Categories) < 1 || len(value.Categories) > len(curatedInputs) || !slices.Contains(value.Categories, r.Invocation.Category) {
		return nil, ErrAdapter
	}
	for _, id := range []string{value.Definition, value.Credential} {
		if _, err := domain.ParseProductID(id); err != nil {
			return nil, ErrAdapter
		}
	}
	for _, digest := range []string{value.Safety, value.Endpoint, value.Configuration, value.CredentialDigest} {
		if !validCredentialVersionDigest(digest) {
			return nil, ErrAdapter
		}
	}
	endpoint := sha256.Sum256([]byte(r.Invocation.Binding.Endpoint))
	// Credential binding digest is an opaque registered identity, not a hash
	// of the reference string. Its derivation belongs to binding authority.
	if value.Endpoint != hex.EncodeToString(endpoint[:]) {
		return nil, ErrAdapter
	}
	seen := make(map[string]bool)
	for _, category := range value.Categories {
		if _, ok := curatedInputs[category]; !ok || seen[category] {
			return nil, ErrAdapter
		}
		seen[category] = true
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrAdapter
	}
	return canonical, nil
}
