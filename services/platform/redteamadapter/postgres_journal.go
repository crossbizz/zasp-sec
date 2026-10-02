package redteamadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const postgresJournalStartSQL = `SELECT zasp_production_security_agent_existing_tests_invocation_start($1,$2,$3,$4,$5,$6,$7,$8,$9)`
const postgresJournalCompleteSQL = `SELECT zasp_production_security_agent_existing_tests_invocation_complete($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const postgresJournalResolveSQL = `SELECT zasp_production_security_agent_existing_tests_invocation_resolve($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

// PostgresInvocationJournal uses only guarded adapter entrypoints, never
// private cores. QueryJSON must finish the autocommit statement (including commit
// errors) before returning; a transaction-scoped implementation is not suitable.
type PostgresInvocationJournal struct {
	database              JSONDatabase
	checksum, fingerprint string
	orderedMode           bool
}

func NewPostgresInvocationJournal(database JSONDatabase, checksum, fingerprint string) (*PostgresInvocationJournal, error) {
	if nilJSONDatabase(database) || !releaseDigestPattern.MatchString(checksum) || !releaseDigestPattern.MatchString(fingerprint) {
		return nil, ErrAdapter
	}
	return &PostgresInvocationJournal{database: database, checksum: checksum, fingerprint: fingerprint}, nil
}

func nilJSONDatabase(database JSONDatabase) bool {
	if database == nil {
		return true
	}
	value := reflect.ValueOf(database)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// ValidOrderedConfiguration is a zero-I/O check for the ordered SQL mode,
// exact release identity, and usable database required before readiness.
func (j *PostgresInvocationJournal) ValidOrderedConfiguration(checksum, fingerprint string) bool {
	return j != nil && j.orderedMode && !nilJSONDatabase(j.database) && releaseDigestPattern.MatchString(checksum) && releaseDigestPattern.MatchString(fingerprint) && j.checksum == checksum && j.fingerprint == fingerprint
}

func (j *PostgresInvocationJournal) Ready(ctx context.Context) error {
	if j == nil || nilJSONDatabase(j.database) || !releaseDigestPattern.MatchString(j.checksum) || !releaseDigestPattern.MatchString(j.fingerprint) || ctx == nil || ctx.Err() != nil {
		return ErrAdapter
	}
	value, err := j.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_production_security_agent_existing_tests_client_ready($1,$2))`, j.checksum, j.fingerprint)
	if err != nil || string(value) != "true" || ctx.Err() != nil {
		return ErrAdapter
	}
	value, err = j.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_red_team_principal_ready($1))`, "zasp_red_team_adapter")
	if err != nil || string(value) != "true" || ctx.Err() != nil {
		return ErrAdapter
	}
	return nil
}

func (j *PostgresInvocationJournal) ResolveTarget(ctx context.Context, r TargetResolution) (TargetBinding, error) {
	_, runErr := domain.ParseProductID(r.RunID)
	if j == nil || j.database == nil || ctx == nil || ctx.Err() != nil || r.Scope.Validate() != nil || runErr != nil || r.RunID == r.TargetID || !runLeaseRE.MatchString(r.LeaseToken) || !validRequestBody(requestBody{TargetID: r.TargetID, TargetKind: r.TargetKind, Category: r.Category, Input: curatedInputs[r.Category]}) {
		return TargetBinding{}, ErrAdapter
	}
	body, err := j.database.QueryJSON(ctx, postgresJournalResolveSQL, r.Scope.OrganizationID().String(), r.Scope.WorkspaceID().String(), r.Scope.EnvironmentID().String(), r.TargetID, r.TargetKind, r.RunID, []byte(r.LeaseToken), r.Category, j.checksum, j.fingerprint)
	if err != nil || len(body) < 2 || len(body) > 16384 {
		return TargetBinding{}, ErrAdapter
	}
	fields, err := exactJournalObject(body, "target_id target_kind endpoint credential_reference version")
	var binding TargetBinding
	if err != nil || len(fields) != 5 || json.Unmarshal(body, &binding) != nil || !validBinding(binding) || binding.TargetID != r.TargetID || binding.TargetKind != r.TargetKind {
		return TargetBinding{}, ErrAdapter
	}
	return binding, nil
}

func (j *PostgresInvocationJournal) valid(ctx context.Context, r JournalRequest) bool {
	_, err := domain.ParseProductID(r.Invocation.RunID)
	if j == nil || j.database == nil || ctx == nil || ctx.Err() != nil || err != nil || r.Invocation.Scope.Validate() != nil || r.Invocation.RunID == r.Invocation.Binding.TargetID || !runLeaseRE.MatchString(r.LeaseToken) || !validBinding(r.Invocation.Binding) || !validRequestBody(requestBody{TargetID: r.Invocation.Binding.TargetID, TargetKind: r.Invocation.Binding.TargetKind, Category: r.Invocation.Category, Input: r.Invocation.Input}) {
		return false
	}
	body, err := targetPayload(r.Invocation)
	digest := sha256.Sum256(body)
	return err == nil && r.RequestDigest == hex.EncodeToString(digest[:])
}

func (j *PostgresInvocationJournal) Start(ctx context.Context, r JournalRequest) (InvocationReceipt, error) {
	if !j.valid(ctx, r) {
		return InvocationReceipt{}, ErrAdapter
	}
	digest, _ := hex.DecodeString(r.RequestDigest)
	s := r.Invocation.Scope
	body, err := j.database.QueryJSON(ctx, postgresJournalStartSQL, s.OrganizationID().String(), s.WorkspaceID().String(), s.EnvironmentID().String(), r.Invocation.RunID, []byte(r.LeaseToken), r.Invocation.Category, digest, j.checksum, j.fingerprint)
	if err != nil {
		return InvocationReceipt{}, ErrAdapter
	}
	return decodeJournalReceipt(body, r)
}

func (j *PostgresInvocationJournal) Complete(ctx context.Context, r JournalRequest, attempt int, observation InvocationObservation) error {
	if !j.valid(ctx, r) || attempt < 1 || attempt > 5 || !validInvocationObservation(observation) || !validCredentialVersionDigest(observation.CredentialVersionDigest) {
		return ErrAdapter
	}
	digest, _ := hex.DecodeString(r.RequestDigest)
	responseDigest, _ := hex.DecodeString(observation.ResponseDigest)
	credentialDigest, _ := hex.DecodeString(observation.CredentialVersionDigest)
	s := r.Invocation.Scope
	body, err := j.database.QueryJSON(ctx, postgresJournalCompleteSQL, s.OrganizationID().String(), s.WorkspaceID().String(), s.EnvironmentID().String(), r.Invocation.RunID, attempt, []byte(r.LeaseToken), r.Invocation.Category, digest, observation.HTTPStatus, responseDigest, *observation.Protected, credentialDigest, j.checksum, j.fingerprint)
	if err != nil {
		return ErrAdapter
	}
	receipt, err := decodeJournalReceipt(body, r)
	if err != nil || receipt.State != "completed" || receipt.Attempt != attempt || receipt.Observation == nil || receipt.Observation.HTTPStatus != observation.HTTPStatus || receipt.Observation.ResponseDigest != observation.ResponseDigest || receipt.Observation.CredentialVersionDigest != observation.CredentialVersionDigest || receipt.Observation.Protected == nil || *receipt.Observation.Protected != *observation.Protected {
		return ErrAdapter
	}
	return nil
}

// exactJournalObject rejects duplicate/case-aliased keys as well as extra keys.
// SQL jsonb does not emit duplicates, but the client boundary must not silently
// turn an ambiguous or incompatible receipt into permission to send a request.
func exactJournalObject(body []byte, allowed string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrAdapter
	}
	result := make(map[string]json.RawMessage)
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !slices.Contains(strings.Fields(allowed), key) {
			return nil, ErrAdapter
		}
		if _, exists := result[key]; exists {
			return nil, ErrAdapter
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrAdapter
		}
		result[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrAdapter
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrAdapter
	}
	return result, nil
}

func decodeJournalReceipt(body []byte, r JournalRequest) (InvocationReceipt, error) {
	fail := func() (InvocationReceipt, error) { return InvocationReceipt{}, ErrAdapter }
	if len(body) < 2 || len(body) > 16384 {
		return fail()
	}
	fields, err := exactJournalObject(body, "state attempt category input_digest request_digest target_binding target_provenance target_comparison run_id http_status response_digest protected completed_at credential_version_digest")
	if err != nil {
		return fail()
	}
	var wire struct {
		State                   string        `json:"state"`
		Attempt                 int           `json:"attempt"`
		Category                string        `json:"category"`
		InputDigest             string        `json:"input_digest"`
		RequestDigest           string        `json:"request_digest"`
		Binding                 TargetBinding `json:"target_binding"`
		RunID                   string        `json:"run_id"`
		HTTPStatus              int           `json:"http_status"`
		ResponseDigest          string        `json:"response_digest"`
		Protected               *bool         `json:"protected"`
		CompletedAt             string        `json:"completed_at"`
		CredentialVersionDigest string        `json:"credential_version_digest"`
		Provenance              struct {
			IntegrationID string `json:"integration_id"`
			SnapshotID    string `json:"snapshot_id"`
			EvidenceID    string `json:"evidence_id"`
			Source        string `json:"source"`
			Generation    int64  `json:"generation"`
		} `json:"target_provenance"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Attempt < 1 || wire.Attempt > 5 || wire.Category != r.Invocation.Category || !releaseDigestPattern.MatchString(wire.InputDigest) || wire.RequestDigest != r.RequestDigest || !validBinding(wire.Binding) || wire.Binding != r.Invocation.Binding {
		return fail()
	}
	binding, err := exactJournalObject(fields["target_binding"], "target_id target_kind endpoint credential_reference version")
	if err != nil || len(binding) != 5 {
		return fail()
	}
	provenance, err := exactJournalObject(fields["target_provenance"], "integration_id snapshot_id evidence_id source generation")
	if err != nil || len(provenance) != 5 || strings.TrimSpace(wire.Provenance.Source) == "" || wire.Provenance.Generation < 1 {
		return fail()
	}
	for _, id := range []string{wire.Provenance.IntegrationID, wire.Provenance.SnapshotID, wire.Provenance.EvidenceID} {
		if _, err := domain.ParseProductID(id); err != nil {
			return fail()
		}
	}
	result := InvocationReceipt{TargetBinding: wire.Binding, State: wire.State, Attempt: wire.Attempt, RequestDigest: wire.RequestDigest}
	result.TargetComparison, err = decodeTargetComparison(fields["target_comparison"], r)
	if err != nil {
		return fail()
	}
	if wire.State == "started" {
		if len(fields) != 8 {
			return fail()
		}
		return result, nil
	}
	observation := InvocationObservation{HTTPStatus: wire.HTTPStatus, ResponseDigest: wire.ResponseDigest, Protected: wire.Protected, CredentialVersionDigest: wire.CredentialVersionDigest}
	var comparison TargetComparison
	if json.Unmarshal(result.TargetComparison, &comparison) != nil {
		return fail()
	}
	observation.TargetComparison = &comparison
	if wire.State != "completed" || len(fields) != 14 || wire.RunID != r.Invocation.RunID || !validInvocationObservation(observation) || !validCredentialVersionDigest(wire.CredentialVersionDigest) {
		return fail()
	}
	if _, err := time.Parse(time.RFC3339Nano, wire.CompletedAt); err != nil {
		return fail()
	}
	result.Observation = &observation
	return result, nil
}

var _ InvocationJournal = (*PostgresInvocationJournal)(nil)
var _ TargetResolver = (*PostgresInvocationJournal)(nil)

func validCredentialVersionDigest(value string) bool {
	return releaseDigestPattern.MatchString(value) && value != strings.Repeat("0", 64)
}
