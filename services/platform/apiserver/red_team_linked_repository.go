package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/legacytests"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresLinkedRedTeamReadySQL = `SELECT to_jsonb(zasp_production_security_agent_existing_tests_client_ready($1,$2))`
const postgresLinkedRedTeamProtocolSQL = `SELECT zasp_production_security_agent_existing_tests_worker_protocol($1,$2,$3,$4,$5,$6)`
const postgresLinkedRedTeamClaimSQL = `SELECT zasp_production_security_agent_existing_tests_worker_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)`
const postgresLinkedRedTeamHeartbeatSQL = `SELECT zasp_production_security_agent_existing_tests_worker_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9)`
const postgresLinkedRedTeamCancelSQL = `SELECT zasp_production_security_agent_existing_tests_worker_cancel($1,$2,$3,$4,$5,$6,$7,$8,$9)`
const postgresLinkedRedTeamFinishSQL = `SELECT zasp_production_security_agent_existing_tests_worker_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21)`

func (r *LinkedRedTeamExecutionRepository) FinishRedTeamRun(ctx context.Context, scope domain.Scope, input RedTeamRunCompletion) (RedTeamRun, error) {
	if len(input.EvidenceArtifact) == 0 || len(input.EvidenceArtifact) > 1<<20 || int64(len(input.EvidenceArtifact)) != input.EvidenceSizeBytes {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	artifactDigest := sha256.Sum256(input.EvidenceArtifact)
	if !bytes.Equal(artifactDigest[:], input.EvidenceChecksum) || !json.Valid(input.EvidenceArtifact) {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validProductID(input.RunID) || !validRedTeamWorkerLease(input.Worker, input.LeaseToken) || input.InputArtifact == nil || !validRedTeamCompletion(scope, input) || input.EvidenceSizeBytes > 1<<20 || input.Verdict == "engine_error" && input.ErrorCode != "outcome_unknown" {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	evidence, err := json.Marshal(input.Evidence)
	if err != nil {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	receipt, err := json.Marshal(input.InputArtifact)
	if err != nil {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	var errorCode any
	if input.ErrorCode != "" {
		errorCode = input.ErrorCode
	}
	raw, err := r.database.QueryJSON(ctx, postgresLinkedRedTeamFinishSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.RunID, input.Worker, []byte(input.LeaseToken), input.InputDigest[:], input.Verdict, input.Objective, input.Behavior, errorCode, evidence, input.EvidenceReference, input.EvidenceKey, input.EvidenceVersionID, input.EvidenceChecksum, input.EvidenceSizeBytes, receipt, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint(), input.EvidenceArtifact)
	fields := []string{"id", "version", "definition_id", "definition_version", "status", "attempt", "cancel_requested", "queued_at", "started_at", "completed_at", "verdict", "evidence_reference"}
	if input.ErrorCode != "" {
		fields = append(fields, "error_code")
	}
	if err != nil || ctx.Err() != nil || len(raw) > 16384 || !budgetJSONFields(raw, fields...) {
		return RedTeamRun{}, ErrRepositoryUnavailable
	}
	result, err := decodeRedTeamWorkerRun(raw, nil, input.RunID, "complete")
	if err != nil || result.CancelRequested || result.Verdict != input.Verdict || result.ErrorCode != input.ErrorCode || result.EvidenceReference != input.EvidenceReference {
		return RedTeamRun{}, ErrRepositoryUnavailable
	}
	return result, nil
}

// QueryJSON must complete the autocommit statement, including commit errors,
// before returning a lease. The worker router selects this client only from
// persisted protocol classification; feature activation has separate gates.
type LinkedRedTeamDatabase interface {
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
}

type LinkedRedTeamExecutionRepository struct{ database LinkedRedTeamDatabase }

func (r *LinkedRedTeamExecutionRepository) RunProtocol(ctx context.Context, scope domain.Scope, runID string) (string, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validProductID(runID) {
		return "", ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, postgresLinkedRedTeamProtocolSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil || ctx.Err() != nil || len(raw) > 1024 || !budgetJSONFields(raw, "protocol") {
		return "", ErrRepositoryUnavailable
	}
	var result struct {
		Protocol string `json:"protocol"`
	}
	if decodeStrictDiscovery(raw, &result) != nil || !stringIn(result.Protocol, "linked", "legacy") {
		return "", ErrRepositoryUnavailable
	}
	return result.Protocol, nil
}

// A separate method prevents the linked processor from accidentally selecting
// legacy cancellation, which cannot classify durable invocation uncertainty.
func (r *LinkedRedTeamExecutionRepository) CancelLinkedRedTeamRun(ctx context.Context, scope domain.Scope, runID, worker, leaseToken string, inputDigest [sha256.Size]byte) (RedTeamRun, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validProductID(runID) || !validRedTeamWorkerLease(worker, leaseToken) || inputDigest == [sha256.Size]byte{} {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, postgresLinkedRedTeamCancelSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, worker, []byte(leaseToken), inputDigest[:], migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil || ctx.Err() != nil || len(raw) > 16384 || !budgetJSONFields(raw, "run", "cancellation_outcome") {
		return RedTeamRun{}, ErrRepositoryUnavailable
	}
	fields, _ := budgetJSONObject(raw)
	if !budgetJSONFields(fields["run"], "id", "version", "definition_id", "definition_version", "status", "attempt", "cancel_requested", "queued_at", "started_at", "completed_at", "error_code") {
		return RedTeamRun{}, ErrRepositoryUnavailable
	}
	var result struct {
		Run     RedTeamRun `json:"run"`
		Outcome string     `json:"cancellation_outcome"`
	}
	if decodeStrictDiscovery(raw, &result) != nil || !validRedTeamRun(result.Run) || result.Run.ID != runID || result.Run.Attempt < 1 || !result.Run.CancelRequested {
		return RedTeamRun{}, ErrRepositoryUnavailable
	}
	if result.Outcome == "outcome_unknown" {
		if result.Run.Status != "failed" || result.Run.ErrorCode != "outcome_unknown" {
			return RedTeamRun{}, ErrRepositoryUnavailable
		}
	} else if !stringIn(result.Outcome, "cancelled_before_execution", "cancelled_after_partial_execution") || result.Run.Status != "cancelled" || result.Run.ErrorCode != "cancelled" {
		return RedTeamRun{}, ErrRepositoryUnavailable
	}
	return result.Run, nil
}

func NewLinkedRedTeamExecutionRepository(database LinkedRedTeamDatabase) (*LinkedRedTeamExecutionRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if probe, ok := database.(interface {
		LegacyTestsAvailable(context.Context, string) (bool, error)
	}); ok {
		installed, err := probe.LegacyTestsAvailable(ctx, "zasp_red_team_worker")
		if err != nil {
			return nil, ErrRepositoryConfiguration
		}
		if installed {
			database = legacytests.Database{DB: database, Role: "zasp_red_team_worker"}
		}
	}
	repo := &LinkedRedTeamExecutionRepository{database: database}
	if repo.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repo, nil
}

func (r *LinkedRedTeamExecutionRepository) Ready(ctx context.Context) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	raw, err := r.database.QueryJSON(ctx, postgresLinkedRedTeamReadySQL, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(raw, &ready) != nil || !ready || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	raw, err = r.database.QueryJSON(ctx, postgresRedTeamPrincipalReadySQL, RedTeamExecutionAuthorityWorker)
	ready = false
	if err != nil || decodeStrictDiscovery(raw, &ready) != nil || !ready || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (r *LinkedRedTeamExecutionRepository) ClaimRedTeamRun(ctx context.Context, scope domain.Scope, runID, worker, leaseToken string, leaseSeconds int) (RedTeamRunClaim, error) {
	fail := RedTeamRunClaim{}
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validProductID(runID) || !validRedTeamWorkerLease(worker, leaseToken) || leaseSeconds < 30 || leaseSeconds > 900 {
		return fail, ErrRepositoryOperation
	}
	// The SQL entrypoint revalidates role and release on every operation. Never
	// fall back to an unpinned legacy claim when this call is unavailable.
	raw, err := r.database.QueryJSON(ctx, postgresLinkedRedTeamClaimSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, worker, []byte(leaseToken), leaseSeconds, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil || ctx.Err() != nil || len(raw) > 16*1024 {
		return fail, ErrRepositoryUnavailable
	}
	fields, ok := budgetJSONObject(raw)
	if !ok {
		return fail, ErrRepositoryUnavailable
	}
	var disposition string
	if json.Unmarshal(fields["disposition"], &disposition) != nil {
		return fail, ErrRepositoryUnavailable
	}
	if disposition != "claimed" {
		if len(fields) != 1 || !stringIn(disposition, "retry_later", "ack_terminal", "reconcile_required") {
			return fail, ErrRepositoryUnavailable
		}
		return RedTeamRunClaim{Disposition: disposition}, nil
	}
	if !budgetJSONFields(raw, "disposition", "evidence_version", "run", "definition", "input_digest", "lease_expires_at") ||
		!budgetJSONFields(fields["run"], "id", "version", "definition_id", "definition_version", "status", "attempt", "cancel_requested", "queued_at", "started_at") ||
		!budgetJSONFields(fields["definition"], "id", "version", "name", "target_id", "target_kind", "categories", "safety", "enabled", "created_at", "updated_at") {
		return fail, ErrRepositoryUnavailable
	}
	definitionFields, _ := budgetJSONObject(fields["definition"])
	if !budgetJSONFields(definitionFields["safety"], "environment", "credential_class", "expected_side_effects") {
		return fail, ErrRepositoryUnavailable
	}
	var wire struct {
		Disposition     string            `json:"disposition"`
		EvidenceVersion string            `json:"evidence_version"`
		Run             RedTeamRun        `json:"run"`
		Definition      RedTeamDefinition `json:"definition"`
		InputDigest     string            `json:"input_digest"`
		LeaseExpiresAt  time.Time         `json:"lease_expires_at"`
	}
	if decodeStrictDiscovery(raw, &wire) != nil {
		return fail, ErrRepositoryUnavailable
	}
	digest, err := hex.DecodeString(wire.InputDigest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != wire.InputDigest || bytes.Equal(digest, make([]byte, sha256.Size)) || wire.EvidenceVersion != "red-team-v2" || wire.Run.ID != runID || wire.Run.Status != "leased" || wire.Run.CancelRequested || !validRedTeamRun(wire.Run) || wire.Definition.ID != wire.Run.DefinitionID || wire.Definition.Version != wire.Run.DefinitionVersion || !wire.Definition.Enabled || !validRedTeamDefinition(wire.Definition) || !validLeaseExpiration(wire.LeaseExpiresAt, leaseSeconds) {
		return fail, ErrRepositoryUnavailable
	}
	result := RedTeamRunClaim{Disposition: wire.Disposition, EvidenceVersion: wire.EvidenceVersion, Run: wire.Run, Definition: wire.Definition, LeaseExpiresAt: wire.LeaseExpiresAt.UTC()}
	copy(result.InputDigest[:], digest)
	return result, nil
}

func (r *LinkedRedTeamExecutionRepository) HeartbeatRedTeamRun(ctx context.Context, scope domain.Scope, runID, worker, leaseToken string, leaseSeconds int) (RedTeamRunHeartbeat, error) {
	fail := RedTeamRunHeartbeat{}
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validProductID(runID) || !validRedTeamWorkerLease(worker, leaseToken) || leaseSeconds < 30 || leaseSeconds > 900 {
		return fail, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, postgresLinkedRedTeamHeartbeatSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, worker, []byte(leaseToken), leaseSeconds, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil || ctx.Err() != nil || len(raw) > 1024 {
		return fail, ErrRepositoryUnavailable
	}
	var result RedTeamRunHeartbeat
	if decodeStrictDiscovery(raw, &result) != nil {
		return fail, ErrRepositoryUnavailable
	}
	if result.Renewed {
		if !budgetJSONFields(raw, "renewed", "cancel_requested", "lease_expires_at") || result.CancelRequested || result.LeaseExpiresAt == nil || !validLeaseExpiration(*result.LeaseExpiresAt, leaseSeconds) {
			return fail, ErrRepositoryUnavailable
		}
		expires := result.LeaseExpiresAt.UTC()
		result.LeaseExpiresAt = &expires
	} else if !budgetJSONFields(raw, "renewed", "cancel_requested") || result.LeaseExpiresAt != nil {
		return fail, ErrRepositoryUnavailable
	}
	return result, nil
}
