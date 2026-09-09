package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	RedTeamExecutionAuthorityWorker = "zasp_red_team_worker"
	RedTeamExecutionAuthorityOutbox = "zasp_red_team_outbox_worker"
	RedTeamOutboxTopic              = "test-jobs"

	postgresRedTeamPrincipalReadySQL     = `SELECT to_jsonb(zasp_red_team_principal_ready($1))`
	postgresRedTeamClaimOutboxSQL        = `SELECT zasp_red_team_claim_outbox($1,$2,$3,$4)`
	postgresRedTeamHeartbeatOutboxSQL    = `SELECT to_jsonb(zasp_red_team_heartbeat_outbox($1,$2,$3,$4,$5,$6,$7))`
	postgresRedTeamAckOutboxSQL          = `SELECT to_jsonb(zasp_red_team_ack_outbox($1,$2,$3,$4,$5,$6,$7))`
	postgresRedTeamRetryOutboxSQL        = `SELECT to_jsonb(zasp_red_team_retry_outbox($1,$2,$3,$4,$5,$6,$7))`
	postgresRedTeamClaimRunSQL           = `SELECT zasp_red_team_claim_run($1,$2,$3,$4,$5,$6,$7)`
	postgresRedTeamHeartbeatRunSQL       = `SELECT zasp_red_team_heartbeat_run($1,$2,$3,$4,$5,$6,$7)`
	postgresRedTeamFinishRunSQL          = `SELECT zasp_red_team_finish_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17)`
	postgresRedTeamFinishRunArtifactsSQL = `SELECT zasp_red_team_finish_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18::jsonb)`
	postgresRedTeamRetryRunSQL           = `SELECT zasp_red_team_retry_run($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresRedTeamCancelClaimedRunSQL   = `SELECT zasp_red_team_cancel_claimed_run($1,$2,$3,$4,$5,$6,$7)`
)

var (
	redTeamWorkerPattern     = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,127}$`)
	redTeamLeaseTokenPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

type RedTeamExecutionRepository struct {
	database  JSONDatabase
	authority string
}

type RedTeamOutboxEvent struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	ID             string
	Topic          string
	Payload        json.RawMessage
	PayloadDigest  []byte
	Attempt        int
	LeaseExpiresAt time.Time
}

type RedTeamRunClaim struct {
	Disposition    string
	Run            RedTeamRun
	Definition     RedTeamDefinition
	InputDigest    [sha256.Size]byte
	LeaseExpiresAt time.Time
}

type RedTeamRunHeartbeat struct {
	Renewed         bool `json:"renewed"`
	CancelRequested bool `json:"cancel_requested"`
}

type RedTeamRunCompletion struct {
	InputArtifact                                     *RedTeamArtifactReference
	RunID, Worker, LeaseToken                         string
	InputDigest                                       [sha256.Size]byte
	Verdict, Objective, Behavior, ErrorCode           string
	Evidence                                          []string
	EvidenceReference, EvidenceKey, EvidenceVersionID string
	EvidenceChecksum                                  []byte
	EvidenceSizeBytes                                 int64
}

func NewRedTeamExecutionRepository(database JSONDatabase, authority string) (*RedTeamExecutionRepository, error) {
	if nilInterface(database) || !stringIn(authority, RedTeamExecutionAuthorityWorker, RedTeamExecutionAuthorityOutbox) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	repository := &RedTeamExecutionRepository{database: database, authority: authority}
	if repository.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *RedTeamExecutionRepository) Ready(ctx context.Context) error {
	if !validRedTeamExecutionRepository(repository, ctx) {
		return ErrRepositoryUnavailable
	}
	var ready bool
	metadata := migrations.ProductionRecovery()
	payload, err := repository.database.QueryJSON(ctx, postgresProductionRecoveryReadinessSQL, metadata.Checksum(), migrations.ProductionRecoverySemanticFingerprint())
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		metadata := migrations.ProductionRedTeamExecution()
		payload, err = repository.database.QueryJSON(ctx, postgresRedTeamExecutionReadinessSQL, metadata.Checksum(), migrations.ProductionRedTeamExecutionSemanticFingerprint())
		ready = false
	}
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	payload, err = repository.database.QueryJSON(ctx, postgresRedTeamPrincipalReadySQL, repository.authority)
	ready = false
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *RedTeamExecutionRepository) ReadyArtifacts(ctx context.Context) error {
	if repository.Ready(ctx) != nil {
		return ErrRepositoryUnavailable
	}
	metadata := migrations.ProductionRedTeamArtifacts()
	payload, err := repository.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_production_red_team_artifacts_readiness($1,$2))`, metadata.Checksum(), migrations.ProductionRedTeamArtifactsSemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *RedTeamExecutionRepository) ClaimRedTeamOutbox(ctx context.Context, worker, leaseToken string, leaseSeconds, limit int) ([]RedTeamOutboxEvent, error) {
	if !validRedTeamAuthority(repository, ctx, RedTeamExecutionAuthorityOutbox) || !validRedTeamWorkerLease(worker, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 100 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamClaimOutboxSQL, worker, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var wire []struct {
		OrganizationID string    `json:"organization_id"`
		WorkspaceID    string    `json:"workspace_id"`
		EnvironmentID  string    `json:"environment_id"`
		OutboxID       string    `json:"outbox_id"`
		Topic          string    `json:"topic"`
		Payload        string    `json:"payload"`
		PayloadDigest  string    `json:"payload_digest"`
		Attempt        int       `json:"attempt"`
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	}
	if decodeStrictDiscovery(payload, &wire) != nil || len(wire) > limit {
		return nil, ErrRepositoryUnavailable
	}
	result := make([]RedTeamOutboxEvent, len(wire))
	seen := make(map[string]struct{}, len(wire))
	for index, item := range wire {
		organization, organizationErr := domain.ParseProductID(item.OrganizationID)
		workspace, workspaceErr := domain.ParseProductID(item.WorkspaceID)
		environment, environmentErr := domain.ParseProductID(item.EnvironmentID)
		outbox, outboxErr := domain.ParseProductID(item.OutboxID)
		scope, scopeErr := domain.NewScope(organization, workspace, environment)
		digest, digestErr := hex.DecodeString(item.PayloadDigest)
		actual := sha256.Sum256([]byte(item.Payload))
		if organizationErr != nil || workspaceErr != nil || environmentErr != nil || outboxErr != nil || scopeErr != nil || outbox.IsZero() || item.Topic != RedTeamOutboxTopic || len(item.Payload) < 2 || len(item.Payload) > 65_536 || digestErr != nil || len(digest) != sha256.Size || subtle.ConstantTimeCompare(digest, actual[:]) != 1 || item.Attempt < 1 || item.Attempt > 100 || !validLeaseExpiration(item.LeaseExpiresAt, leaseSeconds) {
			return nil, ErrRepositoryUnavailable
		}
		if _, duplicate := seen[item.OutboxID]; duplicate {
			return nil, ErrRepositoryUnavailable
		}
		seen[item.OutboxID] = struct{}{}
		result[index] = RedTeamOutboxEvent{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ID: item.OutboxID, Topic: item.Topic, Payload: json.RawMessage(bytes.Clone([]byte(item.Payload))), PayloadDigest: bytes.Clone(digest), Attempt: item.Attempt, LeaseExpiresAt: item.LeaseExpiresAt.UTC()}
	}
	return result, nil
}

func (repository *RedTeamExecutionRepository) HeartbeatRedTeamOutbox(ctx context.Context, scope domain.Scope, id, worker, leaseToken string, leaseSeconds int) (bool, error) {
	if !validRedTeamOutboxTransition(repository, ctx, scope, id, worker, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 {
		return false, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamHeartbeatOutboxSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, leaseSeconds)
	return decodeRedTeamBoolean(payload, err)
}

func (repository *RedTeamExecutionRepository) AcknowledgeRedTeamOutbox(ctx context.Context, scope domain.Scope, id, worker, leaseToken, providerAck string) error {
	if !validRedTeamOutboxTransition(repository, ctx, scope, id, worker, leaseToken) || !outboxProviderAckPattern.MatchString(providerAck) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamAckOutboxSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, providerAck)
	updated, decodeErr := decodeRedTeamBoolean(payload, err)
	if decodeErr != nil || !updated {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *RedTeamExecutionRepository) RetryRedTeamOutbox(ctx context.Context, scope domain.Scope, id, worker, leaseToken string, retryAt time.Time) error {
	now := time.Now().UTC()
	if !validRedTeamOutboxTransition(repository, ctx, scope, id, worker, leaseToken) || retryAt.Location() != time.UTC || retryAt.Before(now) || retryAt.After(now.Add(time.Hour)) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamRetryOutboxSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, retryAt)
	updated, decodeErr := decodeRedTeamBoolean(payload, err)
	if decodeErr != nil || !updated {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *RedTeamExecutionRepository) ClaimRedTeamRun(ctx context.Context, scope domain.Scope, runID, worker, leaseToken string, leaseSeconds int) (RedTeamRunClaim, error) {
	if !validRedTeamRunTransition(repository, ctx, scope, runID, worker, leaseToken) || leaseSeconds < 30 || leaseSeconds > 900 {
		return RedTeamRunClaim{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamClaimRunSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, worker, leaseToken, leaseSeconds)
	if err != nil {
		return RedTeamRunClaim{}, discoveryProviderError(err)
	}
	var wire struct {
		Disposition    string            `json:"disposition"`
		Run            RedTeamRun        `json:"run"`
		Definition     RedTeamDefinition `json:"definition"`
		InputDigest    string            `json:"input_digest"`
		LeaseExpiresAt time.Time         `json:"lease_expires_at"`
	}
	if decodeStrictDiscovery(payload, &wire) != nil || !stringIn(wire.Disposition, "claimed", "retry_later", "ack_terminal") {
		return RedTeamRunClaim{}, ErrRepositoryUnavailable
	}
	result := RedTeamRunClaim{Disposition: wire.Disposition}
	if wire.Disposition != "claimed" {
		if wire.Run.ID != "" || wire.Definition.ID != "" || wire.InputDigest != "" || !wire.LeaseExpiresAt.IsZero() {
			return RedTeamRunClaim{}, ErrRepositoryUnavailable
		}
		return result, nil
	}
	digest, digestErr := hex.DecodeString(wire.InputDigest)
	if digestErr != nil || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) || wire.Run.ID != runID || wire.Run.Status != "leased" || !validRedTeamRun(wire.Run) || wire.Definition.ID != wire.Run.DefinitionID || wire.Definition.Version != wire.Run.DefinitionVersion || !validRedTeamDefinition(wire.Definition) || !validLeaseExpiration(wire.LeaseExpiresAt, leaseSeconds) {
		return RedTeamRunClaim{}, ErrRepositoryUnavailable
	}
	copy(result.InputDigest[:], digest)
	result.Run, result.Definition, result.LeaseExpiresAt = wire.Run, wire.Definition, wire.LeaseExpiresAt.UTC()
	return result, nil
}

func (repository *RedTeamExecutionRepository) HeartbeatRedTeamRun(ctx context.Context, scope domain.Scope, runID, worker, leaseToken string, leaseSeconds int) (RedTeamRunHeartbeat, error) {
	if !validRedTeamRunTransition(repository, ctx, scope, runID, worker, leaseToken) || leaseSeconds < 30 || leaseSeconds > 900 {
		return RedTeamRunHeartbeat{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamHeartbeatRunSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, worker, leaseToken, leaseSeconds)
	var result RedTeamRunHeartbeat
	if err != nil || decodeStrictDiscovery(payload, &result) != nil {
		return RedTeamRunHeartbeat{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *RedTeamExecutionRepository) FinishRedTeamRun(ctx context.Context, scope domain.Scope, input RedTeamRunCompletion) (RedTeamRun, error) {
	if !validRedTeamRunTransition(repository, ctx, scope, input.RunID, input.Worker, input.LeaseToken) || !validRedTeamCompletion(scope, input) {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	evidence, marshalErr := json.Marshal(input.Evidence)
	if marshalErr != nil {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	var errorCode any
	if input.ErrorCode != "" {
		errorCode = input.ErrorCode
	}
	statement := postgresRedTeamFinishRunSQL
	arguments := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.RunID, input.Worker, input.LeaseToken, input.InputDigest[:], input.Verdict, input.Objective, input.Behavior, errorCode, evidence, input.EvidenceReference, input.EvidenceKey, input.EvidenceVersionID, input.EvidenceChecksum, input.EvidenceSizeBytes}
	if input.InputArtifact != nil {
		encoded, err := json.Marshal(input.InputArtifact)
		if err != nil {
			return RedTeamRun{}, ErrRepositoryOperation
		}
		statement = postgresRedTeamFinishRunArtifactsSQL
		arguments = append(arguments, encoded)
	}
	payload, err := repository.database.QueryJSON(ctx, statement, arguments...)
	return decodeRedTeamWorkerRun(payload, err, input.RunID, "complete")
}

func (repository *RedTeamExecutionRepository) RetryRedTeamRun(ctx context.Context, scope domain.Scope, runID, worker, leaseToken string, inputDigest [sha256.Size]byte, code string, retryAt time.Time) (RedTeamRun, error) {
	now := time.Now().UTC()
	if !validRedTeamRunTransition(repository, ctx, scope, runID, worker, leaseToken) || inputDigest == [sha256.Size]byte{} || !stringIn(code, "retryable", "rate_limited", "denied", "malformed", "outcome_unknown") || retryAt.Location() != time.UTC || retryAt.Before(now) || retryAt.After(now.Add(time.Hour)) {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamRetryRunSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, worker, leaseToken, inputDigest[:], code, retryAt)
	result, decodeErr := decodeRedTeamWorkerRun(payload, err, runID, "retryable", "failed")
	if decodeErr == nil && result.Status == "failed" && result.ErrorCode != "exhausted" {
		return RedTeamRun{}, ErrRepositoryUnavailable
	}
	return result, decodeErr
}

func (repository *RedTeamExecutionRepository) CancelClaimedRedTeamRun(ctx context.Context, scope domain.Scope, runID, worker, leaseToken string, inputDigest [sha256.Size]byte) (RedTeamRun, error) {
	if !validRedTeamRunTransition(repository, ctx, scope, runID, worker, leaseToken) || inputDigest == [sha256.Size]byte{} {
		return RedTeamRun{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamCancelClaimedRunSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, worker, leaseToken, inputDigest[:])
	return decodeRedTeamWorkerRun(payload, err, runID, "cancelled")
}

func validRedTeamExecutionRepository(repository *RedTeamExecutionRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && stringIn(repository.authority, RedTeamExecutionAuthorityWorker, RedTeamExecutionAuthorityOutbox) && ctx != nil && ctx.Err() == nil
}

func validRedTeamAuthority(repository *RedTeamExecutionRepository, ctx context.Context, authority string) bool {
	return validRedTeamExecutionRepository(repository, ctx) && repository.authority == authority
}

func validRedTeamWorkerLease(worker, token string) bool {
	return redTeamWorkerPattern.MatchString(worker) && redTeamLeaseTokenPattern.MatchString(token)
}

func validRedTeamOutboxTransition(repository *RedTeamExecutionRepository, ctx context.Context, scope domain.Scope, id, worker, token string) bool {
	return validRedTeamAuthority(repository, ctx, RedTeamExecutionAuthorityOutbox) && scope.Validate() == nil && validProductID(id) && validRedTeamWorkerLease(worker, token)
}

func validRedTeamRunTransition(repository *RedTeamExecutionRepository, ctx context.Context, scope domain.Scope, id, worker, token string) bool {
	return validRedTeamAuthority(repository, ctx, RedTeamExecutionAuthorityWorker) && scope.Validate() == nil && validProductID(id) && validRedTeamWorkerLease(worker, token)
}

func decodeRedTeamBoolean(payload json.RawMessage, providerErr error) (bool, error) {
	var result bool
	if providerErr != nil || decodeStrictDiscovery(payload, &result) != nil {
		return false, ErrRepositoryUnavailable
	}
	return result, nil
}

func validRedTeamCompletion(scope domain.Scope, input RedTeamRunCompletion) bool {
	if input.InputArtifact != nil && (!validRedTeamInputArtifact(scope, input.InputArtifact) || input.InputArtifact.Reference == input.EvidenceReference) {
		return false
	}
	if input.InputDigest == [sha256.Size]byte{} || !stringIn(input.Verdict, "pass", "fail", "engine_error") || input.Verdict != "engine_error" && input.ErrorCode != "" || input.Verdict == "engine_error" && !stringIn(input.ErrorCode, "denied", "malformed", "outcome_unknown", "exhausted") || !validRedTeamBoundedText(input.Objective, 512) || !validRedTeamBoundedText(input.Behavior, 2048) || len(input.Evidence) > 64 || !validS3ObjectReference(input.EvidenceReference) || !strings.HasSuffix(input.EvidenceReference, "/"+input.EvidenceKey) || len(input.EvidenceVersionID) < 1 || len(input.EvidenceVersionID) > 512 || strings.ContainsAny(input.EvidenceVersionID, " \t\r\n\x00") || len(input.EvidenceChecksum) != sha256.Size || bytes.Equal(input.EvidenceChecksum, make([]byte, sha256.Size)) || input.EvidenceSizeBytes < 1 || input.EvidenceSizeBytes > 64<<20 {
		return false
	}
	expectedKey := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + input.RunID
	if input.EvidenceKey != expectedKey {
		return false
	}
	for _, item := range input.Evidence {
		if !validRedTeamBoundedText(item, 512) {
			return false
		}
	}
	return true
}

func validRedTeamInputArtifact(scope domain.Scope, value *RedTeamArtifactReference) bool {
	if value == nil || scope.Validate() != nil || !validS3ObjectReference(value.Reference) || len(value.VersionID) < 1 || len(value.VersionID) > 512 || strings.ContainsAny(value.VersionID, " \t\r\n\x00") || !validAttackLabDigest(value.SHA256) || value.SizeBytes < 1 || value.SizeBytes > 65536 {
		return false
	}
	parts := strings.SplitN(value.Reference, "/", 4)
	prefix := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/"
	return len(parts) == 4 && strings.HasPrefix(parts[3], prefix) && validProductID(strings.TrimPrefix(parts[3], prefix))
}

func validRedTeamBoundedText(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func decodeRedTeamWorkerRun(payload json.RawMessage, providerErr error, runID string, allowed ...string) (RedTeamRun, error) {
	var result RedTeamRun
	if providerErr != nil || decodeStrictDiscovery(payload, &result) != nil || result.ID != runID || !validRedTeamRun(result) || !stringIn(result.Status, allowed...) {
		return RedTeamRun{}, ErrRepositoryUnavailable
	}
	return result, nil
}
