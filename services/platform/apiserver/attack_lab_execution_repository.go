package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	AttackLabExecutionAuthorityController = "zasp_attack_lab_controller"
	AttackLabExecutionAuthorityOutbox     = "zasp_attack_lab_outbox_worker"
	AttackLabExecutionAuthorityProxy      = "zasp_attack_lab_proxy"
	AttackLabOutboxTopic                  = "attack-lab-jobs"

	postgresAttackLabPrincipalReadySQL  = `SELECT to_jsonb(zasp_attack_lab_principal_ready($1))`
	postgresAttackLabClaimOutboxSQL     = `SELECT zasp_attack_lab_claim_outbox($1,$2,$3,$4)`
	postgresAttackLabHeartbeatOutboxSQL = `SELECT zasp_attack_lab_heartbeat_outbox($1,$2,$3,$4)`
	postgresAttackLabAckOutboxSQL       = `SELECT zasp_attack_lab_ack_outbox($1,$2,$3,$4,$5,$6,$7)`
	postgresAttackLabRetryOutboxSQL     = `SELECT zasp_attack_lab_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresAttackLabClaimRunSQL        = `SELECT zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,$7)`
	postgresAttackLabHeartbeatRunSQL    = `SELECT zasp_attack_lab_heartbeat_run($1,$2,$3,$4,$5,$6,$7)`
	postgresAttackLabRetryRunSQL        = `SELECT zasp_attack_lab_retry_run($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresAttackLabMarkRunningSQL     = `SELECT zasp_attack_lab_mark_running($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresAttackLabBeginCleanupSQL    = `SELECT zasp_attack_lab_begin_cleanup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18)`
	postgresAttackLabFinishCleanupSQL   = `SELECT zasp_attack_lab_finish_cleanup($1,$2,$3,$4,$5,$6,$7)`
	postgresAttackLabResolveEgressSQL   = `SELECT zasp_attack_lab_resolve_egress($1,$2,$3,$4,$5)`
)

var (
	attackLabExecutionWorkerPattern  = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,127}$`)
	attackLabExecutionTokenPattern   = regexp.MustCompile(`^[a-f0-9]{32}$`)
	attackLabSandboxReferencePattern = regexp.MustCompile(
		`^k8s://attack-lab/jobs/zasp-attack-lab-[a-z0-9-]{8,64}@[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
)

type AttackLabExecutionRepository struct {
	database  JSONDatabase
	authority string
}

type AttackLabOutboxEvent struct {
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

type AttackLabOutboxTransition struct {
	ID             string    `json:"outbox_id"`
	Topic          string    `json:"topic"`
	State          string    `json:"state"`
	ProviderAck    string    `json:"provider_ack"`
	ErrorCode      string    `json:"error_code"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	PublishedAt    time.Time `json:"published_at"`
	AvailableAt    time.Time `json:"available_at"`
	RemainingCount int       `json:"remaining_count"`
	Replayed       bool      `json:"replayed"`
}

type AttackLabPreflightSnapshot struct {
	Environment         string   `json:"environment"`
	CredentialClass     string   `json:"credential_class"`
	Destination         string   `json:"destination"`
	AllowedDestinations []string `json:"allowed_destinations"`
	SuccessCriterion    string   `json:"success_criterion"`
	ExpectedSideEffects []string `json:"expected_side_effects"`
}

type AttackLabCleanupCheckpoint struct {
	Attempt             int      `json:"attempt"`
	SandboxReference    string   `json:"sandbox_reference"`
	Verdict             string   `json:"verdict"`
	CriterionObserved   bool     `json:"criterion_observed"`
	CanaryTouched       bool     `json:"canary_touched"`
	ErrorCode           string   `json:"error_code"`
	Evidence            []string `json:"evidence"`
	EvidenceReference   string   `json:"evidence_reference"`
	EvidenceKey         string   `json:"evidence_key"`
	EvidenceVersionID   string   `json:"evidence_version_id"`
	EvidenceChecksumHex string   `json:"evidence_checksum"`
	EvidenceSizeBytes   int64    `json:"evidence_size"`
}

type AttackLabRunClaim struct {
	Disposition      string
	Run              AttackLabRun
	Preflight        AttackLabPreflightSnapshot
	Checkpoint       AttackLabCleanupCheckpoint
	SandboxReference string
	InputDigest      [sha256.Size]byte
	LeaseExpiresAt   time.Time
}

type AttackLabRunHeartbeat struct {
	Renewed         bool      `json:"renewed"`
	CancelRequested bool      `json:"cancel_requested"`
	LeaseExpiresAt  time.Time `json:"lease_expires_at"`
}

type AttackLabRunningInput struct {
	RunID, Controller, LeaseToken, SandboxReference string
	InputDigest                                     [sha256.Size]byte
}

type AttackLabCleanupInput struct {
	RunID, Controller, LeaseToken, SandboxReference   string
	InputDigest                                       [sha256.Size]byte
	Attempt                                           int
	Verdict                                           string
	CriterionObserved, CanaryTouched                  bool
	ErrorCode                                         string
	Evidence                                          []string
	EvidenceReference, EvidenceKey, EvidenceVersionID string
	EvidenceChecksum                                  []byte
	EvidenceSizeBytes                                 int64
}

type AttackLabRunTransition struct {
	Run      AttackLabRun
	Replayed bool
}

type AttackLabEgressAuthority struct {
	OrganizationID string    `json:"organization_id"`
	WorkspaceID    string    `json:"workspace_id"`
	EnvironmentID  string    `json:"environment_id"`
	RunID          string    `json:"run_id"`
	Destination    string    `json:"destination"`
	Methods        []string  `json:"methods"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func NewAttackLabExecutionRepository(database JSONDatabase, authority string) (*AttackLabExecutionRepository, error) {
	if nilInterface(database) || !stringIn(authority, AttackLabExecutionAuthorityController, AttackLabExecutionAuthorityOutbox, AttackLabExecutionAuthorityProxy) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	repository := &AttackLabExecutionRepository{database: database, authority: authority}
	if repository.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *AttackLabExecutionRepository) Ready(ctx context.Context) error {
	if !validAttackLabExecutionRepository(repository, ctx) {
		return ErrRepositoryUnavailable
	}
	metadata := migrations.ProductionAttackLabExecution()
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabExecutionReadinessSQL, metadata.Checksum(), migrations.ProductionAttackLabExecutionSemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	payload, err = repository.database.QueryJSON(ctx, postgresAttackLabPrincipalReadySQL, repository.authority)
	ready = false
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *AttackLabExecutionRepository) ClaimAttackLabOutbox(ctx context.Context, worker, leaseToken string, leaseSeconds, limit int) ([]AttackLabOutboxEvent, error) {
	if !validAttackLabExecutionAuthority(repository, ctx, AttackLabExecutionAuthorityOutbox) || !validAttackLabExecutionLease(worker, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 10 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabClaimOutboxSQL, worker, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var wire struct {
		Items []struct {
			OrganizationID string    `json:"organization_id"`
			WorkspaceID    string    `json:"workspace_id"`
			EnvironmentID  string    `json:"environment_id"`
			OutboxID       string    `json:"outbox_id"`
			Topic          string    `json:"topic"`
			Payload        string    `json:"payload"`
			PayloadDigest  string    `json:"payload_digest"`
			Attempt        int       `json:"attempt"`
			LeaseExpiresAt time.Time `json:"lease_expires_at"`
		} `json:"items"`
	}
	if decodeStrictDiscovery(payload, &wire) != nil || len(wire.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	result := make([]AttackLabOutboxEvent, len(wire.Items))
	seen := make(map[string]struct{}, len(wire.Items))
	seenOrganizations := make(map[string]struct{}, len(wire.Items))
	for index, item := range wire.Items {
		organization, organizationErr := domain.ParseProductID(item.OrganizationID)
		workspace, workspaceErr := domain.ParseProductID(item.WorkspaceID)
		environment, environmentErr := domain.ParseProductID(item.EnvironmentID)
		outbox, outboxErr := domain.ParseProductID(item.OutboxID)
		scope, scopeErr := domain.NewScope(organization, workspace, environment)
		digest, digestErr := hex.DecodeString(item.PayloadDigest)
		actual := sha256.Sum256([]byte(item.Payload))
		if organizationErr != nil || workspaceErr != nil || environmentErr != nil || outboxErr != nil || scopeErr != nil || outbox.IsZero() || item.Topic != AttackLabOutboxTopic || len(item.Payload) < 2 || len(item.Payload) > 65_536 || digestErr != nil || len(digest) != sha256.Size || subtle.ConstantTimeCompare(digest, actual[:]) != 1 || item.Attempt < 1 || item.Attempt > 100 || !validLeaseExpiration(item.LeaseExpiresAt, leaseSeconds) || !validAttackLabOutboxPayload(item.Payload, scope) {
			return nil, ErrRepositoryUnavailable
		}
		if _, duplicate := seen[item.OutboxID]; duplicate {
			return nil, ErrRepositoryUnavailable
		}
		if _, duplicate := seenOrganizations[item.OrganizationID]; duplicate {
			return nil, ErrRepositoryUnavailable
		}
		seen[item.OutboxID], seenOrganizations[item.OrganizationID] = struct{}{}, struct{}{}
		result[index] = AttackLabOutboxEvent{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ID: item.OutboxID, Topic: item.Topic, Payload: json.RawMessage(bytes.Clone([]byte(item.Payload))), PayloadDigest: bytes.Clone(digest), Attempt: item.Attempt, LeaseExpiresAt: item.LeaseExpiresAt.UTC()}
	}
	return result, nil
}

func (repository *AttackLabExecutionRepository) HeartbeatAttackLabOutbox(ctx context.Context, worker, leaseToken string, leaseSeconds, expectedCount int) (AttackLabOutboxTransition, error) {
	if !validAttackLabExecutionAuthority(repository, ctx, AttackLabExecutionAuthorityOutbox) || !validAttackLabExecutionLease(worker, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 || expectedCount < 1 || expectedCount > 10 {
		return AttackLabOutboxTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabHeartbeatOutboxSQL, worker, leaseToken, leaseSeconds, expectedCount)
	var result AttackLabOutboxTransition
	if err != nil || decodeStrictDiscovery(payload, &result) != nil || result.Topic != AttackLabOutboxTopic || result.RemainingCount != expectedCount || !validLeaseExpiration(result.LeaseExpiresAt, leaseSeconds) || result.ID != "" || result.State != "" || result.ProviderAck != "" || result.ErrorCode != "" || !result.PublishedAt.IsZero() || !result.AvailableAt.IsZero() || result.Replayed {
		return AttackLabOutboxTransition{}, ErrRepositoryUnavailable
	}
	result.LeaseExpiresAt = result.LeaseExpiresAt.UTC()
	return result, nil
}

func (repository *AttackLabExecutionRepository) AcknowledgeAttackLabOutbox(ctx context.Context, scope domain.Scope, id, worker, leaseToken, providerAck string) (AttackLabOutboxTransition, error) {
	if !validAttackLabOutboxTransition(repository, ctx, scope, id, worker, leaseToken) || !outboxProviderAckPattern.MatchString(providerAck) {
		return AttackLabOutboxTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabAckOutboxSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, providerAck)
	var result AttackLabOutboxTransition
	if err != nil || decodeStrictDiscovery(payload, &result) != nil || result.ID != id || result.State != "published" || result.ProviderAck != providerAck || result.RemainingCount < 0 || result.RemainingCount > 9 || !canonicalRedTeamTime(result.PublishedAt) || result.Topic != "" || result.ErrorCode != "" || !result.LeaseExpiresAt.IsZero() || !result.AvailableAt.IsZero() {
		return AttackLabOutboxTransition{}, ErrRepositoryUnavailable
	}
	result.PublishedAt = result.PublishedAt.UTC()
	return result, nil
}

func (repository *AttackLabExecutionRepository) RetryAttackLabOutbox(ctx context.Context, scope domain.Scope, id, worker, leaseToken string, retrySeconds int, code string) (AttackLabOutboxTransition, error) {
	if !validAttackLabOutboxTransition(repository, ctx, scope, id, worker, leaseToken) || retrySeconds < 1 || retrySeconds > 3600 || code != "queue_publish_unknown" {
		return AttackLabOutboxTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabRetryOutboxSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, retrySeconds, code)
	var result AttackLabOutboxTransition
	if err != nil || decodeStrictDiscovery(payload, &result) != nil || result.ID != id || !stringIn(result.State, "pending", "failed") || result.ErrorCode != code || result.RemainingCount < 0 || result.RemainingCount > 9 || !canonicalRedTeamTime(result.AvailableAt) || result.Topic != "" || result.ProviderAck != "" || !result.LeaseExpiresAt.IsZero() || !result.PublishedAt.IsZero() {
		return AttackLabOutboxTransition{}, ErrRepositoryUnavailable
	}
	result.AvailableAt = result.AvailableAt.UTC()
	return result, nil
}

func (repository *AttackLabExecutionRepository) ClaimAttackLabRun(ctx context.Context, scope domain.Scope, runID, controller, leaseToken string, leaseSeconds int) (AttackLabRunClaim, error) {
	if !validAttackLabRunTransition(repository, ctx, scope, runID, controller, leaseToken) || leaseSeconds < 30 || leaseSeconds > 900 {
		return AttackLabRunClaim{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabClaimRunSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, controller, leaseToken, leaseSeconds)
	if err != nil {
		return AttackLabRunClaim{}, discoveryProviderError(err)
	}
	var wire struct {
		Disposition      string                     `json:"disposition"`
		Run              AttackLabRun               `json:"run"`
		Preflight        AttackLabPreflightSnapshot `json:"preflight"`
		Checkpoint       AttackLabCleanupCheckpoint `json:"checkpoint"`
		SandboxReference string                     `json:"sandbox_reference"`
		InputDigest      string                     `json:"input_digest"`
		LeaseExpiresAt   time.Time                  `json:"lease_expires_at"`
	}
	if decodeStrictDiscovery(payload, &wire) != nil || !stringIn(wire.Disposition, "claimed", "running", "cleanup", "retry_later", "ack_terminal") {
		return AttackLabRunClaim{}, ErrRepositoryUnavailable
	}
	result := AttackLabRunClaim{Disposition: wire.Disposition}
	if wire.Disposition == "retry_later" || wire.Disposition == "ack_terminal" {
		if wire.Run.ID != "" || wire.InputDigest != "" || !wire.LeaseExpiresAt.IsZero() || wire.Preflight.SuccessCriterion != "" || wire.Checkpoint.SandboxReference != "" || wire.SandboxReference != "" {
			return AttackLabRunClaim{}, ErrRepositoryUnavailable
		}
		return result, nil
	}
	digest, digestErr := hex.DecodeString(wire.InputDigest)
	if digestErr != nil || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) || wire.Run.ID != runID || !validAttackLabRun(wire.Run) || !validLeaseExpiration(wire.LeaseExpiresAt, leaseSeconds) {
		return AttackLabRunClaim{}, ErrRepositoryUnavailable
	}
	if wire.Disposition == "claimed" && (wire.Run.Status != "leased" || !validAttackLabPreflight(wire.Preflight, wire.Run) || wire.Checkpoint.SandboxReference != "" || wire.SandboxReference != "") || wire.Disposition == "running" && (wire.Run.Status != "running" || wire.Preflight.SuccessCriterion != "" || wire.Checkpoint.SandboxReference != "" || !attackLabSandboxReferencePattern.MatchString(wire.SandboxReference)) || wire.Disposition == "cleanup" && (wire.Run.Status != "cleanup" || wire.Preflight.SuccessCriterion != "" || wire.SandboxReference != "" || !validAttackLabCleanupCheckpoint(scope, runID, wire.Run, wire.Checkpoint)) {
		return AttackLabRunClaim{}, ErrRepositoryUnavailable
	}
	copy(result.InputDigest[:], digest)
	result.Run, result.Preflight, result.Checkpoint, result.SandboxReference, result.LeaseExpiresAt = wire.Run, wire.Preflight, wire.Checkpoint, wire.SandboxReference, wire.LeaseExpiresAt.UTC()
	return result, nil
}

func (repository *AttackLabExecutionRepository) HeartbeatAttackLabRun(ctx context.Context, scope domain.Scope, runID, controller, leaseToken string, leaseSeconds int) (AttackLabRunHeartbeat, error) {
	if !validAttackLabRunTransition(repository, ctx, scope, runID, controller, leaseToken) || leaseSeconds < 30 || leaseSeconds > 900 {
		return AttackLabRunHeartbeat{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabHeartbeatRunSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, controller, leaseToken, leaseSeconds)
	var result AttackLabRunHeartbeat
	if err != nil || decodeStrictDiscovery(payload, &result) != nil || result.Renewed && !validLeaseExpiration(result.LeaseExpiresAt, leaseSeconds) || !result.Renewed && !result.LeaseExpiresAt.IsZero() {
		return AttackLabRunHeartbeat{}, ErrRepositoryUnavailable
	}
	if result.Renewed {
		result.LeaseExpiresAt = result.LeaseExpiresAt.UTC()
	}
	return result, nil
}

func (repository *AttackLabExecutionRepository) RetryAttackLabRun(ctx context.Context, scope domain.Scope, runID, controller, leaseToken string, inputDigest [sha256.Size]byte, code string, retryAt time.Time) (AttackLabRunTransition, error) {
	now := time.Now().UTC()
	if !validAttackLabRunTransition(repository, ctx, scope, runID, controller, leaseToken) || inputDigest == [sha256.Size]byte{} || !stringIn(code, "retryable", "denied", "malformed") || retryAt.Location() != time.UTC || retryAt.Before(now) || retryAt.After(now.Add(time.Hour)) {
		return AttackLabRunTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabRetryRunSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, controller, leaseToken, inputDigest[:], code, retryAt)
	result, decodeErr := decodeAttackLabRunTransition(payload, err, runID, "retryable", "failed", "cancelled")
	if decodeErr != nil {
		return AttackLabRunTransition{}, decodeErr
	}
	if result.Run.Status == "retryable" && result.Run.ErrorCode != "retryable" || result.Run.Status == "failed" && !stringIn(result.Run.ErrorCode, "denied", "malformed", "exhausted") || result.Run.Status == "cancelled" && result.Run.ErrorCode != "cancelled" {
		return AttackLabRunTransition{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *AttackLabExecutionRepository) MarkAttackLabRunning(ctx context.Context, scope domain.Scope, input AttackLabRunningInput) (AttackLabRunTransition, error) {
	if !validAttackLabRunTransition(repository, ctx, scope, input.RunID, input.Controller, input.LeaseToken) || input.InputDigest == [sha256.Size]byte{} || !attackLabSandboxReferencePattern.MatchString(input.SandboxReference) {
		return AttackLabRunTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabMarkRunningSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.RunID, input.Controller, input.LeaseToken, input.InputDigest[:], input.SandboxReference)
	return decodeAttackLabRunTransition(payload, err, input.RunID, "running")
}

func (repository *AttackLabExecutionRepository) BeginAttackLabCleanup(ctx context.Context, scope domain.Scope, input AttackLabCleanupInput) (AttackLabRunTransition, error) {
	if !validAttackLabRunTransition(repository, ctx, scope, input.RunID, input.Controller, input.LeaseToken) || !validAttackLabCleanupInput(scope, input) {
		return AttackLabRunTransition{}, ErrRepositoryOperation
	}
	evidence, marshalErr := json.Marshal(input.Evidence)
	if marshalErr != nil {
		return AttackLabRunTransition{}, ErrRepositoryOperation
	}
	var errorCode any
	if input.ErrorCode != "" {
		errorCode = input.ErrorCode
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabBeginCleanupSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.RunID, input.Controller, input.LeaseToken, input.InputDigest[:], input.SandboxReference, input.Verdict, input.CriterionObserved, input.CanaryTouched, errorCode, evidence, input.EvidenceReference, input.EvidenceKey, input.EvidenceVersionID, input.EvidenceChecksum, input.EvidenceSizeBytes)
	return decodeAttackLabRunTransition(payload, err, input.RunID, "cleanup")
}

func (repository *AttackLabExecutionRepository) FinishAttackLabCleanup(ctx context.Context, scope domain.Scope, runID, controller, leaseToken string, inputDigest [sha256.Size]byte) (AttackLabRunTransition, error) {
	if !validAttackLabRunTransition(repository, ctx, scope, runID, controller, leaseToken) || inputDigest == [sha256.Size]byte{} {
		return AttackLabRunTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabFinishCleanupSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, controller, leaseToken, inputDigest[:])
	return decodeAttackLabRunTransition(payload, err, runID, "complete", "cancelled")
}

func (repository *AttackLabExecutionRepository) ResolveAttackLabEgress(ctx context.Context, scope domain.Scope, runID, destination string) (AttackLabEgressAuthority, error) {
	if !validAttackLabExecutionAuthority(repository, ctx, AttackLabExecutionAuthorityProxy) || scope.Validate() != nil || !validProductID(runID) || !validAttackLabDestination(destination) {
		return AttackLabEgressAuthority{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabResolveEgressSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, destination)
	var result AttackLabEgressAuthority
	if err != nil || decodeStrictDiscovery(payload, &result) != nil || result.OrganizationID != scope.OrganizationID().String() || result.WorkspaceID != scope.WorkspaceID().String() || result.EnvironmentID != scope.EnvironmentID().String() || result.RunID != runID || result.Destination != destination || len(result.Methods) != 1 || result.Methods[0] != "POST" || !canonicalRedTeamTime(result.ExpiresAt) || !result.ExpiresAt.After(time.Now().UTC()) || result.ExpiresAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return AttackLabEgressAuthority{}, ErrRepositoryUnavailable
	}
	result.ExpiresAt = result.ExpiresAt.UTC()
	return result, nil
}

func validAttackLabExecutionRepository(repository *AttackLabExecutionRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && stringIn(repository.authority, AttackLabExecutionAuthorityController, AttackLabExecutionAuthorityOutbox, AttackLabExecutionAuthorityProxy) && ctx != nil && ctx.Err() == nil
}

func validAttackLabExecutionAuthority(repository *AttackLabExecutionRepository, ctx context.Context, authority string) bool {
	return validAttackLabExecutionRepository(repository, ctx) && repository.authority == authority
}

func validAttackLabExecutionLease(worker, token string) bool {
	return attackLabExecutionWorkerPattern.MatchString(worker) && attackLabExecutionTokenPattern.MatchString(token)
}

func validAttackLabOutboxTransition(repository *AttackLabExecutionRepository, ctx context.Context, scope domain.Scope, id, worker, token string) bool {
	return validAttackLabExecutionAuthority(repository, ctx, AttackLabExecutionAuthorityOutbox) && scope.Validate() == nil && validProductID(id) && validAttackLabExecutionLease(worker, token)
}

func validAttackLabRunTransition(repository *AttackLabExecutionRepository, ctx context.Context, scope domain.Scope, id, worker, token string) bool {
	return validAttackLabExecutionAuthority(repository, ctx, AttackLabExecutionAuthorityController) && scope.Validate() == nil && validProductID(id) && validAttackLabExecutionLease(worker, token)
}

func validAttackLabOutboxPayload(value string, scope domain.Scope) bool {
	var payload struct {
		OrganizationID    string `json:"organization_id"`
		WorkspaceID       string `json:"workspace_id"`
		EnvironmentID     string `json:"environment_id"`
		RunID             string `json:"run_id"`
		SourceRunID       string `json:"source_run_id"`
		DefinitionID      string `json:"definition_id"`
		DefinitionVersion int64  `json:"definition_version"`
		TargetID          string `json:"target_id"`
		TargetKind        string `json:"target_kind"`
		InputDigest       string `json:"input_digest"`
	}
	if decodeStrictDiscovery(json.RawMessage(value), &payload) != nil || payload.OrganizationID != scope.OrganizationID().String() || payload.WorkspaceID != scope.WorkspaceID().String() || payload.EnvironmentID != scope.EnvironmentID().String() || !validProductID(payload.RunID) || !validProductID(payload.SourceRunID) || payload.RunID == payload.SourceRunID || !validProductID(payload.DefinitionID) || payload.DefinitionVersion < 1 || payload.DefinitionVersion > 1_000_000 || !validProductID(payload.TargetID) || !stringIn(payload.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") {
		return false
	}
	digest, err := hex.DecodeString(payload.InputDigest)
	return err == nil && len(digest) == sha256.Size && !bytes.Equal(digest, make([]byte, sha256.Size))
}

func validAttackLabPreflight(value AttackLabPreflightSnapshot, run AttackLabRun) bool {
	if value.Environment != run.Environment || value.CredentialClass != run.CredentialClass || value.Destination != run.Destination || len(value.AllowedDestinations) != 1 || value.AllowedDestinations[0] != run.Destination || !validRedTeamBoundedText(value.SuccessCriterion, 512) || len(value.ExpectedSideEffects) < 1 || len(value.ExpectedSideEffects) > 16 {
		return false
	}
	for _, sideEffect := range value.ExpectedSideEffects {
		if !validRedTeamBoundedText(sideEffect, 256) {
			return false
		}
	}
	return true
}

func validAttackLabCleanupCheckpoint(scope domain.Scope, runID string, run AttackLabRun, value AttackLabCleanupCheckpoint) bool {
	checksum, checksumErr := hex.DecodeString(value.EvidenceChecksumHex)
	return checksumErr == nil && value.Attempt == run.Attempt && attackLabSandboxReferencePattern.MatchString(value.SandboxReference) && validAttackLabVerdictEvidence(value.Verdict, value.CriterionObserved, value.CanaryTouched, value.ErrorCode, value.Evidence) && validAttackLabEvidenceArtifact(scope, runID, value.Attempt, value.EvidenceReference, value.EvidenceKey, value.EvidenceVersionID, checksum, value.EvidenceSizeBytes)
}

func validAttackLabCleanupInput(scope domain.Scope, input AttackLabCleanupInput) bool {
	return input.InputDigest != [sha256.Size]byte{} && attackLabSandboxReferencePattern.MatchString(input.SandboxReference) && validAttackLabVerdictEvidence(input.Verdict, input.CriterionObserved, input.CanaryTouched, input.ErrorCode, input.Evidence) && validAttackLabEvidenceArtifact(scope, input.RunID, input.Attempt, input.EvidenceReference, input.EvidenceKey, input.EvidenceVersionID, input.EvidenceChecksum, input.EvidenceSizeBytes)
}

func validAttackLabVerdictEvidence(verdict string, criterion, canary bool, code string, evidence []string) bool {
	if !stringIn(verdict, "verified", "not_reproduced", "inconclusive") || verdict == "verified" && (!criterion || !canary) || verdict == "not_reproduced" && (criterion || canary) || verdict != "inconclusive" && code != "" || verdict == "inconclusive" && !stringIn(code, "denied", "malformed", "outcome_unknown", "exhausted") || len(evidence) != 5 {
		return false
	}
	prefixes := [...]string{"semantic:", "gateway:", "egress:", "kubernetes:", "cloud:"}
	for index, item := range evidence {
		if !validRedTeamBoundedText(item, 512) || !strings.HasPrefix(item, prefixes[index]) || len(item) == len(prefixes[index]) {
			return false
		}
	}
	return true
}

func validAttackLabEvidenceArtifact(scope domain.Scope, runID string, attempt int, reference, key, version string, checksum []byte, size int64) bool {
	expectedKey := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/attack-lab/" + runID + "/attempts/" + strconv.Itoa(attempt) + "/evidence.json"
	return attempt >= 1 && attempt <= 5 && validS3ObjectReference(reference) && strings.HasSuffix(reference, "/"+key) && key == expectedKey && len(version) >= 1 && len(version) <= 512 && !strings.ContainsAny(version, " \t\r\n\x00") && len(checksum) == sha256.Size && !bytes.Equal(checksum, make([]byte, sha256.Size)) && size >= 1 && size <= 64<<20
}

func decodeAttackLabRunTransition(payload json.RawMessage, providerErr error, runID string, allowed ...string) (AttackLabRunTransition, error) {
	var wire struct {
		AttackLabRun
		Replayed bool `json:"replayed"`
	}
	if providerErr != nil || decodeStrictDiscovery(payload, &wire) != nil || wire.ID != runID || !validAttackLabRun(wire.AttackLabRun) || !stringIn(wire.Status, allowed...) {
		return AttackLabRunTransition{}, ErrRepositoryUnavailable
	}
	return AttackLabRunTransition{Run: wire.AttackLabRun, Replayed: wire.Replayed}, nil
}
