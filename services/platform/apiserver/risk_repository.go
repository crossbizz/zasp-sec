package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresRiskFindingGetSQL        = `SELECT zasp_risk_finding_get($1, $2, $3, $4)`
	postgresRiskFindingPageSQL       = `SELECT zasp_risk_finding_page($1, $2, $3, NULLIF($4, ''), $5)`
	postgresRiskAttackPathGetSQL     = `SELECT zasp_risk_attack_path_get($1, $2, $3, $4)`
	postgresRiskAttackPathPageSQL    = `SELECT zasp_risk_attack_path_page($1, $2, $3, NULLIF($4, ''), $5)`
	postgresRiskBreakOptionsGetSQL   = `SELECT zasp_risk_break_options_get($1, $2, $3, $4)`
	postgresRiskHighPathCountSQL     = `SELECT to_jsonb(zasp_risk_high_path_count($1, $2, $3))`
	postgresRiskFindingMutateSQL     = `SELECT zasp_risk_mutate($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''), $11, $12, NULLIF($13, ''))`
	postgresGlobalSearchSQL          = `SELECT zasp_global_search($1, $2, $3, $4, $5)`
	postgresFindingTicketReserveSQL  = `SELECT zasp_finding_ticket_reserve($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	postgresFindingTicketCompleteSQL = `SELECT zasp_finding_ticket_complete($1, $2, $3, $4, $5, $6, $7)`
	postgresFindingTicketReleaseSQL  = `SELECT zasp_finding_ticket_release($1, $2, $3, $4, $5, $6)`
)

var (
	findingTicketDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	findingTicketHostnamePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	findingTicketLeaseTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	findingTicketReferencePattern  = regexp.MustCompile(`^secret_ref_[A-Za-z0-9][A-Za-z0-9._/-]{0,115}$`)
	findingTicketProviderIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

type RiskFactor struct {
	Name       string `json:"name"`
	EvidenceID string `json:"evidence_id"`
}

type RiskFinding struct {
	ID                string       `json:"id"`
	Source            string       `json:"source"`
	Rule              string       `json:"rule,omitempty"`
	Title             string       `json:"title"`
	Severity          string       `json:"severity"`
	Status            string       `json:"status"`
	AgentID           string       `json:"agent_id,omitempty"`
	PathID            string       `json:"path_id,omitempty"`
	ComplianceContext string       `json:"compliance_context,omitempty"`
	EvidenceIDs       []string     `json:"evidence_ids"`
	RiskFactors       []RiskFactor `json:"risk_factors"`
	AcceptanceReason  string       `json:"acceptance_reason,omitempty"`
	Version           int64        `json:"version"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

type RiskFindingPage struct {
	Items  []RiskFinding
	NextID string
}

type RiskAttackPath struct {
	ID          string    `json:"id"`
	EntryID     string    `json:"entry_id"`
	SinkID      string    `json:"sink_id"`
	NodeIDs     []string  `json:"node_ids"`
	State       string    `json:"state"`
	EvidenceIDs []string  `json:"evidence_ids"`
	BlockedEdge int       `json:"blocked_edge"`
	Version     int64     `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RiskAttackPathPage struct {
	Items  []RiskAttackPath
	NextID string
}

type RiskBreakOption struct {
	PathID     string `json:"path_id"`
	TargetID   string `json:"target_id"`
	EvidenceID string `json:"evidence_id"`
	Kind       string `json:"kind"`
	Rank       int    `json:"rank"`
}

type RiskFindingMutation struct {
	Operation       string
	FindingID       string
	IdempotencyKey  string
	ExpectedVersion int64
	Status          string
	Reason          string
	AuditID         string
	CorrelationID   string
	ReceiptID       string
}

type RiskFindingMutationResult struct {
	Body          RiskFinding `json:"body"`
	Version       int64       `json:"version"`
	AuditID       string      `json:"audit_id"`
	CorrelationID string      `json:"correlation_id"`
	ReceiptID     string      `json:"receipt_id,omitempty"`
	Replayed      bool        `json:"replayed"`
}

type GlobalSearchResult struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type GlobalSearchPage struct {
	Items []GlobalSearchResult `json:"items"`
}

type FindingTicketReservation struct {
	State           string
	DeliveryID      string
	Payload         string
	PayloadDigest   string
	DestinationURL  string
	SecretReference string
	LeaseExpiresAt  time.Time
	TicketID        string
}

func (repository *PostgresRepository) ReserveFindingTicket(ctx context.Context, command FindingTicketCommand, deliveryID, leaseToken string, leaseSeconds int) (FindingTicketReservation, error) {
	if !validFindingTicketRepository(repository, ctx) || !validFindingTicketCommand(command) || !validProductID(deliveryID) || !findingTicketLeaseTokenPattern.MatchString(leaseToken) || leaseSeconds < 5 || leaseSeconds > 30 {
		return FindingTicketReservation{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresFindingTicketReserveSQL,
		command.Identity.Scope.OrganizationID().String(), command.Identity.Scope.WorkspaceID().String(), command.Identity.Scope.EnvironmentID().String(), command.Identity.PrincipalID.String(),
		command.FindingID, command.ExpectedVersion, command.IdempotencyKey, command.CorrelationID, deliveryID, leaseToken, leaseSeconds,
	)
	if err != nil {
		return FindingTicketReservation{}, riskProviderError(err)
	}
	var response struct {
		State           string     `json:"state"`
		DeliveryID      string     `json:"delivery_id"`
		Payload         string     `json:"payload"`
		PayloadDigest   string     `json:"payload_digest"`
		DestinationURL  string     `json:"destination_url"`
		SecretReference string     `json:"secret_reference"`
		LeaseExpiresAt  *time.Time `json:"lease_expires_at"`
		TicketID        *string    `json:"ticket_id"`
	}
	if decodeStrictRisk(payload, &response) != nil || !validProductID(response.DeliveryID) {
		return FindingTicketReservation{}, ErrRepositoryUnavailable
	}
	result := FindingTicketReservation{State: response.State, DeliveryID: response.DeliveryID}
	switch response.State {
	case "dispatch":
		if response.TicketID != nil || response.LeaseExpiresAt == nil || !validLeaseExpiration(*response.LeaseExpiresAt, leaseSeconds) || !validFindingTicketPayload(response.Payload, response.PayloadDigest, command, response.DeliveryID) || !validFindingTicketDestination(response.DestinationURL) || !findingTicketReferencePattern.MatchString(response.SecretReference) {
			return FindingTicketReservation{}, ErrRepositoryUnavailable
		}
		result.Payload = response.Payload
		result.PayloadDigest = response.PayloadDigest
		result.DestinationURL = response.DestinationURL
		result.SecretReference = response.SecretReference
		result.LeaseExpiresAt = response.LeaseExpiresAt.UTC()
	case "completed":
		if response.TicketID == nil || !findingTicketProviderIDPattern.MatchString(*response.TicketID) || response.Payload != "" || response.PayloadDigest != "" || response.DestinationURL != "" || response.SecretReference != "" || response.LeaseExpiresAt != nil {
			return FindingTicketReservation{}, ErrRepositoryUnavailable
		}
		result.TicketID = *response.TicketID
	case "busy":
		if response.TicketID != nil || response.Payload != "" || response.PayloadDigest != "" || response.DestinationURL != "" || response.SecretReference != "" || response.LeaseExpiresAt == nil || !validLeaseExpiration(*response.LeaseExpiresAt, leaseSeconds) {
			return FindingTicketReservation{}, ErrRepositoryUnavailable
		}
		result.LeaseExpiresAt = response.LeaseExpiresAt.UTC()
	default:
		return FindingTicketReservation{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) CompleteFindingTicket(ctx context.Context, scope domain.Scope, deliveryID, leaseToken, payloadDigest, ticketID string) (FindingTicket, error) {
	if !validFindingTicketRepository(repository, ctx) || scope.Validate() != nil || !validProductID(deliveryID) || !findingTicketLeaseTokenPattern.MatchString(leaseToken) || !findingTicketDigestPattern.MatchString(payloadDigest) || !findingTicketProviderIDPattern.MatchString(ticketID) {
		return FindingTicket{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresFindingTicketCompleteSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), deliveryID, leaseToken, payloadDigest, ticketID)
	if err != nil {
		return FindingTicket{}, riskProviderError(err)
	}
	var result FindingTicket
	if decodeStrictRisk(payload, &result) != nil || result.TicketID != ticketID {
		return FindingTicket{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) ReleaseFindingTicket(ctx context.Context, scope domain.Scope, deliveryID, leaseToken, payloadDigest string) error {
	if !validFindingTicketRepository(repository, ctx) || scope.Validate() != nil || !validProductID(deliveryID) || !findingTicketLeaseTokenPattern.MatchString(leaseToken) || !findingTicketDigestPattern.MatchString(payloadDigest) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresFindingTicketReleaseSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), deliveryID, leaseToken, payloadDigest)
	if err != nil {
		return riskProviderError(err)
	}
	var released bool
	if decodeStrictRisk(payload, &released) != nil || !released {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *PostgresRepository) SearchGlobal(ctx context.Context, scope domain.Scope, query string, limit int) (GlobalSearchPage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || scope.Validate() != nil || strings.TrimSpace(query) != query || !globalSearchQueryPattern.MatchString(query) || limit < 1 || limit > 100 {
		return GlobalSearchPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresGlobalSearchSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), query, limit)
	if err != nil {
		return GlobalSearchPage{}, riskProviderError(err)
	}
	var result GlobalSearchPage
	if decodeStrictRisk(payload, &result) != nil || result.Items == nil || len(result.Items) > limit {
		return GlobalSearchPage{}, ErrRepositoryUnavailable
	}
	seen := make(map[string]struct{}, len(result.Items))
	for _, item := range result.Items {
		if !validProductID(item.ID) || !stringIn(item.Type, "asset", "agent", "tool", "identity", "runtime", "finding") || !validGlobalSearchName(item.Name) {
			return GlobalSearchPage{}, ErrRepositoryUnavailable
		}
		key := item.Type + "\x00" + item.ID
		if _, duplicate := seen[key]; duplicate {
			return GlobalSearchPage{}, ErrRepositoryUnavailable
		}
		seen[key] = struct{}{}
	}
	return result, nil
}

func (repository *PostgresRepository) GetRiskFinding(ctx context.Context, scope domain.Scope, id string) (RiskFinding, error) {
	if !validRiskRead(repository, ctx, scope, id) {
		return RiskFinding{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskFindingGetSQL, id, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return RiskFinding{}, riskProviderError(err)
	}
	var result RiskFinding
	if decodeStrictRisk(payload, &result) != nil || !validRiskFinding(result) {
		return RiskFinding{}, ErrRepositoryUnavailable
	}
	normalizeRiskFinding(&result)
	return result, nil
}

func (repository *PostgresRepository) ListRiskFindingPage(ctx context.Context, scope domain.Scope, afterID string, limit int) (RiskFindingPage, error) {
	if !validRiskPage(repository, ctx, scope, afterID, limit) {
		return RiskFindingPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskFindingPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), afterID, limit)
	return decodeRiskFindingPage(payload, err, limit)
}

func decodeRiskFindingPage(payload json.RawMessage, err error, limit int) (RiskFindingPage, error) {
	if err != nil {
		return RiskFindingPage{}, riskProviderError(err)
	}
	var envelope struct {
		Items  []RiskFinding `json:"items"`
		NextID *string       `json:"next_id"`
	}
	if decodeStrictRisk(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return RiskFindingPage{}, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		if !validRiskFinding(envelope.Items[index]) {
			return RiskFindingPage{}, ErrRepositoryUnavailable
		}
		normalizeRiskFinding(&envelope.Items[index])
	}
	nextID := ""
	if envelope.NextID != nil {
		nextID = *envelope.NextID
		if !validProductID(nextID) || len(envelope.Items) != limit || len(envelope.Items) == 0 || envelope.Items[len(envelope.Items)-1].ID != nextID {
			return RiskFindingPage{}, ErrRepositoryUnavailable
		}
	}
	return RiskFindingPage{Items: envelope.Items, NextID: nextID}, nil
}

func (repository *PostgresRepository) GetRiskAttackPath(ctx context.Context, scope domain.Scope, id string) (RiskAttackPath, error) {
	if !validRiskRead(repository, ctx, scope, id) {
		return RiskAttackPath{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskAttackPathGetSQL, id, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return RiskAttackPath{}, riskProviderError(err)
	}
	var result RiskAttackPath
	if decodeStrictRisk(payload, &result) != nil || !validRiskAttackPath(result) {
		return RiskAttackPath{}, ErrRepositoryUnavailable
	}
	normalizeRiskAttackPath(&result)
	return result, nil
}

func (repository *PostgresRepository) ListRiskAttackPathPage(ctx context.Context, scope domain.Scope, afterID string, limit int) (RiskAttackPathPage, error) {
	if !validRiskPage(repository, ctx, scope, afterID, limit) {
		return RiskAttackPathPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskAttackPathPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), afterID, limit)
	if err != nil {
		return RiskAttackPathPage{}, riskProviderError(err)
	}
	var envelope struct {
		Items  []RiskAttackPath `json:"items"`
		NextID *string          `json:"next_id"`
	}
	if decodeStrictRisk(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return RiskAttackPathPage{}, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		if !validRiskAttackPath(envelope.Items[index]) {
			return RiskAttackPathPage{}, ErrRepositoryUnavailable
		}
		normalizeRiskAttackPath(&envelope.Items[index])
	}
	nextID := ""
	if envelope.NextID != nil {
		nextID = *envelope.NextID
		if !validProductID(nextID) || len(envelope.Items) != limit || len(envelope.Items) == 0 || envelope.Items[len(envelope.Items)-1].ID != nextID {
			return RiskAttackPathPage{}, ErrRepositoryUnavailable
		}
	}
	return RiskAttackPathPage{Items: envelope.Items, NextID: nextID}, nil
}

func (repository *PostgresRepository) GetRiskBreakOptions(ctx context.Context, scope domain.Scope, pathID string) ([]RiskBreakOption, error) {
	if !validRiskRead(repository, ctx, scope, pathID) {
		return nil, ErrRepositoryOperation
	}
	path, err := repository.GetRiskAttackPath(ctx, scope, pathID)
	if err != nil {
		return nil, err
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskBreakOptionsGetSQL, pathID, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return nil, riskProviderError(err)
	}
	var envelope struct {
		Items []RiskBreakOption `json:"items"`
	}
	if decodeStrictRisk(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > 8 {
		return nil, ErrRepositoryUnavailable
	}
	evidence := make(map[string]struct{}, len(path.EvidenceIDs))
	for _, evidenceID := range path.EvidenceIDs {
		evidence[evidenceID] = struct{}{}
	}
	seen := map[string]struct{}{}
	for index, option := range envelope.Items {
		if option.PathID != pathID || !validProductID(option.TargetID) || !validProductID(option.EvidenceID) || option.Kind != "remove_node" && option.Kind != "enforce_policy" || option.Rank != index+1 {
			return nil, ErrRepositoryUnavailable
		}
		if _, belongsToPath := evidence[option.EvidenceID]; !belongsToPath {
			return nil, ErrRepositoryUnavailable
		}
		key := option.Kind + "\x00" + option.TargetID
		if _, exists := seen[key]; exists {
			return nil, ErrRepositoryUnavailable
		}
		seen[key] = struct{}{}
	}
	return envelope.Items, nil
}

func (repository *PostgresRepository) CountHighRiskPaths(ctx context.Context, scope domain.Scope) (int64, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || scope.Validate() != nil {
		return 0, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskHighPathCountSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return 0, riskProviderError(err)
	}
	var result int64
	if decodeStrictRisk(payload, &result) != nil || result < 0 {
		return 0, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) MutateRiskFinding(ctx context.Context, identity RequestIdentity, mutation RiskFindingMutation) (RiskFindingMutationResult, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !validRiskFindingMutation(mutation) || !validMutationReceiptIdentity(identity, mutation.ReceiptID) {
		return RiskFindingMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskFindingMutateSQL,
		mutation.Operation, mutation.FindingID,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		mutation.IdempotencyKey, mutation.ExpectedVersion, mutation.Status, mutation.Reason, mutation.AuditID, mutation.CorrelationID, mutation.ReceiptID,
	)
	if err != nil {
		return RiskFindingMutationResult{}, riskProviderError(err)
	}
	var result RiskFindingMutationResult
	if decodeStrictRisk(payload, &result) != nil || !validRiskFinding(result.Body) || result.Version != result.Body.Version || result.Version != mutation.ExpectedVersion+1 || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validMutationReceiptIdentity(identity, result.ReceiptID) || !result.Replayed && (result.AuditID != mutation.AuditID || result.CorrelationID != mutation.CorrelationID || result.ReceiptID != mutation.ReceiptID) {
		return RiskFindingMutationResult{}, ErrRepositoryUnavailable
	}
	normalizeRiskFinding(&result.Body)
	return result, nil
}

func validRiskRead(repository *PostgresRepository, ctx context.Context, scope domain.Scope, id string) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && scope.Validate() == nil && validProductID(id)
}

func validRiskPage(repository *PostgresRepository, ctx context.Context, scope domain.Scope, afterID string, limit int) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && scope.Validate() == nil && limit >= 1 && limit <= 100 && (afterID == "" || validProductID(afterID))
}

func validFindingTicketRepository(repository *PostgresRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}

func validFindingTicketCommand(command FindingTicketCommand) bool {
	return validRequestIdentity(command.Identity, false) && validProductID(command.FindingID) && command.ExpectedVersion >= 1 && command.ExpectedVersion <= 1000000 && len(command.IdempotencyKey) >= 16 && len(command.IdempotencyKey) <= 128 && workflowKeyPattern.MatchString(command.IdempotencyKey) && validProductID(command.CorrelationID)
}

func validFindingTicketPayload(payload, encodedDigest string, command FindingTicketCommand, deliveryID string) bool {
	if len(payload) < 2 || len(payload) > 16<<10 || !findingTicketDigestPattern.MatchString(encodedDigest) {
		return false
	}
	decodedDigest, err := hex.DecodeString(strings.TrimPrefix(encodedDigest, "sha256:"))
	if err != nil || len(decodedDigest) != sha256.Size {
		return false
	}
	actualDigest := sha256.Sum256([]byte(payload))
	if subtle.ConstantTimeCompare(actualDigest[:], decodedDigest) != 1 {
		return false
	}
	var body struct {
		DeliveryID string `json:"delivery_id"`
		Event      string `json:"event"`
		Finding    struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
			Version  int64  `json:"version"`
		} `json:"finding"`
		RequestedAt time.Time `json:"requested_at"`
		RequestedBy string    `json:"requested_by"`
		Scope       struct {
			EnvironmentID  string `json:"environment_id"`
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
		} `json:"scope"`
		Version int `json:"version"`
	}
	if decodeStrictRisk(json.RawMessage(payload), &body) != nil {
		return false
	}
	return body.DeliveryID == deliveryID && body.Event == "finding.ticket.requested" && body.Version == 1 && body.Finding.ID == command.FindingID && body.Finding.Version == command.ExpectedVersion && stringIn(body.Finding.Severity, "critical", "high", "medium", "low") && validGlobalSearchName(body.Finding.Title) && body.RequestedBy == command.Identity.PrincipalID.String() && body.Scope.OrganizationID == command.Identity.Scope.OrganizationID().String() && body.Scope.WorkspaceID == command.Identity.Scope.WorkspaceID().String() && body.Scope.EnvironmentID == command.Identity.Scope.EnvironmentID().String() && body.RequestedAt.Location() == time.UTC && validPastServerTime(body.RequestedAt)
}

func validFindingTicketDestination(raw string) bool {
	if len(raw) < 12 || len(raw) > 2048 {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Port() != "" && parsed.Port() != "443" {
		return false
	}
	hostname := parsed.Hostname()
	if hostname == "" || hostname != strings.ToLower(hostname) || !findingTicketHostnamePattern.MatchString(hostname) || net.ParseIP(hostname) != nil || hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".local") || strings.Contains(hostname, "..") {
		return false
	}
	return parsed.Path != "" && strings.HasPrefix(parsed.Path, "/")
}

func validGlobalSearchName(value string) bool {
	if len(value) < 1 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validProductID(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func validRiskFinding(value RiskFinding) bool {
	if !validProductID(value.ID) || value.Source != "posture" && value.Source != "prowler" || len(value.Title) < 1 || len(value.Title) > 256 || !stringIn(value.Severity, "critical", "high", "medium", "low") || !stringIn(value.Status, "open", "under_review", "resolved", "accepted") || len(value.EvidenceIDs) < 1 || len(value.EvidenceIDs) > 64 || value.RiskFactors == nil || len(value.RiskFactors) > 16 || value.Version < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.Rule != "" && len(value.Rule) > 64 || value.ComplianceContext != "" && len(value.ComplianceContext) > 128 || value.Status == "accepted" != (len(value.AcceptanceReason) >= 1 && len(value.AcceptanceReason) <= 512) {
		return false
	}
	if value.AgentID != "" && !validProductID(value.AgentID) || value.PathID != "" && !validProductID(value.PathID) {
		return false
	}
	seenEvidence := map[string]struct{}{}
	for _, id := range value.EvidenceIDs {
		if !validProductID(id) {
			return false
		}
		if _, duplicate := seenEvidence[id]; duplicate {
			return false
		}
		seenEvidence[id] = struct{}{}
	}
	seenFactors := map[string]struct{}{}
	for _, factor := range value.RiskFactors {
		if len(factor.Name) < 1 || len(factor.Name) > 64 || !validProductID(factor.EvidenceID) {
			return false
		}
		if _, belongsToFinding := seenEvidence[factor.EvidenceID]; !belongsToFinding {
			return false
		}
		if _, duplicate := seenFactors[factor.Name]; duplicate {
			return false
		}
		seenFactors[factor.Name] = struct{}{}
	}
	return true
}

func validRiskAttackPath(value RiskAttackPath) bool {
	if !validProductID(value.ID) || !validProductID(value.EntryID) || !validProductID(value.SinkID) || len(value.NodeIDs) < 2 || len(value.NodeIDs) > 8 || !stringIn(value.State, "potential", "observed", "verified", "blocked") || len(value.EvidenceIDs) < 1 || len(value.EvidenceIDs) > 16 || value.Version < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || value.NodeIDs[0] != value.EntryID || value.NodeIDs[len(value.NodeIDs)-1] != value.SinkID {
		return false
	}
	if value.State == "blocked" {
		if value.BlockedEdge < 0 || value.BlockedEdge >= len(value.NodeIDs)-1 {
			return false
		}
	} else if value.BlockedEdge != -1 {
		return false
	}
	return validUniqueProductIDs(value.NodeIDs) && validUniqueProductIDs(value.EvidenceIDs)
}

func validUniqueProductIDs(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validProductID(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validRiskFindingMutation(value RiskFindingMutation) bool {
	if !validProductID(value.FindingID) || len(value.IdempotencyKey) < 16 || len(value.IdempotencyKey) > 128 || !workflowKeyPattern.MatchString(value.IdempotencyKey) || value.ExpectedVersion < 1 || !validProductID(value.AuditID) || !validProductID(value.CorrelationID) {
		return false
	}
	switch value.Operation {
	case "updateFinding":
		return stringIn(value.Status, "open", "under_review", "resolved") && value.Reason == ""
	case "acceptFindingRisk":
		return value.Status == "accepted" && len(value.Reason) >= 1 && len(value.Reason) <= 512 && strings.TrimSpace(value.Reason) == value.Reason
	default:
		return false
	}
}

func decodeStrictRisk(payload json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrRepositoryUnavailable
	}
	return nil
}

func normalizeRiskFinding(value *RiskFinding) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func normalizeRiskAttackPath(value *RiskAttackPath) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func stringIn(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func riskProviderError(err error) error {
	if err == ErrRepositoryOperation {
		return ErrRepositoryUnavailable
	}
	return err
}
