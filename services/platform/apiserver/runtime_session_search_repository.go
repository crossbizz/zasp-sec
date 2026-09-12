package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
	"strconv"
	"time"
	"unicode/utf8"
)

const postgresRuntimeSessionQueryStatusSQL = `SELECT zasp_runtime_session_query_status($1,$2,$3,$4)`
const postgresRuntimeSessionQueryHydrateSQL = `SELECT zasp_runtime_session_query_hydrate($1,$2,$3,$4,$5)`

type RuntimeSessionSearchIndex interface {
	Search(context.Context, domain.Scope, sessionsearch.Filters, string, int) (searchdriver.SessionSearchPage, error)
}

func NewPostgresRepositoryWithRuntimeSessionSearchIndex(database JSONDatabase, index RuntimeSessionSearchIndex, name string) (*PostgresRepository, error) {
	if !searchdriver.ValidSessionIndexName(name) {
		return nil, ErrRepositoryConfiguration
	}
	repository, err := NewPostgresRepositoryWithRuntimeSessionSearch(database, index)
	if err != nil {
		return nil, err
	}
	repository.sandboxSessionSearch = name == "zasp-runtime-sessions-v2"
	return repository, nil
}

func (repository *PostgresRepository) readyRuntimeSessionSearch(ctx context.Context) error {
	if !repository.sandboxSessionSearch {
		return nil
	}
	metadata := migrations.ProductionRuntimeSandboxBinding()
	body, err := repository.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_production_runtime_sandbox_binding_readiness($1,$2))`, metadata.Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint())
	if err != nil || ctx.Err() != nil || !bytes.Equal(bytes.TrimSpace(body), []byte("true")) {
		return ErrRepositoryUnavailable
	}
	return nil
}

func NewPostgresRepositoryWithRuntimeSessionSearch(database JSONDatabase, index RuntimeSessionSearchIndex) (*PostgresRepository, error) {
	if nilInterface(index) {
		return nil, ErrRepositoryConfiguration
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		return nil, err
	}
	repository.runtimeSessionSearch = index
	repository.sandboxSessionReads = true
	return repository, nil
}

// Current describes committed indexing checkpoints. It does not attest provider
// health, unseen sensor events, complete selector metadata or snapshot isolation.
type RuntimeSessionSearchStatus struct {
	State             string     `json:"state"`
	Pending           int        `json:"pending_batches"`
	PendingCapped     bool       `json:"pending_batches_capped"`
	Quarantined       int        `json:"quarantined_batches"`
	QuarantinedCapped bool       `json:"quarantined_batches_capped"`
	LastIndexed       *time.Time `json:"last_indexed_at"`
	OldestPending     *time.Time `json:"oldest_pending_at"`
	CheckedAt         time.Time  `json:"checked_at"`
	SelectorCoverage  string     `json:"selector_coverage"`
}
type runtimeQuerySummary struct {
	Kind        string    `json:"kind"`
	ID          string    `json:"id"`
	Workspace   string    `json:"workspace_id"`
	Environment string    `json:"environment_id"`
	Agent       *string   `json:"agent_id"`
	Principal   *string   `json:"principal_id"`
	First       time.Time `json:"first_event_at"`
	Last        time.Time `json:"last_event_at"`
	Projected   time.Time `json:"projected_at"`
	EventCount  int64     `json:"event_count"`
	Counts      struct {
		Exact        int64 `json:"exact"`
		Strong       int64 `json:"strong"`
		Probable     int64 `json:"probable"`
		Unattributed int64 `json:"unattributed"`
	} `json:"confidence_counts"`
}

func runtimeSessionQueryFilters(scope domain.Scope, parameters map[string]string) (sessionsearch.Filters, int, error) {
	for key, value := range parameters {
		switch key {
		case "kind", "limit", "cursor_binding", "after_id", "agent_id", "principal_id", "tool", "process", "file", "domain", "credential_id", "resource", "decision", "from", "to":
		case "after_parent_id", "after_time":
			if value != "" {
				return sessionsearch.Filters{}, 0, ErrRepositoryOperation
			}
		default:
			return sessionsearch.Filters{}, 0, ErrRepositoryOperation
		}
	}
	limit, err := strconv.Atoi(parameters["limit"])
	if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != parameters["limit"] || parameters["kind"] != "runtime" {
		return sessionsearch.Filters{}, 0, ErrRepositoryOperation
	}
	filters := sessionsearch.Filters{AgentID: parameters["agent_id"], PrincipalID: parameters["principal_id"], Tool: parameters["tool"], Process: parameters["process"], File: parameters["file"], Domain: parameters["domain"], Credential: parameters["credential_id"], Resource: parameters["resource"], Decision: parameters["decision"]}
	for _, bound := range []struct {
		key string
		out *time.Time
	}{{"from", &filters.From}, {"to", &filters.To}} {
		if value := parameters[bound.key]; value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
				return sessionsearch.Filters{}, 0, ErrRepositoryOperation
			}
			*bound.out = parsed
		}
	}
	if _, err := sessionsearch.BuildQuery(scope, filters, parameters["after_id"], limit+1); err != nil {
		return sessionsearch.Filters{}, 0, ErrRepositoryOperation
	}
	return filters, limit, nil
}

func decodeRuntimeSearchStatus(payload json.RawMessage, started time.Time) (RuntimeSessionSearchStatus, error) {
	var status RuntimeSessionSearchStatus
	if !runtimeQueryNonNullFields(payload, "state", "pending_batches", "pending_batches_capped", "quarantined_batches", "quarantined_batches_capped", "checked_at", "selector_coverage") {
		return status, ErrRepositoryUnavailable
	}
	if !exactJSONFields(payload, "state", "pending_batches", "pending_batches_capped", "quarantined_batches", "quarantined_batches_capped", "last_indexed_at", "oldest_pending_at", "checked_at", "selector_coverage") || decodeStrictDiscovery(payload, &status) != nil || status.SelectorCoverage != "observed_only" || status.Pending < 0 || status.Pending > 1000 || status.Quarantined < 0 || status.Quarantined > 1000 || status.PendingCapped && status.Pending != 1000 || status.QuarantinedCapped && status.Quarantined != 1000 || status.CheckedAt.IsZero() || status.CheckedAt.Before(started.Add(-2*time.Second)) || status.CheckedAt.After(time.Now().Add(2*time.Second)) || (status.Pending > 0) != (status.OldestPending != nil) {
		return RuntimeSessionSearchStatus{}, ErrRepositoryUnavailable
	}
	for _, timestamp := range []*time.Time{status.LastIndexed, status.OldestPending} {
		if timestamp != nil && (timestamp.IsZero() || timestamp.After(status.CheckedAt)) {
			return RuntimeSessionSearchStatus{}, ErrRepositoryUnavailable
		}
	}
	expected := "current"
	if status.Quarantined > 0 {
		expected = "blocked"
	} else if status.Pending > 0 {
		expected = "catching_up"
	} else if status.LastIndexed == nil {
		expected = "empty"
	}
	if status.State != expected {
		return RuntimeSessionSearchStatus{}, ErrRepositoryUnavailable
	}
	return status, nil
}
func validRuntimeQuerySummary(payload json.RawMessage, identity RequestIdentity, id string) bool {
	if !runtimeQueryNonNullFields(extractJSONField(payload, "confidence_counts"), "exact", "strong", "probable", "unattributed") {
		return false
	}
	if !exactJSONFields(payload, "kind", "id", "workspace_id", "environment_id", "agent_id", "principal_id", "first_event_at", "last_event_at", "projected_at", "event_count", "confidence_counts") || !exactJSONFields(extractJSONField(payload, "confidence_counts"), "exact", "strong", "probable", "unattributed") {
		return false
	}
	var summary runtimeQuerySummary
	if decodeStrictDiscovery(payload, &summary) != nil || summary.ID != id || summary.Workspace != identity.Scope.WorkspaceID().String() || summary.Environment != identity.Scope.EnvironmentID().String() || summary.First.IsZero() || summary.Last.Before(summary.First) || summary.Projected.IsZero() || summary.EventCount < 1 || summary.EventCount > 9007199254740991 {
		return false
	}
	if id == "unattributed" {
		if summary.Kind != "unattributed" || summary.Agent != nil || summary.Principal != nil {
			return false
		}
	} else if summary.Kind != "runtime" {
		return false
	}
	for _, reference := range []*string{summary.Agent, summary.Principal} {
		if reference != nil && !validAdministrationProductID(*reference) {
			return false
		}
	}
	var total int64
	for _, count := range []int64{summary.Counts.Exact, summary.Counts.Strong, summary.Counts.Probable, summary.Counts.Unattributed} {
		if count < 0 || count > summary.EventCount {
			return false
		}
		total += count
	}
	return total == summary.EventCount
}

func runtimeQueryNonNullFields(payload json.RawMessage, keys ...string) bool {
	var values map[string]json.RawMessage
	if json.Unmarshal(payload, &values) != nil {
		return false
	}
	for _, key := range keys {
		value, exists := values[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func (repository *PostgresRepository) searchRuntimeSessions(ctx context.Context, identity RequestIdentity, parameters map[string]string) (payload json.RawMessage, resultErr error) {
	defer func() {
		if recover() != nil {
			payload = nil
			resultErr = ErrRepositoryUnavailable
		}
	}()
	if repository == nil || nilInterface(repository.database) || nilInterface(repository.runtimeSessionSearch) || ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	filters, limit, err := runtimeSessionQueryFilters(identity.Scope, parameters)
	if err != nil || !validAdministrationProductID(identity.PrincipalID.String()) {
		return nil, ErrRepositoryOperation
	}
	started := time.Now()
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}
	query := func(statement string, args ...any) (json.RawMessage, error) {
		body, err := repository.database.QueryJSON(ctx, statement, args...)
		if errors.Is(err, ErrRepositoryNotFound) {
			return nil, ErrRepositoryNotFound
		}
		if err != nil || ctx.Err() != nil || len(body) == 0 || len(body) > 8<<20 || !utf8.Valid(body) {
			return nil, ErrRepositoryUnavailable
		}
		return body, nil
	}
	statusSQL, hydrateSQL := postgresRuntimeSessionQueryStatusSQL, postgresRuntimeSessionQueryHydrateSQL
	if repository.sandboxSessionSearch {
		if err := repository.readyRuntimeSessionSearch(ctx); err != nil {
			return nil, ErrRepositoryUnavailable
		}
		statusSQL = `SELECT zasp_runtime_sandbox_query_status($1,$2,$3,$4)`
		hydrateSQL = `SELECT zasp_runtime_sandbox_query_hydrate($1,$2,$3,$4,$5)`
	}
	statusBody, err := query(statusSQL, args...)
	if err != nil {
		return nil, err
	}
	if _, err := decodeRuntimeSearchStatus(statusBody, started); err != nil {
		return nil, err
	}
	candidates, err := repository.runtimeSessionSearch.Search(ctx, identity.Scope, filters, parameters["after_id"], limit+1)
	if err != nil || ctx.Err() != nil || candidates.InvestigationIDs == nil || len(candidates.InvestigationIDs) > limit+1 {
		return nil, ErrRepositoryUnavailable
	}
	previous := parameters["after_id"]
	for _, id := range candidates.InvestigationIDs {
		if !runtimeSessionTarget(id) || id <= previous {
			return nil, ErrRepositoryUnavailable
		}
		previous = id
	}
	if len(candidates.InvestigationIDs) == 0 {
		if candidates.After != "" {
			return nil, ErrRepositoryUnavailable
		}
	} else if !runtimeSessionTarget(candidates.After) || candidates.After < previous {
		return nil, ErrRepositoryUnavailable
	}
	payload, err = query(hydrateSQL, append(args, candidates.InvestigationIDs)...)
	if err != nil {
		return nil, err
	}
	var page struct {
		Items  []json.RawMessage `json:"items"`
		Search json.RawMessage   `json:"search"`
	}
	if !exactJSONFields(payload, "items", "search") || decodeStrictDiscovery(payload, &page) != nil || page.Items == nil || len(page.Items) != len(candidates.InvestigationIDs) {
		return nil, ErrRepositoryUnavailable
	}
	if _, err := decodeRuntimeSearchStatus(page.Search, started); err != nil {
		return nil, err
	}
	for position, item := range page.Items {
		if !validRuntimeQuerySummary(item, identity, candidates.InvestigationIDs[position]) {
			return nil, ErrRepositoryUnavailable
		}
	}
	return payload, nil
}
