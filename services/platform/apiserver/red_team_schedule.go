package apiserver

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

const (
	postgresRedTeamGetScheduleSQL = `SELECT zasp_red_team_get_schedule($1,$2,$3,$4)`
	postgresRedTeamPutScheduleSQL = `SELECT zasp_red_team_put_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9)`

	redTeamScheduleMinimumCadenceSeconds = 3600
	redTeamScheduleMaximumCadenceSeconds = 2_678_400
)

// RedTeamSchedule is the continuous re-test of one test definition: on a
// cadence, when the inventory record of the target changes, or both. Version
// 0 means no schedule was ever saved.
type RedTeamSchedule struct {
	DefinitionID   string     `json:"definition_id"`
	Version        int64      `json:"version"`
	Enabled        bool       `json:"enabled"`
	CadenceSeconds *int       `json:"cadence_seconds"`
	OnTargetChange bool       `json:"on_target_change"`
	NextRunAt      *time.Time `json:"next_run_at"`
	LastRunID      *string    `json:"last_run_id"`
	LastTrigger    *string    `json:"last_trigger"`
	LastOutcome    *string    `json:"last_outcome"`
	LastFiredAt    *time.Time `json:"last_fired_at"`
	UpdatedAt      *time.Time `json:"updated_at"`
}

type RedTeamScheduleUpdate struct {
	DefinitionID    string
	ExpectedVersion int64
	Enabled         bool
	CadenceSeconds  *int
	OnTargetChange  bool
}

// RedTeamScheduleAuthority reads and saves the schedule of a test definition.
type RedTeamScheduleAuthority interface {
	GetRedTeamSchedule(context.Context, RequestIdentity, string) (RedTeamSchedule, error)
	PutRedTeamSchedule(context.Context, RequestIdentity, RedTeamScheduleUpdate) (RedTeamSchedule, error)
}

func validRedTeamScheduleUpdate(input RedTeamScheduleUpdate) bool {
	if !validProductID(input.DefinitionID) || input.ExpectedVersion < 0 || input.ExpectedVersion > 999_999 {
		return false
	}
	if input.CadenceSeconds != nil && (*input.CadenceSeconds < redTeamScheduleMinimumCadenceSeconds || *input.CadenceSeconds > redTeamScheduleMaximumCadenceSeconds) {
		return false
	}
	return !input.Enabled || input.CadenceSeconds != nil || input.OnTargetChange
}

func validRedTeamSchedule(value RedTeamSchedule, definitionID string) bool {
	if value.DefinitionID != definitionID || value.Version < 0 || value.Version > 1_000_000 {
		return false
	}
	if value.Version == 0 {
		return !value.Enabled && value.CadenceSeconds == nil && !value.OnTargetChange && value.NextRunAt == nil && value.LastRunID == nil && value.LastTrigger == nil && value.LastOutcome == nil && value.LastFiredAt == nil && value.UpdatedAt == nil
	}
	if value.CadenceSeconds != nil && (*value.CadenceSeconds < redTeamScheduleMinimumCadenceSeconds || *value.CadenceSeconds > redTeamScheduleMaximumCadenceSeconds) {
		return false
	}
	if value.Enabled && value.CadenceSeconds == nil && !value.OnTargetChange || (value.Enabled && value.CadenceSeconds != nil) != (value.NextRunAt != nil) || value.UpdatedAt == nil {
		return false
	}
	if value.LastRunID != nil && !validProductID(*value.LastRunID) || value.LastTrigger != nil && !stringIn(*value.LastTrigger, "cadence", "target_change") || value.LastOutcome != nil && !stringIn(*value.LastOutcome, "queued", "rejected", "skipped_active") {
		return false
	}
	for _, at := range []*time.Time{value.NextRunAt, value.LastFiredAt, value.UpdatedAt} {
		if at != nil && !canonicalRedTeamTime(*at) {
			return false
		}
	}
	return true
}

func (repository *PostgresRepository) GetRedTeamSchedule(ctx context.Context, identity RequestIdentity, definitionID string) (RedTeamSchedule, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || !validProductID(definitionID) {
		return RedTeamSchedule{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamGetScheduleSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID)
	if err != nil {
		return RedTeamSchedule{}, discoveryProviderError(err)
	}
	return decodeRedTeamSchedule(payload, definitionID)
}

func (repository *PostgresRepository) PutRedTeamSchedule(ctx context.Context, identity RequestIdentity, input RedTeamScheduleUpdate) (RedTeamSchedule, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || !validRedTeamScheduleUpdate(input) {
		return RedTeamSchedule{}, ErrRepositoryOperation
	}
	var cadence any
	if input.CadenceSeconds != nil {
		cadence = *input.CadenceSeconds
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamPutScheduleSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.DefinitionID, input.ExpectedVersion, input.Enabled, cadence, input.OnTargetChange)
	if err != nil {
		return RedTeamSchedule{}, discoveryProviderError(err)
	}
	result, err := decodeRedTeamSchedule(payload, input.DefinitionID)
	if err != nil {
		return RedTeamSchedule{}, err
	}
	if result.Version != input.ExpectedVersion+1 || result.Enabled != input.Enabled || result.OnTargetChange != input.OnTargetChange || (result.CadenceSeconds == nil) != (input.CadenceSeconds == nil) || result.CadenceSeconds != nil && *result.CadenceSeconds != *input.CadenceSeconds {
		return RedTeamSchedule{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func decodeRedTeamSchedule(payload []byte, definitionID string) (RedTeamSchedule, error) {
	var result RedTeamSchedule
	if !exactJSONFields(payload, "definition_id", "version", "enabled", "cadence_seconds", "on_target_change", "next_run_at", "last_run_id", "last_trigger", "last_outcome", "last_fired_at", "updated_at") || decodeStrictDiscovery(payload, &result) != nil || !validRedTeamSchedule(result, definitionID) {
		return RedTeamSchedule{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (handler *redTeamPublicHTTPHandler) getProbeCatalog(writer http.ResponseWriter, request *http.Request) {
	identity, ok := IdentityFromRequest(request)
	if !ok || request.Method != http.MethodGet || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || requireZeroByteInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	writeJSONValue(writer, request, http.StatusOK, CurrentRedTeamProbeCatalog(), nil)
}

func (handler *redTeamPublicHTTPHandler) getSchedule(writer http.ResponseWriter, request *http.Request, definitionID string) {
	identity, ok := IdentityFromRequest(request)
	authority, supported := handler.repository.(RedTeamScheduleAuthority)
	if !ok || !supported || request.Method != http.MethodGet || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || !validProductID(definitionID) || requireZeroByteInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := authority.GetRedTeamSchedule(request.Context(), identity, definitionID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *redTeamPublicHTTPHandler) putSchedule(writer http.ResponseWriter, request *http.Request, definitionID string) {
	identity, ok := IdentityFromRequest(request)
	authority, supported := handler.repository.(RedTeamScheduleAuthority)
	var input struct {
		ExpectedVersion *int64 `json:"expected_version"`
		Enabled         *bool  `json:"enabled"`
		CadenceSeconds  *int   `json:"cadence_seconds"`
		OnTargetChange  *bool  `json:"on_target_change"`
	}
	if !ok || !supported || request.Method != http.MethodPut || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || !validProductID(definitionID) || decodeProductionJSON(request, &input) != nil || input.ExpectedVersion == nil || input.Enabled == nil || input.OnTargetChange == nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	update := RedTeamScheduleUpdate{DefinitionID: definitionID, ExpectedVersion: *input.ExpectedVersion, Enabled: *input.Enabled, CadenceSeconds: input.CadenceSeconds, OnTargetChange: *input.OnTargetChange}
	if !validRedTeamScheduleUpdate(update) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := authority.PutRedTeamSchedule(request.Context(), identity, update)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}
