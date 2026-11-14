package apiserver

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresRedTeamStandaloneProtocolSQL  = `SELECT zasp_red_team_standalone_protocol($1,$2,$3,$4)`
	postgresRedTeamStandaloneInstalledSQL = `SELECT to_jsonb(to_regprocedure('public.zasp_red_team_standalone_protocol(text,text,text,text)') IS NOT NULL)`
)

// NewInstalledStandaloneRedTeamExecutionRepository is the worker authority for
// standalone red team runs (queued from the Red Team page or by a schedule)
// on a database where the linked test authority is installed. The release
// readiness of that installation is the linked repository's; this repository
// requires the red team worker principal and the standalone classification
// (completion.sql, section WS2d). Its transitions are the unchanged
// zasp_red_team_* worker functions, each of which refuses a linked run.
func NewInstalledStandaloneRedTeamExecutionRepository(database JSONDatabase) (*RedTeamExecutionRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	repository := &RedTeamExecutionRepository{database: database, authority: RedTeamExecutionAuthorityWorker, installedStandalone: true}
	if repository.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *RedTeamExecutionRepository) installedStandaloneReady(ctx context.Context) error {
	for _, check := range []struct {
		statement string
		arguments []any
	}{{postgresRedTeamStandaloneInstalledSQL, nil}, {postgresRedTeamPrincipalReadySQL, []any{RedTeamExecutionAuthorityWorker}}} {
		var ready bool
		payload, err := repository.database.QueryJSON(ctx, check.statement, check.arguments...)
		if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
			return ErrRepositoryUnavailable
		}
	}
	return nil
}

// currentWorkerProfileReady reports whether the database holds the current
// worker authorization profile and that profile is ready. Both historical
// release predicates of the red team repository pin the releases installed
// at their time, so they are false on every later installation; there the
// worker profile's own gate (zasp_authorization80_worker.runtime_ready, the
// gate every worker passes at startup) is the release readiness. The red team
// principal check that follows is unchanged.
func (repository *RedTeamExecutionRepository) currentWorkerProfileReady(ctx context.Context) bool {
	for _, statement := range []string{`SELECT to_jsonb(to_regnamespace('zasp_authorization80_worker') IS NOT NULL)`, `SELECT to_jsonb(zasp_authorization80_worker.runtime_ready())`} {
		var ready bool
		payload, err := repository.database.QueryJSON(ctx, statement)
		if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
			return false
		}
	}
	return true
}

// StandaloneRunProtocol classifies a run for the red team worker: "standalone"
// for a run that is not a Security Agent test step, "linked" for one that is.
func (repository *RedTeamExecutionRepository) StandaloneRunProtocol(ctx context.Context, scope domain.Scope, runID string) (string, error) {
	if !validRedTeamAuthority(repository, ctx, RedTeamExecutionAuthorityWorker) || scope.Validate() != nil || !validProductID(runID) {
		return "", ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamStandaloneProtocolSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID)
	if err != nil || len(payload) > 1024 || !exactJSONFields(payload, "protocol") {
		return "", ErrRepositoryUnavailable
	}
	var result struct {
		Protocol string `json:"protocol"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || !stringIn(result.Protocol, "standalone", "linked") {
		return "", ErrRepositoryUnavailable
	}
	return result.Protocol, nil
}
