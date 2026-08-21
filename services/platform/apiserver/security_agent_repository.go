package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresSecurityAgentAuthorityReadySQL   = `SELECT jsonb_build_object('release',zasp_security_agent_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_api'))`
	postgresSecurityAgentDefinitionPageSQL   = `SELECT zasp_security_agent_definition_page($1,$2,$3,NULLIF($4,''),$5)`
	postgresSecurityAgentDefinitionValueSQL  = `SELECT zasp_security_agent_definition_value($1,$2,$3,$4)`
	postgresSecurityAgentDefinitionReplaySQL = `SELECT zasp_security_agent_replay_definition($1,$2,$3,$4,$5,$6,$7::jsonb)`
	postgresSecurityAgentDefinitionMutateSQL = `SELECT zasp_security_agent_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`
)

func NewSecurityAgentPostgresRepository(database JSONDatabase) (*PostgresRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	repository := &PostgresRepository{database: database, schema: SecurityAgentExecutionSchemaVersion, securityAgentExecution: true}
	if repository.readySecurityAgentAuthority(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *PostgresRepository) readySecurityAgentAuthority(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentAuthorityReadySQL, migrations.ProductionSecurityAgentExecution().Checksum(), migrations.ProductionSecurityAgentExecutionSemanticFingerprint())
	if err != nil {
		return ErrRepositoryUnavailable
	}
	var raw map[string]json.RawMessage
	var result struct {
		Release   bool `json:"release"`
		Principal bool `json:"principal"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 2 || raw["release"] == nil || raw["principal"] == nil || json.Unmarshal(payload, &result) != nil || !result.Release || !result.Principal {
		return ErrRepositoryUnavailable
	}
	return nil
}
