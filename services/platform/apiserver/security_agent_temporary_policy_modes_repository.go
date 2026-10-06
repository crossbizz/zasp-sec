package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"time"
)

const temporaryPolicyModesReadySQL = `SELECT jsonb_build_object('release',zasp_sa_temporary81.ready($1,$2),'principal',zasp_security_agent_action_principal_ready())`

// Explicit future source successor. Default repositories and registered native
// profiles are unchanged. Source81 Ready is false and has no production grants.
func NewSecurityAgentTemporaryPolicyModesRepository(database JSONDatabase) (*SecurityAgentActionRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	repository := temporaryPolicyModesSourceRepository(database)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if repository.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func temporaryPolicyModesSourceRepository(database JSONDatabase) *SecurityAgentActionRepository {
	return &SecurityAgentActionRepository{database: database, temporaryPolicyModes: true, readySQL: temporaryPolicyModesReadySQL, checksum: migrations.TemporaryPolicyModesSourceChecksum(), fingerprint: migrations.TemporaryPolicyModesSourceChecksum(),
		claimSQL:     `SELECT zasp_sa_temporary81.claim_effects($1,$2,$3,$4)`,
		heartbeatSQL: `SELECT zasp_sa_temporary81.heartbeat_effect($1,$2,$3,$4,$5,$6,$7,$8)`,
		storeSQL:     `SELECT zasp_sa_temporary81.store_target($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		readSQL:      `SELECT zasp_sa_temporary81.read_target($1,$2,$3,$4,$5,$6,$7)`,
		finishSQL:    `SELECT zasp_sa_temporary81.finish_effect($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`}
}
