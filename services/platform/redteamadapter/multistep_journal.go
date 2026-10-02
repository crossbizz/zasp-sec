package redteamadapter

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// ordered selects the dormant release61 SQL boundary without registering a
// handler or changing the public release55 client's readiness or decoder. The
// allowlisted translation preserves its closed receipt and request validation.
func (j *PostgresInvocationJournal) ordered() (*PostgresInvocationJournal, error) {
	if j == nil || nilJSONDatabase(j.database) || j.orderedMode || j.checksum != migrations.ProductionSecurityAgentMultistep().Checksum() || j.fingerprint != migrations.SecurityAgentMultistepRegisteredFingerprint() {
		return nil, ErrAdapter
	}
	ordered, err := NewPostgresInvocationJournal(orderedJournalDatabase{j.database}, j.checksum, j.fingerprint)
	if err != nil {
		return nil, ErrAdapter
	}
	ordered.orderedMode = true
	return ordered, nil
}

type orderedJournalDatabase struct{ database JSONDatabase }

func (d orderedJournalDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	switch statement {
	case postgresJournalStartSQL:
		statement = `SELECT zasp_sa_multistep_prior.test_invocation_start($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	case postgresJournalCompleteSQL:
		statement = `SELECT zasp_sa_multistep_prior.test_invocation_complete($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	case postgresJournalResolveSQL:
		statement = `SELECT zasp_sa_multistep_prior.test_invocation_resolve($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	case `SELECT to_jsonb(zasp_production_security_agent_existing_tests_client_ready($1,$2))`:
		statement = `SELECT to_jsonb(zasp_sa_multistep_prior.test_adapter_ready($1,$2))`
	case `SELECT to_jsonb(zasp_red_team_principal_ready($1))`:
	default:
		return nil, ErrAdapter
	}
	return d.database.QueryJSON(ctx, statement, arguments...)
}
