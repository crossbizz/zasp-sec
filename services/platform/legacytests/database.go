// Package legacytests binds the transitional linked-test clients to exact71.
package legacytests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type Query interface {
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
}

var ErrUnavailable = errors.New("legacy linked test authority unavailable")

const Ready55SQL = `SELECT to_jsonb(zasp_production_security_agent_existing_tests_client_ready($1,$2))`
const ReadySQL = `SELECT to_jsonb(zasp_temporal71.client_ready($1,$2,$3))`

type Database struct {
	DB   Query
	Role string
}

func validRole(r string) bool {
	return r == "zasp_red_team_worker" || r == "zasp_red_team_adapter" || r == "zasp_security_agent_worker"
}
func (d Database) Ready(ctx context.Context) error {
	if d.DB == nil || !validRole(d.Role) || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	raw, err := d.DB.QueryJSON(ctx, ReadySQL, migrations.ProductionTemporalLegacyTests().Checksum(), migrations.TemporalLegacyTestsFingerprint(), d.Role)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
func (d Database) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if d.DB == nil || !validRole(d.Role) || ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if q == Ready55SQL {
		if len(args) != 2 || args[0] != migrations.ProductionSecurityAgentExistingTests().Checksum() || args[1] != migrations.SecurityAgentExistingTestsFingerprint() {
			return nil, ErrUnavailable
		}
		return d.DB.QueryJSON(ctx, ReadySQL, migrations.ProductionTemporalLegacyTests().Checksum(), migrations.TemporalLegacyTestsFingerprint(), d.Role)
	}
	if q == `SELECT to_jsonb(zasp_red_team_principal_ready($1))` && len(args) == 1 && args[0] == d.Role && d.Role != "zasp_security_agent_worker" {
		return d.DB.QueryJSON(ctx, q, args...)
	}
	op, ok := operations[q]
	if !ok || op.role != d.Role {
		return nil, ErrUnavailable
	}
	return d.DB.QueryJSON(ctx, op.sql, args...)
}

type operation struct{ role, sql string }

var operations = map[string]operation{
	"SELECT zasp_production_security_agent_existing_tests_worker_protocol($1,$2,$3,$4,$5,$6)":                                                                      {"zasp_red_team_worker", "SELECT zasp_temporal71.op01($1,$2,$3,$4,$5,$6)"},
	"SELECT zasp_production_security_agent_existing_tests_worker_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)":                                                                {"zasp_red_team_worker", "SELECT zasp_temporal71.op02($1,$2,$3,$4,$5,$6,$7,$8,$9)"},
	"SELECT zasp_production_security_agent_existing_tests_worker_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9)":                                                            {"zasp_red_team_worker", "SELECT zasp_temporal71.op03($1,$2,$3,$4,$5,$6,$7,$8,$9)"},
	"SELECT zasp_production_security_agent_existing_tests_worker_cancel($1,$2,$3,$4,$5,$6,$7,$8,$9)":                                                               {"zasp_red_team_worker", "SELECT zasp_temporal71.op04($1,$2,$3,$4,$5,$6,$7,$8,$9)"},
	"SELECT zasp_production_security_agent_existing_tests_worker_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21)": {"zasp_red_team_worker", "SELECT zasp_temporal71.op05($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21)"},
	"SELECT zasp_production_security_agent_existing_tests_invocation_start($1,$2,$3,$4,$5,$6,$7,$8,$9)":                                                            {"zasp_red_team_adapter", "SELECT zasp_temporal71.op06($1,$2,$3,$4,$5,$6,$7,$8,$9)"},
	"SELECT zasp_production_security_agent_existing_tests_invocation_complete($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)":                                     {"zasp_red_team_adapter", "SELECT zasp_temporal71.op07($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)"},
	"SELECT zasp_production_security_agent_existing_tests_invocation_resolve($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                      {"zasp_red_team_adapter", "SELECT zasp_temporal71.op08($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"},
	"SELECT zasp_production_security_agent_existing_tests_reconcile_scopes($1,$2,$3,$4,$5,$6)":                                                                     {"zasp_security_agent_worker", "SELECT zasp_temporal71.op09($1,$2,$3,$4,$5,$6)"},
	"SELECT zasp_production_security_agent_existing_tests_reconcile_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)":                                                             {"zasp_security_agent_worker", "SELECT zasp_temporal71.op10($1,$2,$3,$4,$5,$6,$7,$8,$9)"},
	"SELECT zasp_production_security_agent_existing_tests_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)":                                                  {"zasp_security_agent_worker", "SELECT zasp_temporal71.op11($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"},
	"SELECT zasp_production_security_agent_existing_tests_reconcile_cancel_stopped($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)":                                            {"zasp_security_agent_worker", "SELECT zasp_temporal71.op12($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"},
	"SELECT zasp_production_security_agent_existing_tests_reconcile_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)":                                             {"zasp_security_agent_worker", "SELECT zasp_temporal71.op13($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"},
	"SELECT zasp_production_security_agent_existing_tests_reconcile_release($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)":                                               {"zasp_security_agent_worker", "SELECT zasp_temporal71.op14($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"},
	"SELECT zasp_production_security_agent_existing_tests_reconcile_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)":                                            {"zasp_security_agent_worker", "SELECT zasp_temporal71.op15($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)"},
}
