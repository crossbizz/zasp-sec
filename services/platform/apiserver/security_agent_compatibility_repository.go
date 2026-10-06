package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const securityAgentCompatibilityReadySQL = `SELECT jsonb_build_object('release',zasp_temporal70.client_ready($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_worker'))`

// Probe each use; an invalid installed authority must never fall back to public
// historical readiness. Other repository families keep their original checks.
func (d *PostgresJSONDatabase) SecurityAgentCompatibilityAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var present, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal70') IS NOT NULL`).Scan(&present); err != nil {
		return false, ErrRepositoryUnavailable
	}
	if !present {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT zasp_temporal70.client_ready($1,$2)`, migrations.TemporalCompatibilityChecksum(), migrations.TemporalCompatibilityFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}

type securityAgentCompatibilityDatabase struct{ JSONDatabase }

func (d *securityAgentCompatibilityDatabase) available(ctx context.Context) (bool, error) {
	raw, err := d.JSONDatabase.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal70.client_ready($1,$2))`, migrations.TemporalCompatibilityChecksum(), migrations.TemporalCompatibilityFingerprint())
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
func (d *securityAgentCompatibilityDatabase) VerifySecurityAgentBudgetRelease(ctx context.Context) error {
	_, err := d.available(ctx)
	return err
}
func (d *securityAgentCompatibilityDatabase) SecurityAgentExistingTestDefinitionsAvailable(ctx context.Context) (bool, error) {
	return d.available(ctx)
}
func (d *securityAgentCompatibilityDatabase) SecurityAgentExportsAvailable(ctx context.Context) (bool, error) {
	return d.available(ctx)
}
func (d *securityAgentCompatibilityDatabase) SecurityAgentAttackLabAvailable(ctx context.Context) (bool, error) {
	return d.available(ctx)
}

// Only complete fixed statements emitted by the existing typed repository are
// translated. User text, arbitrary SQL and fallback operation names are refused.
func (d *securityAgentCompatibilityDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if q == securityAgentCompatibilityReadySQL {
		return d.JSONDatabase.QueryJSON(ctx, q, args...)
	}
	routed, ok := securityAgentCompatibilityOperations[q]
	if !ok {
		return nil, ErrRepositoryOperation
	}
	if routed == "SELECT zasp_temporal70.op02($1,$2,$3,$4)" {
		present, err := d.JSONDatabase.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`)
		if err != nil {
			return nil, ErrRepositoryUnavailable
		}
		if bytes.Equal(bytes.TrimSpace(present), []byte("true")) {
			return d.JSONDatabase.QueryJSON(ctx, "SELECT zasp_temporal78.retained_schedule($1,$2,$3,$4)", args...)
		}
		if !bytes.Equal(bytes.TrimSpace(present), []byte("false")) {
			return nil, ErrRepositoryUnavailable
		}
		if probe, ok := d.JSONDatabase.(interface {
			SecurityAgentTestSelectorAvailable(context.Context) (bool, error)
		}); ok {
			available, err := probe.SecurityAgentTestSelectorAvailable(ctx)
			if err != nil {
				return nil, err
			}
			if available {
				return d.JSONDatabase.QueryJSON(ctx, "SELECT zasp_temporal75.retained_schedule($1,$2,$3,$4)", args...)
			}
		}
		if probe, ok := d.JSONDatabase.(interface {
			SecurityAgentCommonAdmissionAvailable(context.Context) (bool, error)
		}); ok {
			available, err := probe.SecurityAgentCommonAdmissionAvailable(ctx)
			if err != nil {
				return nil, err
			}
			if available {
				routed = "SELECT zasp_temporal73.schedule($1,$2,$3,$4)"
			}
		}
	}
	return d.JSONDatabase.QueryJSON(ctx, routed, args...)
}

var securityAgentCompatibilityOperations = map[string]string{
	"SELECT public.zasp_security_agent_expire_approvals_v28($1,$2)":                                                               "SELECT zasp_temporal70.op01($1,$2)",
	"SELECT zasp_security_agent_expire_approvals_v28($1,$2)":                                                                      "SELECT zasp_temporal70.op01($1,$2)",
	"SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)":                                           "SELECT zasp_temporal70.op02($1,$2,$3,$4)",
	"SELECT zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)":                                                  "SELECT zasp_temporal70.op02($1,$2,$3,$4)",
	"SELECT public.zasp_security_agent_claim_runs_v23($1,$2,$3,$4)":                                                               "SELECT zasp_temporal70.op03($1,$2,$3,$4)",
	"SELECT zasp_security_agent_claim_runs_v23($1,$2,$3,$4)":                                                                      "SELECT zasp_temporal70.op03($1,$2,$3,$4)",
	"SELECT public.zasp_security_agent_heartbeat_run($1,$2,$3,$4,$5,$6,$7)":                                                       "SELECT zasp_temporal70.op04($1,$2,$3,$4,$5,$6,$7)",
	"SELECT zasp_security_agent_heartbeat_run($1,$2,$3,$4,$5,$6,$7)":                                                              "SELECT zasp_temporal70.op04($1,$2,$3,$4,$5,$6,$7)",
	"SELECT public.zasp_sa_export_planner_context($1,$2,$3,$4,$5,$6)":                                                             "SELECT zasp_temporal70.op05($1,$2,$3,$4,$5,$6)",
	"SELECT zasp_sa_export_planner_context($1,$2,$3,$4,$5,$6)":                                                                    "SELECT zasp_temporal70.op05($1,$2,$3,$4,$5,$6)",
	"SELECT public.zasp_sa_export_accept_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)":                             "SELECT zasp_temporal70.op06($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
	"SELECT zasp_sa_export_accept_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)":                                    "SELECT zasp_temporal70.op06($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
	"SELECT public.zasp_sa_export_fail_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)":                                       "SELECT zasp_temporal70.op07($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
	"SELECT zasp_sa_export_fail_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)":                                              "SELECT zasp_temporal70.op07($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
	"SELECT public.zasp_sa_export_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)":                                "SELECT zasp_temporal70.op08($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
	"SELECT zasp_sa_export_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)":                                       "SELECT zasp_temporal70.op08($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
	"SELECT public.zasp_sa_export_run_kind($1,$2,$3,$4,$5,$6)":                                                                    "SELECT zasp_temporal70.op09($1,$2,$3,$4,$5,$6)",
	"SELECT zasp_sa_export_run_kind($1,$2,$3,$4,$5,$6)":                                                                           "SELECT zasp_temporal70.op09($1,$2,$3,$4,$5,$6)",
	"SELECT public.zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                    "SELECT zasp_temporal70.op10($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                           "SELECT zasp_temporal70.op10($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT public.zasp_sa_export_settlement_claim($1,$2,$3,$4,$5,$6)":                                                            "SELECT zasp_temporal70.op11($1,$2,$3,$4,$5,$6)",
	"SELECT zasp_sa_export_settlement_claim($1,$2,$3,$4,$5,$6)":                                                                   "SELECT zasp_temporal70.op11($1,$2,$3,$4,$5,$6)",
	"SELECT public.zasp_sa_export_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                         "SELECT zasp_temporal70.op12($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT zasp_sa_export_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                                "SELECT zasp_temporal70.op12($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT public.zasp_sa_attack_lab_run_kind($1,$2,$3,$4,$5,$6)":                                                                "SELECT zasp_temporal70.op13($1,$2,$3,$4,$5,$6)",
	"SELECT zasp_sa_attack_lab_run_kind($1,$2,$3,$4,$5,$6)":                                                                       "SELECT zasp_temporal70.op13($1,$2,$3,$4,$5,$6)",
	"SELECT public.zasp_production_security_agent_existing_tests_planner_context($1,$2,$3,$4,$5,$6)":                              "SELECT zasp_temporal70.op14($1,$2,$3,$4,$5,$6)",
	"SELECT zasp_production_security_agent_existing_tests_planner_context($1,$2,$3,$4,$5,$6)":                                     "SELECT zasp_temporal70.op14($1,$2,$3,$4,$5,$6)",
	"SELECT public.zasp_sa_attack_lab_planner_context($1,$2,$3,$4,$5,$6)":                                                         "SELECT zasp_temporal70.op15($1,$2,$3,$4,$5,$6)",
	"SELECT zasp_sa_attack_lab_planner_context($1,$2,$3,$4,$5,$6)":                                                                "SELECT zasp_temporal70.op15($1,$2,$3,$4,$5,$6)",
	"SELECT public.zasp_production_security_agent_existing_tests_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)": "SELECT zasp_temporal70.op16($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
	"SELECT zasp_production_security_agent_existing_tests_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)":        "SELECT zasp_temporal70.op16($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
	"SELECT public.zasp_sa_attack_lab_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)":                            "SELECT zasp_temporal70.op17($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
	"SELECT zasp_sa_attack_lab_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)":                                   "SELECT zasp_temporal70.op17($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
	"SELECT public.zasp_production_security_agent_existing_tests_prepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                     "SELECT zasp_temporal70.op18($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT zasp_production_security_agent_existing_tests_prepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                            "SELECT zasp_temporal70.op18($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT public.zasp_sa_attack_lab_prepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                "SELECT zasp_temporal70.op19($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT zasp_sa_attack_lab_prepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                       "SELECT zasp_temporal70.op19($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT public.zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                     "SELECT zasp_temporal70.op20($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                            "SELECT zasp_temporal70.op20($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT public.zasp_sa_attack_lab_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                "SELECT zasp_temporal70.op21($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT zasp_sa_attack_lab_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)":                                                       "SELECT zasp_temporal70.op21($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
	"SELECT public.zasp_security_agent_budget_settle_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)":                         "SELECT zasp_temporal70.op22($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
	"SELECT zasp_security_agent_budget_settle_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)":                                "SELECT zasp_temporal70.op22($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
}
