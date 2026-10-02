package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0078_production_temporal_finding_response.up.sql
var temporalFindingResponseSQL string

//go:embed sql/0078_production_temporal_finding_response.admission.sql
var temporalFindingAdmissionSQL string

//go:embed sql/0078_production_temporal_finding_response.planning.sql
var temporalFindingPlanningSQL string

//go:embed sql/0078_production_temporal_finding_response.accounting.sql
var temporalFindingAccountingSQL string

//go:embed sql/0078_production_temporal_finding_response.effect.sql
var temporalFindingEffectSQL string

//go:embed sql/0078_production_temporal_finding_response.control.sql
var temporalFindingControlSQL string

//go:embed sql/0078_production_temporal_finding_response.delivery.sql
var temporalFindingDeliverySQL string

//go:embed sql/0078_production_temporal_finding_response.human.sql
var temporalFindingHumanSQL string

//go:embed sql/0078_production_temporal_finding_response.decisions.sql
var temporalFindingDecisionsSQL string

//go:embed sql/0078_production_temporal_finding_response.retained.sql
var temporalFindingRetainedSQL string

//go:embed sql/0078_production_temporal_finding_response.reads.sql
var temporalFindingReadsSQL string

//go:embed sql/0078_production_temporal_finding_response.omitted.sql
var temporalFindingOmittedSQL string

//go:embed sql/0078_production_temporal_finding_response.approval.sql
var temporalFindingApprovalSQL string

func TemporalFindingResponseFingerprint() string {
	return "11b999b767465c01389f4482f9196852905866873e585574888281220538d1d4"
}

func TemporalFindingResponseChecksum() string {
	sum := sha256.Sum256([]byte(temporalFindingSource()))
	return hex.EncodeToString(sum[:])
}

func temporalFindingSource() string {
	return strings.NewReplacer("-- finding78 admission", temporalFindingAdmissionSQL, "-- finding78 planning", temporalFindingPlanningSQL, "-- finding78 accounting", temporalFindingAccountingSQL, "-- finding78 effect", temporalFindingEffectSQL, "-- finding78 control", temporalFindingControlSQL, "-- finding78 delivery", temporalFindingDeliverySQL, "-- finding78 human", temporalFindingHumanSQL, "-- finding78 decisions", temporalFindingDecisionsSQL, "-- finding78 retained", temporalFindingRetainedSQL, "-- finding78 reads", temporalFindingReadsSQL, "-- finding78 omitted", temporalFindingOmittedSQL, "-- finding78 approval", temporalFindingApprovalSQL).Replace(temporalFindingResponseSQL)
}

// Staged only. No CLI/publication entrypoint exists for this partial adapter.
func ProductionTemporalFindingResponse() Metadata {
	checksum := TemporalFindingResponseChecksum()
	bound := strings.NewReplacer("-- finding78 checksum", checksum, "-- finding78 fingerprint", TemporalFindingResponseFingerprint(), "-- automatic77 checksum", TemporalAutomaticSourcesChecksum(), "-- automatic77 fingerprint", TemporalAutomaticSourcesFingerprint()).Replace(temporalFindingSource())
	return Metadata{version: 78, name: "production_temporal_finding_response_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalFindingResponse(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockSecurityAgentMultistep(ctx, tx); err != nil {
			return err
		}
		if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal78') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalFindingResponse()
		if !present {
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal77.ready($1,$2)`, TemporalAutomaticSourcesChecksum(), TemporalAutomaticSourcesFingerprint()); err != nil {
				return err
			}
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal78.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalFindingResponseFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal78.ready($1,$2)`, m.Checksum(), TemporalFindingResponseFingerprint())
	})
}
