package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0074_production_temporal_test_executor.up.sql
var temporalTestExecutorSQL string

//go:embed sql/0074_production_temporal_test_executor.planning.sql
var temporalTestPlanningSQL string

//go:embed sql/0074_production_temporal_test_executor.effects.sql
var temporalTestEffectsSQL string

//go:embed sql/0074_production_temporal_test_executor.invocation.sql
var temporalTestInvocationSQL string

//go:embed sql/0074_production_temporal_test_executor.settlement.sql
var temporalTestSettlementSQL string

//go:embed sql/0074_production_temporal_test_executor.control.sql
var temporalTestControlSQL string

//go:embed sql/0074_production_temporal_test_executor.approval.sql
var temporalTestApprovalSQL string

//go:embed sql/0074_production_temporal_test_executor.decisions.sql
var temporalTestDecisionsSQL string

//go:embed sql/0074_production_temporal_test_executor.delivery.sql
var temporalTestDeliverySQL string

//go:embed sql/0074_production_temporal_test_executor.compatibility.sql
var temporalTestCompatibilitySQL string

func TemporalTestExecutorFingerprint() string {
	return "0be1a2bfe93c30928eb03eae744993df6ec6c4db692b909aed9b7c486de6aca5"
}

func ProductionTemporalTestExecutor() Metadata {
	source := strings.Replace(temporalTestExecutorSQL, "-- specialized74 planning", temporalTestPlanningSQL, 1)
	source = strings.Replace(source, "-- specialized74 effects", temporalTestEffectsSQL, 1)
	source = strings.Replace(source, "-- specialized74 invocation", temporalTestInvocationSQL, 1)
	source = strings.Replace(source, "-- specialized74 settlement", temporalTestSettlementSQL, 1)
	source = strings.Replace(source, "-- specialized74 control", temporalTestControlSQL, 1)
	source = strings.Replace(source, "-- specialized74 approval", temporalTestApprovalSQL, 1)
	source = strings.Replace(source, "-- specialized74 decisions", temporalTestDecisionsSQL, 1)
	source = strings.Replace(source, "-- specialized74 delivery", temporalTestDeliverySQL, 1)
	source = strings.Replace(source, "-- specialized74 compatibility", temporalTestCompatibilitySQL, 1)
	sum := sha256.Sum256([]byte(source))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- test74 checksum", checksum, "-- test74 fingerprint", TemporalTestExecutorFingerprint(), "-- admission73 checksum", ProductionTemporalAdmission().Checksum(), "-- admission73 fingerprint", TemporalAdmissionFingerprint(), "-- compatibility70 checksum", ProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(source)
	return Metadata{version: 74, name: "production_temporal_test_executor_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalTestExecutor(ctx context.Context) error {
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
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal74') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalTestExecutor()
		if !present {
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal73.ready($1,$2)`, ProductionTemporalAdmission().Checksum(), TemporalAdmissionFingerprint()); err != nil {
				return err
			}
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal74.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalTestExecutorFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal74.ready($1,$2)`, m.Checksum(), TemporalTestExecutorFingerprint())
	})
}
