package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0068_production_temporal_executor.up.sql
var temporalExecutorSQL string

//go:embed sql/0068_production_temporal_executor.planning.sql
var temporalExecutorPlanningSQL string

//go:embed sql/0068_production_temporal_executor.late_usage.sql
var temporalExecutorLateUsageSQL string

//go:embed sql/0068_production_temporal_executor.effects.sql
var temporalExecutorEffectsSQL string

//go:embed sql/0068_production_temporal_executor.linked.sql
var temporalExecutorLinkedSQL string

//go:embed sql/0068_production_temporal_executor.settlement.sql
var temporalExecutorSettlementSQL string

//go:embed sql/0068_production_temporal_executor.application.sql
var temporalExecutorApplicationSQL string

//go:embed sql/0068_production_temporal_executor.delivery.sql
var temporalExecutorDeliverySQL string

//go:embed sql/0068_production_temporal_executor.cleanup.sql
var temporalExecutorCleanupSQL string

func TemporalExecutorFingerprint() string {
	return "437c678da9969a5935fe7efaa27f593fc58eaeac4e74ff434a5ed44eab2b75eb"
}
func TemporalExecutorBaseFingerprint() string {
	return "c7f814af4248cf3f7901d51b116c1ff7bb5374739473b65134072766db7c174a"
}
func TemporalExecutorDomainFingerprint() string {
	return "499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf"
}

func temporalExecutorSource() string {
	source := strings.Replace(temporalExecutorSQL, "-- executor68 planning", temporalExecutorPlanningSQL, 1)
	source = strings.Replace(source, "-- executor68 late usage", temporalExecutorLateUsageSQL, 1)
	source = strings.Replace(source, "-- executor68 effects", temporalExecutorEffectsSQL, 1)
	source = strings.Replace(source, "-- executor68 linked", temporalExecutorLinkedSQL, 1)
	source = strings.Replace(source, "-- executor68 settlement", temporalExecutorSettlementSQL, 1)
	source = strings.Replace(source, "-- executor68 application", temporalExecutorApplicationSQL, 1)
	source = strings.Replace(source, "-- executor68 delivery", temporalExecutorDeliverySQL, 1)
	source = strings.Replace(source, "-- executor68 cleanup", temporalExecutorCleanupSQL, 1)
	return source
}

func ProductionTemporalExecutor() Metadata {
	source := temporalExecutorSource()
	digest := sha256.Sum256([]byte(source))
	checksum := hex.EncodeToString(digest[:])
	bind := strings.NewReplacer("-- executor68 checksum", checksum,
		"-- executor68 fingerprint", TemporalExecutorFingerprint(),
		"-- executor68 base fingerprint", TemporalExecutorBaseFingerprint(),
		"-- executor68 domain fingerprint", TemporalExecutorDomainFingerprint(),
		"-- domain67 checksum", ProductionTemporalDomain().Checksum(),
		"-- domain67 fingerprint", TemporalDomainFingerprint(),
		"-- release61 checksum", ProductionSecurityAgentMultistep().Checksum(),
		"-- release61 fingerprint", SecurityAgentMultistepRegisteredFingerprint())
	return Metadata{version: 68, name: "production_temporal_executor_extension", checksum: checksum, up: bind.Replace(source)}
}

// Installation consumes a validated67 boundary. It never changes execution
// routes, registers logins implicitly, or accepts a catalog observed in place.
func (r *Runner) UpProductionTemporalExecutor(ctx context.Context) error {
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
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal68') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalExecutor()
		if !present {
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal67.ready($1,$2)`, ProductionTemporalDomain().Checksum(), TemporalDomainFingerprint()); err != nil {
				return err
			}
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal68.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalExecutorFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal68.ready($1,$2)`, m.Checksum(), TemporalExecutorFingerprint())
	})
}
