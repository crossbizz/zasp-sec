package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0070_production_temporal_compatibility.up.sql
var temporalCompatibilitySQL string

func TemporalCompatibilityFingerprint() string {
	return "d15a4b32b9b528fc3913db76097f18d93c74461b31758a19c87142b972f03c99"
}

func ProductionTemporalCompatibility() Metadata {
	sum := sha256.Sum256([]byte(temporalCompatibilitySQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- compatibility70 checksum", checksum, "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint(), "-- workflow69 checksum", ProductionTemporalWorkflow().Checksum(), "-- workflow69 fingerprint", TemporalWorkflowFingerprint()).Replace(temporalCompatibilitySQL)
	return Metadata{version: 70, name: "production_temporal_compatibility_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalCompatibility(ctx context.Context) error {
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
		if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal69.ready($1,$2)`, ProductionTemporalWorkflow().Checksum(), TemporalWorkflowFingerprint()); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal70') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalCompatibility()
		if !present {
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal70.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalCompatibilityFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal70.ready($1,$2)`, m.Checksum(), TemporalCompatibilityFingerprint())
	})
}
