package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0071_production_temporal_legacy_tests.up.sql
var temporalLegacyTestsSQL string

func TemporalLegacyTestsFingerprint() string {
	return "1bfbd14f6f2a23fd3dd2be171473f646cc3c5b0b4b0b36de4dd2f12cec5f07b3"
}

func ProductionTemporalLegacyTests() Metadata {
	sum := sha256.Sum256([]byte(temporalLegacyTestsSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- legacy71 checksum", checksum, "-- legacy71 fingerprint", TemporalLegacyTestsFingerprint(), "-- compatibility70 checksum", ProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(temporalLegacyTestsSQL)
	return Metadata{version: 71, name: "production_temporal_legacy_tests_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalLegacyTests(ctx context.Context) error {
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
		if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal70.ready($1,$2)`, ProductionTemporalCompatibility().Checksum(), TemporalCompatibilityFingerprint()); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal71') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalLegacyTests()
		if !present {
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal71.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalLegacyTestsFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal71.ready($1,$2)`, m.Checksum(), TemporalLegacyTestsFingerprint())
	})
}
