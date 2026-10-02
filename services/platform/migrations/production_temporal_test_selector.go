package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0075_production_temporal_test_selector.up.sql
var temporalTestSelectorSQL string

func TemporalTestSelectorFingerprint() string {
	return "507b909dd0a59c2ffe8c664d8e70c40d120f63ad215a96fc002141c22687b873"
}
func ProductionTemporalTestSelector() Metadata {
	sum := sha256.Sum256([]byte(temporalTestSelectorSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- selector75 checksum", checksum, "-- selector75 fingerprint", TemporalTestSelectorFingerprint(), "-- test74 checksum", ProductionTemporalTestExecutor().Checksum(), "-- test74 fingerprint", TemporalTestExecutorFingerprint(), "-- compatibility70 checksum", ProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(temporalTestSelectorSQL)
	return Metadata{version: 75, name: "production_temporal_test_selector_extension", checksum: checksum, up: bound}
}
func (r *Runner) UpProductionTemporalTestSelector(ctx context.Context) error {
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
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal75') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalTestSelector()
		if !present {
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal74.ready($1,$2)`, ProductionTemporalTestExecutor().Checksum(), TemporalTestExecutorFingerprint()); err != nil {
				return err
			}
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal75.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalTestSelectorFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal75.ready($1,$2)`, m.Checksum(), TemporalTestSelectorFingerprint())
	})
}
