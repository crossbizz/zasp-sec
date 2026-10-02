package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0076_production_temporal_human_admission.up.sql
var temporalHumanAdmissionSQL string

func TemporalHumanAdmissionFingerprint() string {
	return "606fefa6b41a7627fa6c58687a837b9dc3d0185cabeb761cc420f9933026b079"
}

func ProductionTemporalHumanAdmission() Metadata {
	sum := sha256.Sum256([]byte(temporalHumanAdmissionSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- human76 checksum", checksum, "-- human76 fingerprint", TemporalHumanAdmissionFingerprint(), "-- selector75 checksum", ProductionTemporalTestSelector().Checksum(), "-- selector75 fingerprint", TemporalTestSelectorFingerprint(), "-- compatibility70 checksum", ProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(temporalHumanAdmissionSQL)
	return Metadata{version: 76, name: "production_temporal_human_admission_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalHumanAdmission(ctx context.Context) error {
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
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal76') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalHumanAdmission()
		if !present {
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal75.ready($1,$2)`, ProductionTemporalTestSelector().Checksum(), TemporalTestSelectorFingerprint()); err != nil {
				return err
			}
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal76.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalHumanAdmissionFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal76.ready($1,$2)`, m.Checksum(), TemporalHumanAdmissionFingerprint())
	})
}
