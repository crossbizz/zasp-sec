package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0073_production_temporal_admission.up.sql
var temporalAdmissionSQL string

func TemporalAdmissionFingerprint() string {
	return "09895c8411beabd971e2425c3382a1152df3d224334ded17433fa80ae243b115"
}

func ProductionTemporalAdmission() Metadata {
	sum := sha256.Sum256([]byte(temporalAdmissionSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- admission73 checksum", checksum, "-- admission73 fingerprint", TemporalAdmissionFingerprint(), "-- discovery72 checksum", ProductionTemporalDiscovery().Checksum(), "-- discovery72 fingerprint", TemporalDiscoveryFingerprint(), "-- compatibility70 checksum", ProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(temporalAdmissionSQL)
	return Metadata{version: 73, name: "production_temporal_admission_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalAdmission(ctx context.Context) error {
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
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal73') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalAdmission()
		if !present {
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal72.ready($1,$2)`, ProductionTemporalDiscovery().Checksum(), TemporalDiscoveryFingerprint()); err != nil {
				return err
			}
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal73.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalAdmissionFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal73.ready($1,$2)`, m.Checksum(), TemporalAdmissionFingerprint())
	})
}
