package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0072_production_temporal_discovery.up.sql
var temporalDiscoverySQL string

func TemporalDiscoveryFingerprint() string {
	return "b5d7f17f5350c89b337c6c875975402ab67b10ffc6facc2ea34c042342e9f07e"
}

func ProductionTemporalDiscovery() Metadata {
	sum := sha256.Sum256([]byte(temporalDiscoverySQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- discovery72 checksum", checksum, "-- discovery72 fingerprint", TemporalDiscoveryFingerprint(), "-- legacy71 checksum", ProductionTemporalLegacyTests().Checksum(), "-- legacy71 fingerprint", TemporalLegacyTestsFingerprint()).Replace(temporalDiscoverySQL)
	return Metadata{version: 72, name: "production_temporal_discovery_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalDiscovery(ctx context.Context) error {
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
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal72') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalDiscovery()
		if !present {
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal71.ready($1,$2)`, ProductionTemporalLegacyTests().Checksum(), TemporalLegacyTestsFingerprint()); err != nil {
				return err
			}
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal72.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalDiscoveryFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal72.ready($1,$2)`, m.Checksum(), TemporalDiscoveryFingerprint())
	})
}
