package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0069_production_temporal_workflow.up.sql
var temporalWorkflowSQL string

func TemporalWorkflowFingerprint() string {
	return "5c5952d665d582373bf63d010b5d9f6d85cdf197e8a8b5f37554058e146b960d"
}
func ProductionTemporalWorkflow() Metadata {
	sum := sha256.Sum256([]byte(temporalWorkflowSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- workflow69 checksum", checksum, "-- workflow69 fingerprint", TemporalWorkflowFingerprint(), "-- executor68 checksum", ProductionTemporalExecutor().Checksum(), "-- executor68 fingerprint", TemporalExecutorFingerprint()).Replace(temporalWorkflowSQL)
	return Metadata{version: 69, name: "production_temporal_workflow_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalWorkflow(ctx context.Context) error {
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
		if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal68.ready($1,$2)`, ProductionTemporalExecutor().Checksum(), TemporalExecutorFingerprint()); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal69') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalWorkflow()
		if !present {
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal69.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalWorkflowFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal69.ready($1,$2)`, m.Checksum(), TemporalWorkflowFingerprint())
	})
}
