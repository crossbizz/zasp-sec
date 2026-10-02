package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0066_production_temporal_ownership.up.sql
var temporalOwnershipUpSQL string

//go:embed sql/0066_production_temporal_ownership.down.sql
var temporalOwnershipDownSQL string

func TemporalOwnershipFingerprint() string {
	return "422b211febdd6e2b37882dc3f5961a79ca5c58f3f87f1642f7babf1224fbe94a"
}

func ProductionTemporalOwnership() Metadata {
	digest := sha256.Sum256([]byte(temporalOwnershipUpSQL + "\x00" + temporalOwnershipDownSQL))
	checksum := hex.EncodeToString(digest[:])
	bind := strings.NewReplacer("-- owner66 checksum", checksum, "-- owner66 fingerprint", TemporalOwnershipFingerprint(),
		"-- outbox65 checksum", ProductionTemporalOutbox().Checksum(), "-- outbox65 fingerprint", TemporalOutboxFingerprint(),
		"-- public62 checksum", ProductionSecurityAgentPublic().Checksum(), "-- public62 fingerprint", SecurityAgentPublicFingerprint(),
		"-- worker63 checksum", ProductionSecurityAgentWorker().Checksum(), "-- worker63 fingerprint", SecurityAgentWorkerFingerprint(),
		"-- scheduler64 checksum", ProductionSecurityAgentScheduler().Checksum(), "-- scheduler64 fingerprint", SecurityAgentSchedulerFingerprint())
	return Metadata{version: 66, name: "production_temporal_ownership_extension", checksum: checksum, up: bind.Replace(temporalOwnershipUpSQL), down: temporalOwnershipDownSQL}
}

func (r *Runner) UpProductionTemporalOwnership(ctx context.Context) error {
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
		if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_ordered_public62.ready($1,$2)`, ProductionSecurityAgentPublic().Checksum(), SecurityAgentPublicFingerprint()); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal65.ready($1,$2)`, ProductionTemporalOutbox().Checksum(), TemporalOutboxFingerprint()); err != nil {
			return err
		}
		var present, registered bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal66') IS NOT NULL,to_regclass('zasp_temporal66.registration') IS NOT NULL`, nil, &present, &registered); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if present != registered {
			return ErrInvalidState
		}
		m := ProductionTemporalOwnership()
		if !present {
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal66.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalOwnershipFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal66.ready($1,$2)`, m.Checksum(), TemporalOwnershipFingerprint())
	})
}

// Once66 records retirement, obsolete optional schedulers cannot be installed,
// restored, or dropped independently of the retained ownership authority.
func rejectRetiredTemporalScheduler(ctx context.Context, tx Transaction) error {
	var present bool
	if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal66') IS NOT NULL`, nil, &present); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if present {
		return ErrInvalidState
	}
	return nil
}
