package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// Scheduler64 is a separately registered successor, never a canonical row.
//
//go:embed sql/0064_production_security_agent_scheduler.up.sql
var securityAgentSchedulerUpSQL string

//go:embed sql/0064_production_security_agent_scheduler.down.sql
var securityAgentSchedulerDownSQL string

func SecurityAgentSchedulerFingerprint() string {
	return "9a8a090c97a4c8b913921dd1503b6ca0925c837adf5da9219c3c8f1e3a6d0419"
}

func ProductionSecurityAgentScheduler() Metadata {
	digest := sha256.Sum256([]byte(securityAgentSchedulerUpSQL + "\x00" + securityAgentSchedulerDownSQL))
	checksum := hex.EncodeToString(digest[:])
	bind := strings.NewReplacer("-- scheduler64 checksum", checksum, "-- scheduler64 fingerprint", SecurityAgentSchedulerFingerprint(), "-- worker63 checksum", ProductionSecurityAgentWorker().Checksum(), "-- worker63 fingerprint", SecurityAgentWorkerFingerprint(), "-- public62 checksum", ProductionSecurityAgentPublic().Checksum(), "-- public62 fingerprint", SecurityAgentPublicFingerprint(), "-- release61 checksum", ProductionSecurityAgentMultistep().Checksum(), "-- release61 fingerprint", SecurityAgentMultistepRegisteredFingerprint())
	return Metadata{version: 64, name: "production_security_agent_scheduler_extension", checksum: checksum, up: bind.Replace(securityAgentSchedulerUpSQL), down: bind.Replace(securityAgentSchedulerDownSQL)}
}

const scheduler64ReadinessSQL = `SELECT zasp_ordered_scheduler64.ready($1,$2)`

func (r *Runner) UpProductionSecurityAgentScheduler(ctx context.Context) error {
	return r.securityAgentScheduler(ctx, true)
}
func (r *Runner) DownProductionSecurityAgentScheduler(ctx context.Context) error {
	return r.securityAgentScheduler(ctx, false)
}
func (r *Runner) securityAgentScheduler(ctx context.Context, up bool) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockSecurityAgentMultistep(ctx, tx); err != nil {
			return err
		}
		if err := rejectRetiredTemporalScheduler(ctx, tx); err != nil {
			return err
		}
		if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, multistepReadinessSQL, ProductionSecurityAgentMultistep().Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, `LOCK TABLE zasp_ordered_public62.registration,zasp_ordered_worker63.registration IN SHARE MODE`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := requireMigrationReadiness(ctx, tx, worker63ReadinessSQL, ProductionSecurityAgentWorker().Checksum(), SecurityAgentWorkerFingerprint()); err != nil {
			return err
		}
		var present, registered bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_ordered_scheduler64') IS NOT NULL,to_regclass('zasp_ordered_scheduler64.registration') IS NOT NULL`, nil, &present, &registered); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if present != registered {
			return ErrInvalidState
		}
		m := ProductionSecurityAgentScheduler()
		if present {
			if err := tx.Exec(ctx, `LOCK TABLE zasp_ordered_scheduler64.registration IN ACCESS EXCLUSIVE MODE`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := requireMigrationReadiness(ctx, tx, scheduler64ReadinessSQL, m.Checksum(), SecurityAgentSchedulerFingerprint()); err != nil {
				return err
			}
		}
		if up && !present {
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_ordered_scheduler64.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), SecurityAgentSchedulerFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if !up && present {
			if err := tx.Exec(ctx, m.DownSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := requireMigrationReadiness(ctx, tx, worker63ReadinessSQL, ProductionSecurityAgentWorker().Checksum(), SecurityAgentWorkerFingerprint()); err != nil {
			return err
		}
		if up {
			return requireMigrationReadiness(ctx, tx, scheduler64ReadinessSQL, m.Checksum(), SecurityAgentSchedulerFingerprint())
		}
		return nil
	})
}
