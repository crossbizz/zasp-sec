package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// Worker63 is separately registered after public62. The private runtime
// deliberately requires a canonical chain of exactly 61 schema versions.
//
//go:embed sql/0063_production_security_agent_worker.up.sql
var securityAgentWorkerUpSQL string

//go:embed sql/0063_production_security_agent_worker.down.sql
var securityAgentWorkerDownSQL string

func SecurityAgentWorkerFingerprint() string {
	return "c81c4cb4cb799894ab9bf69b16815341ac53665e967fd0405b32009898510239"
}

// SecurityAgentWorkerChecksum hashes the original unbound sources per call.
// Readiness does not need to render public62 or release61 migration SQL.
func SecurityAgentWorkerChecksum() string {
	digest := sha256.Sum256([]byte(securityAgentWorkerUpSQL + "\x00" + securityAgentWorkerDownSQL))
	return hex.EncodeToString(digest[:])
}

func ProductionSecurityAgentWorker() Metadata {
	digest := sha256.Sum256([]byte(securityAgentWorkerUpSQL + "\x00" + securityAgentWorkerDownSQL))
	checksum := hex.EncodeToString(digest[:])
	bind := strings.NewReplacer("-- worker63 checksum", checksum, "-- worker63 fingerprint", SecurityAgentWorkerFingerprint(), "-- public62 checksum", ProductionSecurityAgentPublic().Checksum(), "-- public62 fingerprint", SecurityAgentPublicFingerprint(), "-- release61 checksum", ProductionSecurityAgentMultistep().Checksum(), "-- release61 fingerprint", SecurityAgentMultistepRegisteredFingerprint())
	return Metadata{version: 63, name: "production_security_agent_worker_extension", checksum: checksum, up: bind.Replace(securityAgentWorkerUpSQL), down: bind.Replace(securityAgentWorkerDownSQL)}
}

const worker63ReadinessSQL = `SELECT zasp_ordered_worker63.ready($1,$2)`

func (r *Runner) UpProductionSecurityAgentWorker(ctx context.Context) error {
	return r.securityAgentWorker(ctx, true)
}

func (r *Runner) DownProductionSecurityAgentWorker(ctx context.Context) error {
	return r.securityAgentWorker(ctx, false)
}

func (r *Runner) securityAgentWorker(ctx context.Context, up bool) error {
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
		if err := tx.Exec(ctx, `LOCK TABLE zasp_ordered_public62.registration IN SHARE MODE`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := requireMigrationReadiness(ctx, tx, public62ReadinessSQL, ProductionSecurityAgentPublic().Checksum(), SecurityAgentPublicFingerprint()); err != nil {
			return err
		}
		var present, registered bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_ordered_worker63') IS NOT NULL,to_regclass('zasp_ordered_worker63.registration') IS NOT NULL`, nil, &present, &registered); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if present != registered {
			return ErrInvalidState
		}
		m := ProductionSecurityAgentWorker()
		if present {
			// Freeze registration before checking its identity, not at DROP.
			// Otherwise a writer can commit drift while down waits to discard it.
			if err := tx.Exec(ctx, `LOCK TABLE zasp_ordered_worker63.registration IN ACCESS EXCLUSIVE MODE`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := requireMigrationReadiness(ctx, tx, worker63ReadinessSQL, m.Checksum(), SecurityAgentWorkerFingerprint()); err != nil {
				return err
			}
		}
		if up && !present {
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_ordered_worker63.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), SecurityAgentWorkerFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if !up && present {
			if err := tx.Exec(ctx, m.DownSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := requireMigrationReadiness(ctx, tx, multistepReadinessSQL, ProductionSecurityAgentMultistep().Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
			return err
		}
		if up {
			return requireMigrationReadiness(ctx, tx, worker63ReadinessSQL, m.Checksum(), SecurityAgentWorkerFingerprint())
		}
		return nil
	})
}
