package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0065_production_temporal_outbox.up.sql
var temporalOutboxUpSQL string

//go:embed sql/0065_production_temporal_outbox.down.sql
var temporalOutboxDownSQL string

func TemporalOutboxFingerprint() string {
	return "8c64101128b0b31cd4d12575480035ab1e30f157d92fa96c236babc7620de3f8"
}
func ProductionTemporalOutbox() Metadata {
	digest := sha256.Sum256([]byte(temporalOutboxUpSQL + "\x00" + temporalOutboxDownSQL))
	checksum := hex.EncodeToString(digest[:])
	bind := strings.NewReplacer("-- outbox65 checksum", checksum, "-- outbox65 fingerprint", TemporalOutboxFingerprint(), "-- public62 checksum", ProductionSecurityAgentPublic().Checksum(), "-- public62 fingerprint", SecurityAgentPublicFingerprint(), "-- release60 checksum", ProductionDiscoveryScheduleReplay().Checksum(), "-- release60 fingerprint", DiscoveryScheduleReplayFingerprint())
	return Metadata{version: 65, name: "production_temporal_outbox_extension", checksum: checksum, up: bind.Replace(temporalOutboxUpSQL), down: temporalOutboxDownSQL}
}
func (r *Runner) UpProductionTemporalOutbox(ctx context.Context) error {
	return r.temporalOutbox(ctx, true)
}
func (r *Runner) DownProductionTemporalOutbox(ctx context.Context) error {
	return r.temporalOutbox(ctx, false)
}
func (r *Runner) temporalOutbox(ctx context.Context, up bool) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockSecurityAgentMultistep(ctx, tx); err != nil {
			return err
		}
		if !up {
			var retained bool
			if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal67') IS NOT NULL`, nil, &retained); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if retained {
				return ErrInvalidState
			}
		}
		var count int64
		if err := scanRow(ctx, tx, countRowsSQL, nil, &count); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		predecessor := "legacy60"
		if count == 60 {
			if err := readProductionDiscoveryScheduleReplayState(ctx, tx); err != nil {
				return err
			}
			if err := requireMigrationReadiness(ctx, tx, productionDiscoveryScheduleReplayReadinessSQL, ProductionDiscoveryScheduleReplay().Checksum(), DiscoveryScheduleReplayFingerprint()); err != nil {
				return err
			}
		} else if count == 61 {
			predecessor = "ordered62"
			if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
				return err
			}
			if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
				return err
			}
			if err := tx.Exec(ctx, `LOCK TABLE zasp_ordered_public62.registration IN SHARE MODE`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := requireMigrationReadiness(ctx, tx, public62ReadinessSQL, ProductionSecurityAgentPublic().Checksum(), SecurityAgentPublicFingerprint()); err != nil {
				return err
			}
		} else {
			return ErrInvalidState
		}
		var present, registered bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal65') IS NOT NULL,to_regclass('zasp_temporal65.registration') IS NOT NULL`, nil, &present, &registered); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if present != registered {
			return ErrInvalidState
		}
		m := ProductionTemporalOutbox()
		if present {
			if err := tx.Exec(ctx, `LOCK TABLE zasp_temporal65.registration IN ACCESS EXCLUSIVE MODE`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal65.ready($1,$2)`, m.Checksum(), TemporalOutboxFingerprint()); err != nil {
				return err
			}
		}
		if up && !present {
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal65.registration(checksum,fingerprint,predecessor) VALUES($1,$2,$3)`, m.Checksum(), TemporalOutboxFingerprint(), predecessor); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if !up && present {
			if err := tx.Exec(ctx, m.DownSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if up {
			return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal65.ready($1,$2)`, m.Checksum(), TemporalOutboxFingerprint())
		}
		return nil
	})
}
