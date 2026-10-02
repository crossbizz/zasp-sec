package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0060_production_discovery_schedule_replay.up.sql
var discoveryScheduleReplayUpSQL string

//go:embed sql/0060_production_discovery_schedule_replay.down.sql
var discoveryScheduleReplayDownSQL string

func DiscoveryScheduleReplayFingerprint() string {
	return "1ed52fb5f9a83384e1d3fecbc3bc116d3981a36479e9b3b1f6ec04b5cd4f3b36"
}

func ProductionDiscoveryScheduleReplay() Metadata {
	up := strings.NewReplacer("-- schedule replay predecessor checksum", ProductionSecurityAgentWebhooks().Checksum(), "-- schedule replay predecessor fingerprint", SecurityAgentWebhooksFingerprint()).Replace(discoveryScheduleReplayUpSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + discoveryScheduleReplayDownSQL))
	checksum := hex.EncodeToString(digest[:])
	up = strings.NewReplacer("-- compiled schedule replay checksum", checksum, "-- compiled schedule replay fingerprint", DiscoveryScheduleReplayFingerprint()).Replace(up)
	return Metadata{version: 60, name: "production_discovery_schedule_replay", checksum: checksum, up: up, down: discoveryScheduleReplayDownSQL}
}

const productionDiscoveryScheduleReplayReadinessSQL = `SELECT public.zasp_discovery_schedule_replay_readiness($1,$2)`

func readProductionDiscoveryScheduleReplayState(ctx context.Context, q Queryer) error {
	return readExactReleaseState(ctx, q, append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports(), ProductionSecurityAgentWebhooks(), ProductionDiscoveryScheduleReplay()))
}

func lockDiscoveryScheduleReplay(ctx context.Context, tx Transaction) error {
	for _, statement := range []string{`SET LOCAL lock_timeout='3s'`, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`, `LOCK TABLE public.zasp_discovery_schedules IN ACCESS EXCLUSIVE MODE`, `LOCK TABLE public.zasp_discovery_schedule_runs IN ACCESS EXCLUSIVE MODE`, lockTableSQL} {
		if err := tx.Exec(ctx, statement); err != nil {
			return fixedDatabaseError(ctx, err)
		}
	}
	return nil
}

func (r *Runner) UpProductionDiscoveryScheduleReplay(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockDiscoveryScheduleReplay(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentWebhooksState(ctx, tx); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, productionSecurityAgentWebhooksReadinessSQL, ProductionSecurityAgentWebhooks().Checksum(), SecurityAgentWebhooksFingerprint()); err != nil {
			return err
		}
		m := ProductionDiscoveryScheduleReplay()
		if err := tx.Exec(ctx, m.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_discovery_schedule_replay_checksum',$1),('production_discovery_schedule_replay_fingerprint',$2)`, m.Checksum(), DiscoveryScheduleReplayFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, insertRowSQL, m.Version(), m.Name(), m.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionDiscoveryScheduleReplayState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionDiscoveryScheduleReplayReadinessSQL, m.Checksum(), DiscoveryScheduleReplayFingerprint())
	})
}

func (r *Runner) DownProductionDiscoveryScheduleReplay(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockDiscoveryScheduleReplay(ctx, tx); err != nil {
			return err
		}
		if err := readProductionDiscoveryScheduleReplayState(ctx, tx); err != nil {
			return err
		}
		m := ProductionDiscoveryScheduleReplay()
		if err := requireMigrationReadiness(ctx, tx, productionDiscoveryScheduleReplayReadinessSQL, m.Checksum(), DiscoveryScheduleReplayFingerprint()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, m.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, deleteRowSQL, m.Version(), m.Name(), m.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentWebhooksState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionSecurityAgentWebhooksReadinessSQL, ProductionSecurityAgentWebhooks().Checksum(), SecurityAgentWebhooksFingerprint())
	})
}
