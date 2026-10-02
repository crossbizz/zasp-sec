package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0059_production_security_agent_webhooks.up.sql
var securityAgentWebhooksUpSQL string

//go:embed sql/0059_production_security_agent_webhooks.down.sql
var securityAgentWebhooksDownSQL string

func SecurityAgentWebhooksFingerprint() string {
	return "e89317deca2aabbeb6e35bbe303d8245ba8ea0dbda6351c2d1b2e458e79842f1"
}

func ProductionSecurityAgentWebhooks() Metadata {
	up := strings.NewReplacer("-- webhook predecessor checksum", ProductionSecurityAgentExports().Checksum(), "-- webhook predecessor fingerprint", SecurityAgentExportsFingerprint()).Replace(securityAgentWebhooksUpSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + securityAgentWebhooksDownSQL))
	checksum := hex.EncodeToString(digest[:])
	up = strings.NewReplacer("-- compiled webhook checksum", checksum, "-- compiled webhook fingerprint", SecurityAgentWebhooksFingerprint()).Replace(up)
	return Metadata{version: 59, name: "production_security_agent_webhooks", checksum: checksum, up: up, down: securityAgentWebhooksDownSQL}
}

const productionSecurityAgentWebhooksReadinessSQL = `SELECT public.zasp_sa_webhook_readiness($1,$2)`

func readProductionSecurityAgentWebhooksState(ctx context.Context, q Queryer) error {
	return readExactReleaseState(ctx, q, append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports(), ProductionSecurityAgentWebhooks()))
}

func (r *Runner) UpProductionSecurityAgentWebhooks(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentExportsState(ctx, tx); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, productionSecurityAgentExportsReadinessSQL, ProductionSecurityAgentExports().Checksum(), SecurityAgentExportsFingerprint()); err != nil {
			return err
		}
		m := ProductionSecurityAgentWebhooks()
		if err := tx.Exec(ctx, m.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_security_agent_webhooks_checksum',$1),('production_security_agent_webhooks_fingerprint',$2)`, m.Checksum(), SecurityAgentWebhooksFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, insertRowSQL, m.Version(), m.Name(), m.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentWebhooksState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionSecurityAgentWebhooksReadinessSQL, m.Checksum(), SecurityAgentWebhooksFingerprint())
	})
}

func (r *Runner) DownProductionSecurityAgentWebhooks(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentWebhooksState(ctx, tx); err != nil {
			return err
		}
		m := ProductionSecurityAgentWebhooks()
		if err := requireMigrationReadiness(ctx, tx, productionSecurityAgentWebhooksReadinessSQL, m.Checksum(), SecurityAgentWebhooksFingerprint()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, m.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, deleteRowSQL, m.Version(), m.Name(), m.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentExportsState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionSecurityAgentExportsReadinessSQL, ProductionSecurityAgentExports().Checksum(), SecurityAgentExportsFingerprint())
	})
}
