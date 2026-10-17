package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// ApprovalSettlementAuditProfileName identifies an additive audited settlement
// profile. Installation neither activates workers nor rewrites predecessors.
const ApprovalSettlementAuditProfileName = "canonical61-authorization80-approval-settlement-audit-v1"

//go:embed sql/approval_settlement_audit_profile.sql
var approvalSettlementAuditSQL string

func approvalSettlementAuditSource() (string, string, error) {
	activationPin, err := ApprovalActivationProfileChecksum()
	if err != nil {
		return "", "", err
	}
	source := strings.ReplaceAll(approvalSettlementAuditSQL, "-- activation checksum", activationPin)
	digest := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(digest[:])
	return strings.ReplaceAll(source, "-- settlement checksum", pin), pin, nil
}

func ApprovalSettlementAuditProfileChecksum() (string, error) {
	_, pin, err := approvalSettlementAuditSource()
	return pin, err
}

// UpProductionApprovalSettlementAuditProfile coexists with the exact sealed
// activation profile. Unknown existing catalogs refuse without any repair or
// fingerprint replacement. Runtime selection remains explicit and fail closed.
func (r *Runner) UpProductionApprovalSettlementAuditProfile(ctx context.Context) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin, err := approvalSettlementAuditSource()
	if err != nil {
		return err
	}
	activationPin, err := ApprovalActivationProfileChecksum()
	if err != nil {
		return err
	}
	bootstrap, definitions, err := approvalSettlementAuditDefinitions(source)
	if err != nil {
		return err
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s';SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		check := func(q string, args ...any) error {
			var ok bool
			if err := scanRow(ctx, tx, q, args, &ok); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !ok {
				return ErrInvalidState
			}
			return nil
		}
		if err := check(`SELECT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND(SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$1)`, ProductionSecurityAgentMultistep().Checksum()); err != nil {
			return err
		}
		if err := requireMaintenanceAuthorizationReady(ctx, tx); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_approval_settlement_v1') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			if err := tx.Exec(ctx, bootstrap); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		predecessor := func() error {
			return check(`SELECT zasp_approval_activation_v1.catalog_ready($1)`, activationPin)
		}
		if err := predecessor(); err != nil {
			return err
		}
		if !present {
			if err := tx.Exec(ctx, definitions); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_approval_settlement_v1.registration VALUES(true,$1,zasp_approval_settlement_v1.fingerprint())`, pin); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := check(`SELECT zasp_approval_settlement_v1.catalog_ready($1) AND EXISTS(SELECT 1 FROM zasp_approval_settlement_v1.registration WHERE singleton AND checksum=$1)`, pin); err != nil {
			return err
		}
		return predecessor()
	})
}

func approvalSettlementAuditDefinitions(source string) (string, string, error) {
	const ddl = "CREATE SCHEMA zasp_approval_settlement_v1 AUTHORIZATION zasp_discovery_authority;"
	before, definitions, found := strings.Cut(source, ddl)
	if !found || strings.Count(source, ddl) != 1 {
		return "", "", ErrInvalidState
	}
	for _, line := range strings.Split(before, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "--") {
			return "", "", ErrInvalidState
		}
	}
	return before + ddl, definitions, nil
}
