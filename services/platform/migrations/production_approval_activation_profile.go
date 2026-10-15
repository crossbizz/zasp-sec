package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// ApprovalActivationProfileName identifies a supplementary profile, not a new
// canonical migration. Installation never activates a worker or grants a task.
const ApprovalActivationProfileName = "canonical61-authorization80-approval-activation-v1"

//go:embed sql/approval_activation_profile.sql
var approvalActivationSQL string

func approvalActivationSource() (string, string, error) {
	connectorPin, err := ConnectorMaintenanceProfileChecksum()
	if err != nil {
		return "", "", err
	}
	source := strings.NewReplacer("-- authorization79 checksum", ProductionAuthorizationProjection().Checksum(), "-- authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- connector checksum", connectorPin, "-- approval checksum", ApprovalMaintenanceProfileChecksum()).Replace(approvalActivationSQL)
	digest := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(digest[:])
	return strings.ReplaceAll(source, "-- activation checksum", pin), pin, nil
}

func ApprovalActivationProfileChecksum() (string, error) {
	_, pin, err := approvalActivationSource()
	return pin, err
}

// UpProductionApprovalActivationProfile installs only the sealed successor.
// The measured withdrawal permit and synchronized projection are required by
// the separate activation operation; installation does not establish either.
func (r *Runner) UpProductionApprovalActivationProfile(ctx context.Context) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin, err := approvalActivationSource()
	if err != nil {
		return err
	}
	connectorPin, err := ConnectorMaintenanceProfileChecksum()
	if err != nil {
		return err
	}
	bootstrap, definitions, err := approvalActivationDefinitions(source)
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
		if err := check(`SELECT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND(SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$1) AND zasp_authorization80.ready($2)`, ProductionSecurityAgentMultistep().Checksum(), ProductionAuthorizationEnforcement().Checksum()); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_approval_activation_v1') IS NOT NULL`, nil, &present); err != nil {
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
			return check(`SELECT zasp_authorization79.ready($1) AND zasp_authorization80.ready($2) AND zasp_connector_maintenance.catalog_ready($3) AND zasp_approval_maintenance.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE singleton AND checksum=$4)`, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum(), connectorPin, ApprovalMaintenanceProfileChecksum())
		}
		if err := predecessor(); err != nil {
			return err
		}
		if !present {
			if err := tx.Exec(ctx, definitions); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_approval_activation_v1.registration VALUES(true,$1,zasp_approval_activation_v1.fingerprint())`, pin); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := check(`SELECT zasp_approval_activation_v1.ready() AND EXISTS(SELECT 1 FROM zasp_approval_activation_v1.registration WHERE singleton AND checksum=$1)`, pin); err != nil {
			return err
		}
		return predecessor()
	})
}

func approvalActivationDefinitions(source string) (string, string, error) {
	const ddl = "CREATE SCHEMA zasp_approval_activation_v1 AUTHORIZATION zasp_discovery_authority;"
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
