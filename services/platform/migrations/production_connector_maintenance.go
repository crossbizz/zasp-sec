package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// Separate native connector source. Canonical79/80 and original connector
// functions remain immutable. Installation is inactive; it does not rotate
// credentials, withdraw workers, select a runtime or publish projection.
const ConnectorMaintenanceProfileName = "canonical61-authorization80-connector-maintenance-v1"

//go:embed sql/connector_maintenance_profile.sql
var connectorMaintenanceSQL string

func connectorMaintenanceSource() (string, string, error) {
	_, capturePin, err := connectorEnqueueProvenanceSource()
	if err != nil {
		return "", "", err
	}
	source := strings.NewReplacer("-- authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- connector provenance checksum", capturePin).Replace(connectorMaintenanceSQL)
	h := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(h[:])
	return strings.ReplaceAll(source, "-- connector maintenance checksum", pin), pin, nil
}
func ConnectorMaintenanceProfileChecksum() (string, error) {
	_, pin, err := connectorMaintenanceSource()
	return pin, err
}

// UpProductionConnectorMaintenance registers the captured enqueue and complete
// native lifecycle definitions in one transaction. Existing unknown catalogs
// refuse. Only a separately verified cutover may later activate projection.
func (r *Runner) UpProductionConnectorMaintenance(ctx context.Context) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin, err := connectorMaintenanceSource()
	if err != nil {
		return err
	}
	captureSource, capturePin, err := connectorEnqueueProvenanceSource()
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
		if err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		var capturePresent bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_connector_provenance') IS NOT NULL`, nil, &capturePresent); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !capturePresent {
			if err := tx.Exec(ctx, captureSource); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_connector_provenance.registration VALUES(true,$1,zasp_connector_provenance.fingerprint())`, capturePin); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := check(`SELECT zasp_connector_provenance.catalog_matches($1)`, capturePin); err != nil {
			return err
		}
		// Composed projection preserves the approval family's desired tuples.
		// It cannot install against a missing/unregistered predecessor or fall
		// back to canonical-only projection while another family is active.
		if err := check(`SELECT to_regnamespace('zasp_approval_maintenance') IS NOT NULL`); err != nil {
			return err
		}
		if err := check(`SELECT zasp_approval_maintenance.catalog_ready()`); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_connector_maintenance') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			if err := tx.Exec(ctx, source); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_connector_maintenance.registration VALUES(true,$1,zasp_connector_maintenance.fingerprint(),false)`, pin); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return check(`SELECT zasp_connector_maintenance.catalog_ready($1)`, pin)
	})
}
