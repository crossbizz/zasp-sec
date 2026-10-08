package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"regexp"
	"strings"
)

// Supplementary captured-only source. No canonical migration, activation,
// native lifecycle authority, deployment readiness or legacy origin adoption.
const ConnectorEnqueueProvenanceProfileName = "canonical61-authorization80-connector-enqueue-provenance-v1"

//go:embed sql/connector_enqueue_provenance.sql
var connectorEnqueueProvenanceSQL string

func connectorEnqueueProvenanceSource() (string, string, error) {
	// prosrc preserves this unchanged original dollar-quoted function body.
	// Refuse source drift instead of learning a trusted pin from a live database.
	pattern := regexp.MustCompile(`(?s)CREATE FUNCTION "public"\."zasp_connector_stage_pkce_cleanup"\([^;]*?LANGUAGE plpgsql AS \$\$(.*?)\$\$;`)
	matched := pattern.FindAllStringSubmatch(ConnectorAuthorization().UpSQL(), -1)
	if len(matched) != 1 || len(matched[0]) != 2 {
		return "", "", ErrInvalidState
	}
	predecessor := sha256.Sum256([]byte(matched[0][1]))
	source := strings.NewReplacer("-- authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- pkce predecessor source digest", hex.EncodeToString(predecessor[:])).Replace(connectorEnqueueProvenanceSQL)
	h := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(h[:])
	return strings.ReplaceAll(source, "-- connector provenance checksum", pin), pin, nil
}

func ConnectorEnqueueProvenanceProfileChecksum() (string, error) {
	_, pin, err := connectorEnqueueProvenanceSource()
	return pin, err
}

// UpProductionConnectorEnqueueProvenance installs only captured provenance.
// It never selects a worker, registers a forward verifier, claims old work or
// changes canonical79/80 definitions or the three shared outbox consumers.
func (r *Runner) UpProductionConnectorEnqueueProvenance(ctx context.Context) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin, err := connectorEnqueueProvenanceSource()
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
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_connector_provenance') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			if err := tx.Exec(ctx, source); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_connector_provenance.registration VALUES(true,$1,zasp_connector_provenance.fingerprint())`, pin); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return check(`SELECT zasp_connector_provenance.catalog_matches($1)`, pin)
	})
}
