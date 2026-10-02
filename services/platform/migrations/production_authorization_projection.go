package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0079_production_authorization_projection.up.sql
var authorizationProjectionUpSQL string

func ProductionAuthorizationProjection() Metadata {
	digest := sha256.Sum256([]byte(authorizationProjectionUpSQL))
	checksum := hex.EncodeToString(digest[:])
	return Metadata{version: 79, name: "production_authorization_projection_extension", checksum: checksum, up: strings.ReplaceAll(authorizationProjectionUpSQL, "-- authorization79 checksum", checksum)}
}
func (r *Runner) UpProductionAuthorizationProjection(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s'; SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		var count int64
		if err := scanRow(ctx, tx, countRowsSQL, nil, &count); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if count < 25 || count > 61 {
			return ErrInvalidState
		}
		for _, metadata := range []Metadata{ProductionIdentityAdministration(), ProductionRedTeamExecution()} {
			var valid bool
			if err := scanRow(ctx, tx, `SELECT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=$1 AND name=$2 AND checksum=$3)`, []any{metadata.Version(), metadata.Name(), metadata.Checksum()}, &valid); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !valid {
				return ErrInvalidState
			}
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_authorization79') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		metadata := ProductionAuthorizationProjection()
		if !present {
			if err := tx.Exec(ctx, metadata.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_authorization79.registration(checksum,fingerprint) VALUES($1,zasp_authorization79.fingerprint())`, metadata.Checksum()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		var ready bool
		if err := scanRow(ctx, tx, `SELECT zasp_authorization79.ready($1)`, []any{metadata.Checksum()}, &ready); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !ready {
			return ErrInvalidState
		}
		return nil
	})
}
