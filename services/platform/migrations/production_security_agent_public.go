package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// This is an extension of registered61, not row62 in zasp_schema_versions.
// The private runtime deliberately requires a canonical chain of exactly61.
//
//go:embed sql/0062_production_security_agent_public.up.sql
var securityAgentPublicUpSQL string

//go:embed sql/0062_production_security_agent_public.down.sql
var securityAgentPublicDownSQL string

func SecurityAgentPublicFingerprint() string {
	return "07e774a28105095c73275ad959c765a3fddda9ee9aa81e81cd3828222e40aad3"
}

func ProductionSecurityAgentPublic() Metadata {
	digest := sha256.Sum256([]byte(securityAgentPublicUpSQL + "\x00" + securityAgentPublicDownSQL))
	checksum := hex.EncodeToString(digest[:])
	bind := strings.NewReplacer("-- public62 checksum", checksum, "-- public62 fingerprint", SecurityAgentPublicFingerprint(), "-- release61 checksum", ProductionSecurityAgentMultistep().Checksum(), "-- release61 fingerprint", SecurityAgentMultistepRegisteredFingerprint())
	return Metadata{version: 62, name: "production_security_agent_public_extension", checksum: checksum, up: bind.Replace(securityAgentPublicUpSQL), down: bind.Replace(securityAgentPublicDownSQL)}
}

const public62ReadinessSQL = `SELECT zasp_ordered_public62.ready($1,$2)`

func (r *Runner) UpProductionSecurityAgentPublic(ctx context.Context) error {
	return r.securityAgentPublic(ctx, true)
}

func (r *Runner) DownProductionSecurityAgentPublic(ctx context.Context) error {
	return r.securityAgentPublic(ctx, false)
}

func (r *Runner) securityAgentPublic(ctx context.Context, up bool) error {
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
		if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, multistepReadinessSQL, ProductionSecurityAgentMultistep().Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
			return err
		}
		var present, registered bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_ordered_public62') IS NOT NULL,to_regclass('zasp_ordered_public62.registration') IS NOT NULL`, nil, &present, &registered); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if present != registered {
			return ErrInvalidState
		}
		m := ProductionSecurityAgentPublic()
		if present {
			// Freeze registration before checking its identity, not at DROP.
			// Otherwise a writer can commit drift while down waits to discard it.
			if err := tx.Exec(ctx, `LOCK TABLE zasp_ordered_public62.registration IN ACCESS EXCLUSIVE MODE`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := requireMigrationReadiness(ctx, tx, public62ReadinessSQL, m.Checksum(), SecurityAgentPublicFingerprint()); err != nil {
				return err
			}
		}
		if up && !present {
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_ordered_public62.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), SecurityAgentPublicFingerprint()); err != nil {
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
			return requireMigrationReadiness(ctx, tx, public62ReadinessSQL, m.Checksum(), SecurityAgentPublicFingerprint())
		}
		return nil
	})
}
