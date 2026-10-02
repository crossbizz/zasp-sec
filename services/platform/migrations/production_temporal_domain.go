package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0067_production_temporal_domain.base.sql
var temporalDomainBaseSQL string

//go:embed sql/0067_production_temporal_domain.up.sql
var temporalDomainUpSQL string

func TemporalDomainBaseFingerprint() string {
	return "b8b6e336ec72fa1b056c5e8a2f65cdd8275e9bbaee498ef1064d5f90133cf191"
}
func TemporalDomainFingerprint() string {
	return "3559e54be45e44575699fb6fad8f23edffe3e98a5b8228f2b2b96ae42057ae92"
}

func ProductionTemporalDomain() Metadata {
	digest := sha256.Sum256([]byte(temporalDomainBaseSQL + "\x00" + temporalDomainUpSQL))
	checksum := hex.EncodeToString(digest[:])
	return Metadata{version: 67, name: "production_temporal_domain_extension", checksum: checksum, up: temporalDomainBind(checksum).Replace(temporalDomainUpSQL)}
}

func temporalDomainBind(checksum string) *strings.Replacer {
	return strings.NewReplacer("-- domain67 checksum", checksum, "-- domain67 fingerprint", TemporalDomainFingerprint(), "-- domain67 base fingerprint", TemporalDomainBaseFingerprint(),
		"-- release60 checksum", ProductionDiscoveryScheduleReplay().Checksum(), "-- release60 fingerprint", DiscoveryScheduleReplayFingerprint(),
		"-- release61 checksum", ProductionSecurityAgentMultistep().Checksum(), "-- release61 fingerprint", SecurityAgentMultistepRegisteredFingerprint(),
		"-- public62 checksum", ProductionSecurityAgentPublic().Checksum(), "-- public62 fingerprint", SecurityAgentPublicFingerprint(),
		"-- outbox65 checksum", ProductionTemporalOutbox().Checksum(), "-- outbox65 fingerprint", TemporalOutboxFingerprint(),
		"-- owner66 checksum", ProductionTemporalOwnership().Checksum(), "-- owner66 fingerprint", TemporalOwnershipFingerprint(),
		"-- worker63 fingerprint", SecurityAgentWorkerFingerprint(), "-- scheduler64 fingerprint", SecurityAgentSchedulerFingerprint())
}

// UpProductionTemporalDomain is a single authority cutover transaction. It does
// not register a new historical61 fingerprint, relax its readiness, or enable a
// route. Replay validates67, never the intentionally superseded62/65/66 pins.
func (r *Runner) UpProductionTemporalDomain(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockSecurityAgentMultistep(ctx, tx); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal67') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalDomain()
		if present {
			if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
				return err
			}
			if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
				return err
			}
			return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal67.ready($1,$2)`, m.Checksum(), TemporalDomainFingerprint())
		}
		var count int64
		if err := scanRow(ctx, tx, countRowsSQL, nil, &count); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		predecessor := "clean60"
		switch count {
		case 60:
			if err := readProductionDiscoveryScheduleReplayState(ctx, tx); err != nil {
				return err
			}
			if err := requireMigrationReadiness(ctx, tx, productionDiscoveryScheduleReplayReadinessSQL, ProductionDiscoveryScheduleReplay().Checksum(), DiscoveryScheduleReplayFingerprint()); err != nil {
				return err
			}
		case 61:
			predecessor = "registered61"
			if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
				return err
			}
			if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
				return err
			}
			if err := requireMigrationReadiness(ctx, tx, multistepReadinessSQL, ProductionSecurityAgentMultistep().Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
				return err
			}
		default:
			return ErrInvalidState
		}
		// Validate every installed predecessor before any source transformation.
		installed := map[string]bool{}
		for _, x := range []struct {
			schema      string
			metadata    Metadata
			fingerprint string
		}{
			{"zasp_ordered_public62", ProductionSecurityAgentPublic(), SecurityAgentPublicFingerprint()},
			{"zasp_temporal65", ProductionTemporalOutbox(), TemporalOutboxFingerprint()},
			{"zasp_temporal66", ProductionTemporalOwnership(), TemporalOwnershipFingerprint()},
		} {
			var exists bool
			if err := scanRow(ctx, tx, `SELECT to_regnamespace($1) IS NOT NULL`, []any{x.schema}, &exists); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			installed[x.schema] = exists
			if exists {
				if err := tx.Exec(ctx, `LOCK TABLE `+x.schema+`.registration IN ACCESS EXCLUSIVE MODE`); err != nil {
					return fixedDatabaseError(ctx, err)
				}
				if err := requireMigrationReadiness(ctx, tx, `SELECT `+x.schema+`.ready($1,$2)`, x.metadata.Checksum(), x.fingerprint); err != nil {
					return err
				}
			}
		}
		if installed["zasp_temporal66"] {
			predecessor = "registered66"
		}
		if count == 60 {
			legacy := ProductionSecurityAgentMultistep()
			for _, statement := range []string{legacy.UpSQL(), multistepRegistrationSQL(securityAgentMultistepPromoteSQL)} {
				if err := tx.Exec(ctx, statement); err != nil {
					return fixedDatabaseError(ctx, err)
				}
			}
			if err := tx.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_security_agent_multistep_checksum',$1),('production_security_agent_multistep_fingerprint',$2)`, legacy.Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, insertRowSQL, legacy.Version(), legacy.Name(), legacy.Checksum()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := tx.Exec(ctx, temporalDomainBind(m.Checksum()).Replace(temporalDomainBaseSQL)); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := requireTemporalDomainCheck(ctx, tx, `SELECT zasp_temporal67.base_ready()`); err != nil {
			return err
		}
		if !installed["zasp_ordered_public62"] {
			p := ProductionSecurityAgentPublic()
			// Exact historical DDL, with its single installation guard bound to the
			// new validated predecessor. Runtime ready is replaced below, not here.
			needle := "public.zasp_sa_multistep_readiness('" + ProductionSecurityAgentMultistep().Checksum() + "','" + SecurityAgentMultistepRegisteredFingerprint() + "')"
			if strings.Count(p.UpSQL(), needle) != 2 {
				return ErrInvalidState
			}
			statement := strings.Replace(p.UpSQL(), needle, "zasp_temporal67.base_ready()", 1)
			if err := tx.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_ordered_public62.registration(checksum,fingerprint) VALUES($1,$2)`, p.Checksum(), SecurityAgentPublicFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if !installed["zasp_temporal65"] {
			p := ProductionTemporalOutbox()
			if err := tx.Exec(ctx, p.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal65.registration(checksum,fingerprint,predecessor) VALUES($1,$2,'ordered62')`, p.Checksum(), TemporalOutboxFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if !installed["zasp_temporal66"] {
			p := ProductionTemporalOwnership()
			if err := tx.Exec(ctx, p.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal66.registration(checksum,fingerprint) VALUES($1,$2)`, p.Checksum(), TemporalOwnershipFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		// No arbitrary observed source gets copied: bind every object and ACL in
		// the three complete predecessor catalogs before rewriting their entries.
		if err := requireTemporalDomainCheck(ctx, tx, `SELECT zasp_ordered_public62.fingerprint()=$1 AND zasp_temporal65.fingerprint()=$2 AND zasp_temporal66.fingerprint()=$3`, SecurityAgentPublicFingerprint(), TemporalOutboxFingerprint(), TemporalOwnershipFingerprint()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, m.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, `INSERT INTO zasp_temporal67.registration(checksum,fingerprint,predecessor,outbox_predecessor) SELECT $1,$2,$3,predecessor FROM zasp_temporal65.registration`, m.Checksum(), TemporalDomainFingerprint(), predecessor); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal67.ready($1,$2)`, m.Checksum(), TemporalDomainFingerprint())
	})
}

func requireTemporalDomainCheck(ctx context.Context, q Queryer, statement string, args ...any) error {
	var ready bool
	if err := scanRow(ctx, q, statement, args, &ready); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if !ready {
		return ErrInvalidState
	}
	return nil
}
