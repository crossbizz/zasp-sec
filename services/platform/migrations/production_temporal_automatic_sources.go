package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0077_production_temporal_automatic_sources.up.sql
var temporalAutomaticSourcesSQL string

//go:embed sql/0077_production_temporal_automatic_sources.rules.sql
var temporalAutomaticRulesSQL string

//go:embed sql/0077_production_temporal_automatic_sources.runtime.sql
var temporalAutomaticRuntimeSQL string

//go:embed sql/0077_production_temporal_automatic_sources.policy.sql
var temporalAutomaticPolicySQL string

//go:embed sql/0077_production_temporal_automatic_sources.sources.sql
var temporalAutomaticCaptureSQL string

//go:embed sql/0077_production_temporal_automatic_sources.finding.sql
var temporalAutomaticFindingSQL string

//go:embed sql/0077_production_temporal_automatic_sources.matcher.sql
var temporalAutomaticMatcherSQL string

//go:embed sql/0077_production_temporal_automatic_sources.catchup.sql
var temporalAutomaticCatchupSQL string

//go:embed sql/0077_production_temporal_automatic_sources.admission.sql
var temporalAutomaticAdmissionSQL string

//go:embed sql/0077_production_temporal_automatic_sources.pages.sql
var temporalAutomaticPagesSQL string

//go:embed sql/0077_production_temporal_automatic_sources.outbox.sql
var temporalAutomaticOutboxSQL string

func TemporalAutomaticSourcesFingerprint() string {
	return "8cac13406a1886a98cd327065e5525be28997add7a9bd359d12e7b4ed219f5ef"
}

func temporalAutomaticSource() string {
	source := strings.Replace(temporalAutomaticSourcesSQL, "-- automatic77 rules", temporalAutomaticRulesSQL, 1)
	source = strings.Replace(source, "-- automatic77 runtime", temporalAutomaticRuntimeSQL, 1)
	source = strings.Replace(source, "-- automatic77 policy", temporalAutomaticPolicySQL, 1)
	source = strings.Replace(source, "-- automatic77 sources", temporalAutomaticCaptureSQL, 1)
	source = strings.Replace(source, "-- automatic77 finding", temporalAutomaticFindingSQL, 1)
	source = strings.Replace(source, "-- automatic77 matcher", temporalAutomaticMatcherSQL, 1)
	source = strings.Replace(source, "-- automatic77 catchup", temporalAutomaticCatchupSQL, 1)
	source = strings.Replace(source, "-- automatic77 admission", temporalAutomaticAdmissionSQL, 1)
	source = strings.Replace(source, "-- automatic77 pages", temporalAutomaticPagesSQL, 1)
	source = strings.Replace(source, "-- automatic77 outbox", temporalAutomaticOutboxSQL, 1)
	return source
}

// The request path needs the source checksum, not recursively bound ancestor SQL.
func TemporalAutomaticSourcesChecksum() string {
	sum := sha256.Sum256([]byte(temporalAutomaticSource()))
	return hex.EncodeToString(sum[:])
}

// ProductionTemporalAutomaticSources is private staged source. No migrate CLI
// command exposes this release until the dependent dispatcher is ready.
func ProductionTemporalAutomaticSources() Metadata {
	source := temporalAutomaticSource()
	checksum := TemporalAutomaticSourcesChecksum()
	bound := strings.NewReplacer("-- automatic77 checksum", checksum, "-- automatic77 fingerprint", TemporalAutomaticSourcesFingerprint(), "-- human76 checksum", ProductionTemporalHumanAdmission().Checksum(), "-- human76 fingerprint", TemporalHumanAdmissionFingerprint(), "-- compatibility70 checksum", ProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(source)
	return Metadata{version: 77, name: "production_temporal_automatic_sources_extension", checksum: checksum, up: bound}
}

func (r *Runner) UpProductionTemporalAutomaticSources(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockSecurityAgentMultistep(ctx, tx); err != nil {
			return err
		}
		if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal77') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionTemporalAutomaticSources()
		if !present {
			if err := requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal76.ready($1,$2)`, ProductionTemporalHumanAdmission().Checksum(), TemporalHumanAdmissionFingerprint()); err != nil {
				return err
			}
			if err := tx.Exec(ctx, m.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_temporal77.registration(checksum,fingerprint) VALUES($1,$2)`, m.Checksum(), TemporalAutomaticSourcesFingerprint()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return requireMigrationReadiness(ctx, tx, `SELECT zasp_temporal77.ready($1,$2)`, m.Checksum(), TemporalAutomaticSourcesFingerprint())
	})
}
