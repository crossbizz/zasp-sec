package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestCurrentRuntimeIngestRequiresExplicitDatabaseProfile(t *testing.T) {
	for _, profile := range []string{"", migrations.AuthorizationRuntimeProfileName, "current", " " + migrations.AuthorizationRuntimeProfileName} {
		environment := validProductionIngestEnvironment()
		environment["ZASP_RUNTIME_DATABASE_PROFILE"] = profile
		config, err := loadProductionIngestConfig(func(k string) string { return environment[k] })
		valid := profile == "" || profile == migrations.AuthorizationRuntimeProfileName
		if (err == nil) != valid {
			t.Fatal("unknown database profile admitted", profile, err)
		}
		if !valid {
			continue
		}
		db := &precisionConfigDatabase{}
		repository, err := newProfiledProductionIngestRepository(db, config)
		if err != nil {
			t.Fatal(err)
		}
		_ = repository.Ready(context.Background())
		current := strings.Contains(db.query, "zasp_authorization80_runtime.ready(")
		if current != (profile == migrations.AuthorizationRuntimeProfileName) {
			t.Fatal("payload schema inferred database authority", profile, db.query)
		}
	}
}

type currentCompositionDatabase struct{ compositionDatabase }

func (d *currentCompositionDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if q == `SELECT jsonb_build_object('ready',zasp_authorization80_runtime.ready($1,$2))` {
		return d.compositionDatabase.QueryJSON(ctx, "current profile readiness", args...)
	}
	if q == `SELECT zasp_authorization80_runtime.runtime_claim_reconciliation_v2($1,$2,$3,$4)` {
		return d.compositionDatabase.QueryJSON(ctx, `SELECT zasp_runtime_claim_reconciliation_v2($1,$2,$3,$4)`, args...)
	}
	if q == `SELECT zasp_authorization80_runtime.runtime_release_reconciliation($1,$2,$3,$4,$5,$6,$7,$8,$9)` {
		return d.compositionDatabase.QueryJSON(ctx, `SELECT zasp_runtime_release_reconciliation($1,$2,$3,$4,$5,$6,$7,$8,$9)`, args...)
	}
	return nil, errRuntimeUnavailable
}

// A current-profile reconciler owns the superset backlog even when this intake
// process admits only semantic v1 requests. It must not claim v2 and abandon it.
func TestCurrentRuntimeIngestReconcilesPreciseBacklogWithSemanticIntake(t *testing.T) {
	values := validProductionIngestEnvironment()
	values["ZASP_RUNTIME_DATABASE_PROFILE"] = migrations.AuthorizationRuntimeProfileName
	values["ZASP_RUNTIME_INGEST_SCHEMA"] = "runtime-event-v1"
	config, err := loadProductionIngestConfig(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	db, artifacts := &currentCompositionDatabase{}, &compositionArtifacts{}
	dependencies, err := composeProductionIngestDependencies(context.Background(), config, db, artifacts, func(context.Context) error { return nil }, func() time.Time { return time.Now().UTC() }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = dependencies.Reconcile(context.Background()); err != nil || artifacts.inspections != 1 {
		t.Fatal("semantic intake abandoned current precise recovery lease", err, artifacts.inspections)
	}
}
