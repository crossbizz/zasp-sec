package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

func composeAdapterProtocols(ctx context.Context, database redteamadapter.JSONDatabase, config redteamadapter.Config, invoker *redteamadapter.HTTPSInvoker) (http.Handler, func(context.Context) error, error) {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, errRuntimeUnavailable
	}
	database = boundedAdapterDatabase{database}
	if retainedAdapterProfileReady(ctx, database) != nil {
		return nil, nil, errRuntimeUnavailable
	}
	present, err := database.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal68') IS NOT NULL)`)
	if err != nil || string(present) != "true" && string(present) != "false" {
		return nil, nil, errRuntimeUnavailable
	}
	if string(present) == "true" {
		journal, err := redteamadapter.NewTemporalPostgresJournal(database, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint())
		if err != nil || journal.Ready(ctx) != nil {
			return nil, nil, errRuntimeUnavailable
		}
		standalone, err := redteamadapter.NewHandler(config, journal.StandaloneResolver(), invoker)
		if err != nil {
			return nil, nil, errRuntimeUnavailable
		}
		effect, err := redteamadapter.NewEffectJournaledHandler(config, journal, invoker, journal)
		if err != nil {
			return nil, nil, errRuntimeUnavailable
		}
		effectReady := journal.Ready
		specialized, err := database.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal74') IS NOT NULL)`)
		if err != nil || string(specialized) != "true" && string(specialized) != "false" {
			return nil, nil, errRuntimeUnavailable
		}
		if string(specialized) == "true" {
			router, err := redteamadapter.NewTestEffectRouter(ctx, database)
			if err != nil {
				return nil, nil, errRuntimeUnavailable
			}
			effect, err = redteamadapter.NewEffectJournaledHandler(config, router, invoker, router)
			if err != nil {
				return nil, nil, errRuntimeUnavailable
			}
			effectReady = router.Ready
		}
		retained, err := redteamadapter.NewPostgresInvocationJournal(database, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
		if err != nil {
			return nil, nil, errRuntimeUnavailable
		}
		retained, err = retained.Release61(ctx)
		if err != nil {
			return nil, nil, errRuntimeUnavailable
		}
		var resolver redteamadapter.TargetResolver = retained
		var linkedJournal redteamadapter.InvocationJournal = retained
		linkedReady := retained.Ready
		installed, err := database.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal71') IS NOT NULL)`)
		if err != nil || string(installed) != "true" && string(installed) != "false" {
			return nil, nil, errRuntimeUnavailable
		}
		if string(installed) == "true" {
			router, err := redteamadapter.NewLegacyJournalRouter(ctx, database)
			if err != nil {
				return nil, nil, errRuntimeUnavailable
			}
			resolver, linkedJournal, linkedReady = router, router, router.Ready
		}
		linked, err := redteamadapter.NewJournaledHandler(config, resolver, invoker, linkedJournal)
		if err != nil {
			return nil, nil, errRuntimeUnavailable
		}
		ready := func(ctx context.Context) error {
			if retainedAdapterProfileReady(ctx, database) != nil || journal.Ready(ctx) != nil || effectReady(ctx) != nil || linkedReady(ctx) != nil {
				return errRuntimeUnavailable
			}
			return nil
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r != nil && r.URL != nil && r.URL.Path == "/v1/effects/evaluate" {
				effect.ServeHTTP(w, r)
				return
			}
			if r != nil && r.URL != nil && r.URL.Path == "/v1/linked/evaluate" {
				linked.ServeHTTP(w, r)
				return
			}
			standalone.ServeHTTP(w, r)
		}), ready, nil
	}
	legacy, err := redteamadapter.NewPostgresResolver(database, migrations.ProductionRedTeamInvocation().Checksum(), migrations.ProductionRedTeamInvocationSemanticFingerprint())
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	journal, err := redteamadapter.NewPostgresInvocationJournal(database, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	ready := func(ctx context.Context) error {
		if retainedAdapterProfileReady(ctx, database) != nil || legacy.Ready(ctx) != nil || journal.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if ready(ctx) != nil {
		return nil, nil, errRuntimeUnavailable
	}
	legacyHandler, err := redteamadapter.NewHandler(config, legacy, invoker)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	linkedHandler, err := redteamadapter.NewJournaledHandler(config, journal, invoker, journal)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	// Exact dispatch avoids ServeMux path cleaning/redirects. Each handler still
	// validates authentication, escaped path, method, body and scoped lease.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.URL != nil && r.URL.Path == "/v1/linked/evaluate" {
			linkedHandler.ServeHTTP(w, r)
			return
		}
		legacyHandler.ServeHTTP(w, r)
	})
	return handler, ready, nil
}

// The private worker profile is not a supported production composition until
// every live family and captured completion path has passed its runtime gate.
// Call before cloud/token loading as well as protocol construction and health.
func retainedAdapterProfileReady(ctx context.Context, database redteamadapter.JSONDatabase) error {
	if ctx == nil || ctx.Err() != nil || database == nil {
		return errRuntimeUnavailable
	}
	present, err := (boundedAdapterDatabase{database}).QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_authorization80_worker') IS NOT NULL)`)
	if err != nil || string(present) != "false" {
		return errRuntimeUnavailable
	}
	return nil
}

// Startup, health and all selected protocol queries keep a per-call SQL bound,
// including retained routes whose callers may provide only a request context.
type boundedAdapterDatabase struct{ redteamadapter.JSONDatabase }

func (d boundedAdapterDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errRuntimeUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return d.JSONDatabase.QueryJSON(ctx, statement, args...)
}
