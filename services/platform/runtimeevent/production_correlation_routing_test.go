package runtimeevent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestCorrelationRoutingCapabilityPinsReleaseAndClaims(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "schema49", true: "schema48"}[legacy], func(t *testing.T) {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), json.RawMessage(`[]`)}}
			if legacy {
				database.responses = append([]json.RawMessage{nil}, database.responses...)
				database.errors = []error{&pgconn.PgError{Code: "42883"}, nil, nil}
			}
			repository, err := NewPostgresCorrelationPipelineRepository(database)
			if err != nil {
				t.Fatal(err)
			}
			leases, err := repository.ClaimStages(context.Background(), "correlation-reader", "correlation-lease-token", 30, 2)
			want := 2
			claimSQL := "SELECT zasp_runtime_claim_correlation_v2($1,$2,$3,$4)"
			if legacy {
				want = 3
				claimSQL = productionPipelineClaimStageSQL
			}
			if err != nil || len(leases) != 0 || database.calls != want || database.statements[0] != productionCorrelationRoutingReadySQL || database.statements[want-1] != claimSQL {
				t.Fatal("claim capability not pinned", database.statements, err)
			}
			if !reflect.DeepEqual(database.arguments[0], []any{migrations.ProductionRuntimeCorrelationRouting().Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint(), string(ProductionPipelineAuthorityCorrelation)}) {
				t.Fatal("routing release not compiled-pin bound", database.arguments)
			}
			if legacy && (database.statements[1] != productionCandidateReadyV48SQL || !reflect.DeepEqual(database.arguments[1], []any{migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint(), migrations.ProductionRuntimeCandidateAuthority().Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint(), string(ProductionPipelineAuthorityCorrelation)})) {
				t.Fatal("fallback did not independently pin healthy48")
			}
		})
	}
}

func TestCorrelationRoutingReadinessAndPollingFailClosed(t *testing.T) {
	for _, operation := range []string{"ready", "claim"} {
		for _, scenario := range []struct {
			name, body string
			err        error
		}{
			{"false", `{"ready":false}`, nil}, {"extra", `{"ready":true,"extra":true}`, nil}, {"alias", `{"Ready":true}`, nil}, {"duplicate", `{"ready":false,"ready":true}`, nil}, {"null", `{"ready":null}`, nil}, {"denied", "", &pgconn.PgError{Code: "42501"}}, {"provider", "", errors.New("private provider detail")},
		} {
			t.Run(operation+"/"+scenario.name, func(t *testing.T) {
				database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(scenario.body), json.RawMessage(`{"ready":true}`), json.RawMessage(`[]`)}, errors: []error{scenario.err, nil, nil}}
				repository, _ := NewPostgresCorrelationPipelineRepository(database)
				var err error
				if operation == "ready" {
					err = repository.Ready(context.Background())
				} else {
					_, err = repository.ClaimStages(context.Background(), "correlation-reader", "correlation-lease-token", 30, 1)
				}
				if err != ErrProductionPipelineUnavailable || database.calls != 1 {
					t.Fatal("routing error fell back or exposed details", err, database.calls)
				}
			})
		}
	}
	for _, body := range []string{`{"ready":false}`, `{"ready":true,"extra":true}`, `null`} {
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{nil, json.RawMessage(body), json.RawMessage(`[]`)}, errors: []error{&pgconn.PgError{Code: "42883"}, nil, nil}}
		repository, _ := NewPostgresCorrelationPipelineRepository(database)
		if _, err := repository.ClaimStages(context.Background(), "correlation-reader", "correlation-lease-token", 30, 1); err != ErrProductionPipelineUnavailable || database.calls != 2 {
			t.Fatal("unhealthy48 fallback claimed work", err, database.calls)
		}
	}
	// An absent upgraded claim function after successful49 readiness is drift,
	// not permission to downgrade to an unversioned legacy claim.
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), nil, json.RawMessage(`[]`)}, errors: []error{nil, &pgconn.PgError{Code: "42883"}, nil}}
	repository, _ := NewPostgresCorrelationPipelineRepository(database)
	if _, err := repository.ClaimStages(context.Background(), "correlation-reader", "correlation-lease-token", 30, 1); err != ErrProductionPipelineUnavailable || database.calls != 2 {
		t.Fatal("missing49 claim silently downgraded", err, database.calls)
	}
}

func TestCorrelationRoutingRejectsUnsupportedClaimedVersions(t *testing.T) {
	scope := fixtureScope(t, 130)
	batch := fixtureID(t, 133)
	for _, legacy := range []bool{false, true} {
		for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3"} {
			t.Run(map[bool]string{true: "schema48/", false: "schema49/"}[legacy]+version, func(t *testing.T) {
				body, _ := json.Marshal([]map[string]any{{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "batch_id": batch.String(), "generation": 4, "stage": "correlate", "attempt": 2, "implementation_version": version, "predecessor_digest": strings.Repeat("a", 64), "input_digest": strings.Repeat("b", 64), "input_reference": "s3://zasp-runtime/results/index.json", "input_version_id": "version-3", "lease_expires_at": "2030-08-20T12:00:30Z"}})
				database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), body}}
				if legacy {
					database.responses = append([]json.RawMessage{nil}, database.responses...)
					database.errors = []error{&pgconn.PgError{Code: "42883"}, nil, nil}
				}
				repository, _ := NewPostgresCorrelationPipelineRepository(database)
				leases, err := repository.ClaimStages(context.Background(), "correlation-reader", "correlation-lease-token", 30, 1)
				valid := version == "runtime-correlation-v1" || !legacy && version == "runtime-correlation-v2"
				if (err == nil) != valid || valid && len(leases) != 1 || !valid && leases != nil {
					t.Fatal("unexpected version crossed capability boundary", version, legacy, leases, err)
				}
			})
		}
	}
}
