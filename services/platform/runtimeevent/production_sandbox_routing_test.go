package runtimeevent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSandboxRoutingNeverDowngradesReadinessOrClaimFailures(t *testing.T) {
	for _, body := range []string{`{"ready":false}`, `{"Ready":true}`, `{"ready":true,"other":true}`, `{"ready":true,"ready":false}`, `{"ready":null}`, `null`} {
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(body), json.RawMessage(`{"ready":true}`), json.RawMessage(`[]`)}}
		repository, _ := NewPostgresSandboxCorrelationPipelineRepository(database)
		if _, err := repository.ClaimStages(context.Background(), "sandbox-reader", "sandbox-reader-token", 60, 1); err != ErrProductionPipelineUnavailable || database.calls != 1 {
			t.Fatal("malformed50 readiness fell back", body, err, database.calls)
		}
	}
	for _, failure := range []error{&pgconn.PgError{Code: "42501"}, errors.New("private provider failure")} {
		database := &productionIngestDatabaseStub{errors: []error{failure}, responses: []json.RawMessage{nil, json.RawMessage(`{"ready":true}`)}}
		repository, _ := NewPostgresSandboxCorrelationPipelineRepository(database)
		if err := repository.Ready(context.Background()); err != ErrProductionPipelineUnavailable || database.calls != 1 {
			t.Fatal("50 readiness error fell back", err)
		}
	}
	for _, failure := range []error{&pgconn.PgError{Code: "42883"}, &pgconn.PgError{Code: "42501"}, errors.New("private claim failure")} {
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), nil, json.RawMessage(`[]`)}, errors: []error{nil, failure, nil}}
		repository, _ := NewPostgresSandboxCorrelationPipelineRepository(database)
		if _, err := repository.ClaimStages(context.Background(), "sandbox-reader", "sandbox-reader-token", 60, 1); err != ErrProductionPipelineUnavailable || database.calls != 2 {
			t.Fatal("50 claim failure downgraded", err, database.calls)
		}
	}
}

func TestSandboxRoutingRejectsClaimsBeyondNegotiatedVersion(t *testing.T) {
	scope := fixtureScope(t, 130)
	for _, schema := range []int{49, 50} {
		for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3", "runtime-correlation-v4"} {
			body, _ := json.Marshal([]map[string]any{{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "batch_id": fixtureID(t, 133).String(), "generation": 4, "stage": "correlate", "attempt": 2, "implementation_version": version, "predecessor_digest": strings.Repeat("a", 64), "input_digest": strings.Repeat("b", 64), "input_reference": "s3://zasp-runtime/results/index.json", "input_version_id": "version-3", "lease_expires_at": "2030-08-20T12:00:30Z"}})
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), body}}
			if schema == 49 {
				database.responses = append([]json.RawMessage{nil}, database.responses...)
				database.errors = []error{&pgconn.PgError{Code: "42883"}, nil, nil}
			}
			repository, _ := NewPostgresSandboxCorrelationPipelineRepository(database)
			leases, err := repository.ClaimStages(context.Background(), "sandbox-reader", "sandbox-reader-token", 60, 1)
			valid := version == "runtime-correlation-v1" || version == "runtime-correlation-v2" || schema == 50 && version == "runtime-correlation-v3"
			if (err == nil) != valid || valid && len(leases) != 1 || !valid && leases != nil {
				t.Fatal("lease crossed negotiated capability", schema, version, leases, err)
			}
		}
	}
}

func TestSandboxRoutingRequiresHealthy49WithoutOlderFallback(t *testing.T) {
	for _, scenario := range []struct {
		body string
		err  error
	}{
		{`{"ready":false}`, nil}, {`{"ready":true,"extra":true}`, nil}, {`null`, nil}, {"", &pgconn.PgError{Code: "42883"}}, {"", &pgconn.PgError{Code: "42501"}},
	} {
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{nil, json.RawMessage(scenario.body), json.RawMessage(`{"ready":true}`)}, errors: []error{&pgconn.PgError{Code: "42883"}, scenario.err, nil}}
		repository, _ := NewPostgresSandboxCorrelationPipelineRepository(database)
		if _, err := repository.ClaimStages(context.Background(), "sandbox-reader", "sandbox-reader-token", 60, 1); err != ErrProductionPipelineUnavailable || database.calls != 2 {
			t.Fatal("sandbox reader fell back beyond healthy49", err, database.calls)
		}
	}
}
