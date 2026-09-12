package runtimeevent

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSandboxSessionRoutingNegotiatesClosedVersions(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		authority, prefix, claim := ProductionPipelineAuthorityProjection, "runtime-projection-", "SELECT zasp_runtime_claim_projection_v2($1,$2,$3,$4)"
		if stage == "complete" {
			authority, prefix, claim = ProductionPipelineAuthorityCoordinator, "runtime-complete-", "SELECT zasp_runtime_claim_completion_v2($1,$2,$3,$4)"
		}
		for _, schema := range []int{49, 50} {
			for _, suffix := range []string{"v1", "v2", "v3"} {
				t.Run(stage+"/"+suffix+"/"+strconv.Itoa(schema), func(t *testing.T) {
					scope := fixtureScope(t, 130)
					body, _ := json.Marshal([]map[string]any{{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "batch_id": fixtureID(t, 133).String(), "generation": 4, "stage": stage, "attempt": 2, "implementation_version": prefix + suffix, "predecessor_digest": strings.Repeat("a", 64), "input_digest": strings.Repeat("b", 64), "input_reference": "s3://zasp-runtime/results/prior.json", "input_version_id": "version-3", "lease_expires_at": "2030-08-20T12:00:30Z"}})
					database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), body}}
					wantClaim := claim
					if schema == 49 {
						database.responses = append([]json.RawMessage{nil}, database.responses...)
						database.errors = []error{&pgconn.PgError{Code: "42883"}, nil, nil}
						wantClaim = productionSandboxRoutingReadySQL
					}
					repository, err := NewPostgresSandboxSessionPipelineRepository(database, authority)
					if err != nil {
						t.Fatal(err)
					}
					leases, err := repository.ClaimStages(context.Background(), "session-worker", "session-worker-lease", 60, 1)
					valid := schema == 50 && (suffix == "v1" || suffix == "v2")
					if (err == nil) != valid || valid && len(leases) != 1 || !valid && leases != nil {
						t.Fatal("lease crossed negotiated session version", schema, suffix, leases, err)
					}
					if database.statements[0] != productionSandboxRoutingReadySQL || database.statements[len(database.statements)-1] != wantClaim {
						t.Fatal("wrong session claim routing", database.statements)
					}
					if database.arguments[0][0] != migrations.ProductionRuntimeSandboxBinding().Checksum() || database.arguments[0][1] != migrations.ProductionRuntimeSandboxBindingSemanticFingerprint() || database.arguments[0][2] != string(authority) {
						t.Fatal("50 authority not pinned", database.arguments[0])
					}
					if schema == 49 && database.calls != 1 {
						t.Fatal("v2 worker attempted unsupported49 fallback")
					}
				})
			}
		}
	}
}

func TestSandboxSessionRoutingRejectsInvalidAuthority(t *testing.T) {
	for _, authority := range []ProductionPipelineAuthority{ProductionPipelineAuthorityArchive, ProductionPipelineAuthorityIndex, ProductionPipelineAuthorityCorrelation, ""} {
		if repository, err := NewPostgresSandboxSessionPipelineRepository(&productionIngestDatabaseStub{}, authority); err != ErrProductionPipeline || repository != nil {
			t.Fatal("invalid session authority admitted", authority)
		}
	}
	if repository, err := NewPostgresSandboxSessionPipelineRepository(nil, ProductionPipelineAuthorityProjection); err != ErrProductionPipeline || repository != nil {
		t.Fatal("nil database admitted")
	}
}

func TestSandboxSessionRoutingNeverDowngradesFailure(t *testing.T) {
	for _, authority := range []ProductionPipelineAuthority{ProductionPipelineAuthorityProjection, ProductionPipelineAuthorityCoordinator} {
		for _, body := range []string{`{"ready":false}`, `{"Ready":true}`, `{"ready":true,"extra":true}`, `{"ready":true,"ready":false}`, `null`, `{"ready":null}`} {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(body), json.RawMessage(`{"ready":true}`), json.RawMessage(`[]`)}}
			repository, _ := NewPostgresSandboxSessionPipelineRepository(database, authority)
			if err := repository.Ready(context.Background()); err != ErrProductionPipelineUnavailable || database.calls != 1 {
				t.Fatal("malformed readiness downgraded", body, err, database.calls)
			}
		}
		for _, code := range []string{"42501", "55000", "08006"} {
			database := &productionIngestDatabaseStub{errors: []error{&pgconn.PgError{Code: code}}, responses: []json.RawMessage{nil, json.RawMessage(`{"ready":true}`)}}
			repository, _ := NewPostgresSandboxSessionPipelineRepository(database, authority)
			if _, err := repository.ClaimStages(context.Background(), "session-worker", "session-worker-lease", 60, 1); err != ErrProductionPipelineUnavailable || database.calls != 1 {
				t.Fatal("failed readiness downgraded", code, err, database.calls)
			}
		}
		for _, code := range []string{"42883", "42501", "55000"} {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), nil, json.RawMessage(`[]`)}, errors: []error{nil, &pgconn.PgError{Code: code}, nil}}
			repository, _ := NewPostgresSandboxSessionPipelineRepository(database, authority)
			if _, err := repository.ClaimStages(context.Background(), "session-worker", "session-worker-lease", 60, 1); err != ErrProductionPipelineUnavailable || database.calls != 2 {
				t.Fatal("failed claim downgraded", code, err, database.calls)
			}
		}
		database := &productionIngestDatabaseStub{errors: []error{&pgconn.PgError{Code: "42883"}, &pgconn.PgError{Code: "42883"}}, responses: []json.RawMessage{nil, nil, json.RawMessage(`{"ready":true}`)}}
		repository, _ := NewPostgresSandboxSessionPipelineRepository(database, authority)
		if err := repository.Ready(context.Background()); err != ErrProductionPipelineUnavailable || database.calls != 1 {
			t.Fatal("fell back beyond49", err, database.calls)
		}
	}
}
