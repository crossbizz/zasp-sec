package runtimeevent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionCandidateReadinessRequiresExactAuthority(t *testing.T) {
	for _, scenario := range []struct {
		name  string
		body  string
		err   error
		ready bool
	}{
		{"ready", `{"ready":true}`, nil, true},
		{"schema drift", `{"ready":false}`, nil, false},
		{"permission denied", "", &pgconn.PgError{Code: "42501", Message: "private provider detail"}, false},
		{"provider failure", "", errors.New("private provider detail"), false},
		{"unknown field", `{"ready":true,"other":true}`, nil, false},
		{"case alias", `{"Ready":true}`, nil, false},
		{"duplicate", `{"ready":false,"ready":true}`, nil, false},
		{"null", `{"ready":null}`, nil, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(scenario.body)}, errors: []error{scenario.err}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			err := repository.ReadyCandidates(context.Background())
			if (err == nil) != scenario.ready || err != nil && err != ErrProductionPipelineUnavailable {
				t.Fatal("candidate readiness failed closed-response contract", err)
			}
			metadata := migrations.ProductionRuntimeCandidateAuthority()
			if database.calls != 1 || database.statements[0] != productionCandidateReadyV48SQL || !reflect.DeepEqual(database.arguments[0], []any{migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint(), metadata.Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint(), string(ProductionPipelineAuthorityCorrelation)}) {
				t.Fatal("candidate readiness lost exact schema/principal binding or fell back")
			}
		})
	}
	for _, authority := range []ProductionPipelineAuthority{ProductionPipelineAuthorityIndex, ProductionPipelineAuthorityCoordinator} {
		database := &productionIngestDatabaseStub{}
		repository, _ := NewPostgresProductionPipelineRepository(database, authority)
		if repository.ReadyCandidates(context.Background()) != ErrProductionPipelineUnavailable || database.calls != 0 {
			t.Fatal("wrong authority queried candidate readiness")
		}
	}
}

func TestProductionCandidateReadinessOnlyFallsBackToExactPredecessor(t *testing.T) {
	for _, predecessor := range []struct {
		body  string
		err   error
		ready bool
	}{
		{`{"ready":true}`, nil, true},
		{`{"ready":false}`, nil, false},
		{"", &pgconn.PgError{Code: "42883"}, false},
		{`{"ready":true,"other":true}`, nil, false},
	} {
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{nil, json.RawMessage(predecessor.body)}, errors: []error{&pgconn.PgError{Code: "42883"}, predecessor.err}}
		repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
		err := repository.ReadyCandidates(context.Background())
		if (err == nil) != predecessor.ready || database.calls != 2 || database.statements[0] != productionCandidateReadyV48SQL || database.statements[1] != productionCandidateReadySQL {
			t.Fatal("candidate readiness lost exact predecessor fallback", err)
		}
		if !reflect.DeepEqual(database.arguments[1], []any{migrations.ProductionRuntimeCandidateAuthority().Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint(), string(ProductionPipelineAuthorityCorrelation)}) {
			t.Fatal("predecessor fallback did not pin schema47")
		}
	}
}

func TestProductionCandidateReadinessRejectsCanceledAndInvalidRepository(t *testing.T) {
	for _, scenario := range []string{"nil context", "canceled before query", "canceled response", "provider panic", "nil repository", "wrong stage"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			database := candidateDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
				calls++
				if scenario == "provider panic" {
					panic("private provider detail")
				}
				if scenario == "canceled response" {
					cancel()
				}
				return json.RawMessage(`{"ready":true}`), nil
			})
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			switch scenario {
			case "nil context":
				ctx = nil
			case "canceled before query":
				cancel()
			case "nil repository":
				repository = nil
			case "wrong stage":
				repository.stage = RuntimeStageIndex
			}
			if repository.ReadyCandidates(ctx) != ErrProductionPipelineUnavailable {
				t.Fatal("invalid readiness accepted")
			}
			wantCalls := 0
			if scenario == "canceled response" || scenario == "provider panic" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatal("invalid readiness reached database")
			}
		})
	}
}
