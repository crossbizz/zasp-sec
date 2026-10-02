package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type automaticRiskRouteDatabase struct {
	workflowCallDatabase
	installed bool
	failure   error
	queries   []string
}

func (d *automaticRiskRouteDatabase) RiskAutomaticSourcesAvailable(context.Context) (bool, error) {
	return d.installed, d.failure
}
func (d *automaticRiskRouteDatabase) QueryJSON(_ context.Context, q string, _ ...any) (json.RawMessage, error) {
	d.queries = append(d.queries, q)
	return nil, ErrRepositoryNotFound
}

func TestTemporalAutomaticFindingRoute(t *testing.T) {
	for _, kind := range []string{"omitted", "installed", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			db := &automaticRiskRouteDatabase{installed: kind == "installed"}
			if kind == "invalid" {
				db.failure = ErrRepositoryUnavailable
			}
			repo := &PostgresRepository{database: db}
			mutation := RiskFindingMutation{Operation: "updateFinding", FindingID: riskFindingID, ExpectedVersion: 1, Status: "under_review", IdempotencyKey: "automatic-risk-route-0001", AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ReceiptID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
			_, err := repo.MutateRiskFinding(context.Background(), fixtureRequestIdentity(t), mutation)
			if kind == "invalid" {
				if err != ErrRepositoryUnavailable || len(db.queries) != 0 {
					t.Fatal("invalid release fell back", db.queries, err)
				}
				return
			}
			if err != ErrRepositoryNotFound || len(db.queries) != 1 {
				t.Fatal("route retried/downgraded after SQL error", db.queries, err)
			}
			if kind == "omitted" && db.queries[0] != postgresRiskFindingMutateSQL || kind == "installed" && !strings.HasPrefix(db.queries[0], "SELECT zasp_temporal77.risk_mutate(") {
				t.Fatal("wrong risk authority route", db.queries)
			}
		})
	}
}
