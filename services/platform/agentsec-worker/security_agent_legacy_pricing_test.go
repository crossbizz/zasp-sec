package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// These cases fail if a cached ceiling permits a changed prepared request or
// revoked current SQL approval to send, or if dispatch can send twice.
func TestInstalledLegacyPricingBindsCurrentPreparedRequest(t *testing.T) {
	for _, mode := range []string{"exact", "scope", "missing", "ambiguous", "unknown", "lookup_error", "body", "credential", "credential_wait", "policy", "config", "revoked", "expired", "cancelled", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			transport := bindingResponseTransport()
			planner := requestBindingPlanner(t, transport)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			value := testSecurityAgentPlannerContext()
			base, err := planner.Prepare(ctx, value)
			if err != nil {
				t.Fatal(err)
			}
			p := base.(*productionSecurityAgentPreparedPlan)
			fixture := &securityAgentOrderedPreparedPlan{planner: planner, body: p.body, identity: securityAgentOrderedRequestIdentity{BodyDigest: p.identity.BodyDigest, Model: p.identity.Model, Endpoint: p.identity.Endpoint, PolicyVersion: p.identity.PolicyVersion, MaximumTokens: p.identity.MaximumTokens}, contextValue: securityAgentOrderedPlannerContext{OrganizationID: value.OrganizationID, WorkspaceID: value.WorkspaceID, EnvironmentID: value.EnvironmentID}}
			binding, response := orderedPricingWorkerFixture(t, fixture)
			db := &pricingBoundDatabase{response: response}
			if mode == "scope" {
				binding.EnvironmentID = binding.WorkspaceID
			}
			if mode == "unknown" {
				db.response = json.RawMessage(`{}`)
			}
			failureDB := &legacyPricingFailureDB{pricingBoundDatabase: db, failed: mode == "lookup_error"}
			priced := &installedLegacyPricedPlanner{planner: planner, database: failureDB, bindings: []securityAgentMultistepPricingBinding{binding}}
			if mode == "missing" {
				priced.bindings = nil
			}
			if mode == "ambiguous" {
				priced.bindings = append(priced.bindings, binding)
			}
			prepared, err := priced.Prepare(ctx, value)
			if err != nil {
				t.Fatal(err)
			}
			bound := prepared.PlannerBudget()
			if mode == "scope" || mode == "unknown" || mode == "missing" || mode == "ambiguous" || mode == "lookup_error" {
				if bound.MaximumCostNanoCredits != 0 {
					t.Fatal("unknown approval acquired ceiling")
				}
				if prepared.Dispatch(ctx).Failure == "" || transport.calls != 0 {
					t.Fatal("pricing sent")
				}
				return
			}
			if bound.MaximumTokens != 1000 || bound.MaximumCostNanoCredits != 2000000 {
				t.Fatal("approved bound lost", bound)
			}
			switch mode {
			case "body":
				prepared.(*installedLegacyPricedPlan).prepared.body += " "
			case "credential":
				planner.mu.Lock()
				planner.token = []byte("sk-or-v1-rotated-test-credential")
				planner.mu.Unlock()
			case "credential_wait":
				db.mutate = func() {
					planner.mu.Lock()
					planner.token = []byte("sk-or-v1-rotated-test-credential")
					planner.mu.Unlock()
				}
			case "config":
				planner.mu.Lock()
				planner.maximumTokens++
				planner.mu.Unlock()
			case "policy":
				var v map[string]any
				json.Unmarshal(response, &v)
				v["policy_version"] = 2
				db.response, _ = json.Marshal(v)
			case "revoked":
				db.response = json.RawMessage(`{}`)
			case "expired":
				var v map[string]any
				json.Unmarshal(response, &v)
				v["policy"].(map[string]any)["expires_at"] = "2020-01-01T00:00:00.000000Z"
				db.response, _ = json.Marshal(v)
			case "cancelled":
				cancel()
			}
			got := prepared.Dispatch(ctx)
			if mode == "exact" || mode == "duplicate" {
				if got.Failure != "" || transport.calls != 1 {
					t.Fatal("exact production send failed", got.Failure, transport.calls)
				}
				if mode == "duplicate" {
					again := prepared.Dispatch(ctx)
					if again.Failure == "" || transport.calls != 1 {
						t.Fatal("duplicate send")
					}
				}
			} else if got.Failure == "" || transport.calls != 0 {
				t.Fatal("changed approval sent", mode, transport.calls)
			}
			for _, q := range db.queries {
				if !strings.Contains(q, "pricing_ready") && !strings.Contains(q, "pricing_lookup") {
					t.Fatal("new pricing authority", q)
				}
			}
		})
	}
}

type legacyPricingFailureDB struct {
	*pricingBoundDatabase
	failed bool
}

func (d *legacyPricingFailureDB) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if d.failed {
		return nil, errors.New("controlled lookup unavailable")
	}
	return d.pricingBoundDatabase.QueryJSON(ctx, q, args...)
}
