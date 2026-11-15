package demodata

import (
	"context"
	"encoding/json"
	"testing"
)

// The demo shows who created an agent in every way a collector can know it,
// and the people of the identity provider carry the email address and
// department the team suggestion is matched on. Every creator that is an
// address is one of those people or another example.com address.
func TestDatasetShowsCreatorsAndThePeopleTheyAreMatchedTo(t *testing.T) {
	integrations, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	type attributed struct{ by, at, source, team string }
	agents := map[string]attributed{}
	people := map[string]string{}
	sources := map[string]int{}
	for _, integration := range integrations {
		snapshot, err := Collect(context.Background(), integration, testTarget(t, integration.Key))
		if err != nil {
			t.Fatalf("%s: %v", integration.Key, err)
		}
		var entities []struct {
			Kind        string `json:"kind"`
			DisplayName string `json:"display_name"`
			ProductKind string `json:"product_kind"`
			Attributes  struct {
				CreatedBy       string `json:"created_by"`
				CreatedAt       string `json:"created_at"`
				CreatedBySource string `json:"created_by_source"`
				OwningTeam      string `json:"owning_team"`
				Email           string `json:"email"`
				Department      string `json:"department"`
			} `json:"attributes"`
		}
		if err := json.Unmarshal(snapshot.Entities, &entities); err != nil {
			t.Fatal(err)
		}
		for _, entity := range entities {
			if entity.Kind == "okta_user" && entity.Attributes.Email != "" {
				people[entity.Attributes.Email] = entity.Attributes.Department
			}
			if entity.Attributes.CreatedBy == "" && entity.Attributes.OwningTeam == "" {
				continue
			}
			if entity.ProductKind != "agent" {
				t.Fatalf("%s %q is attributed and is not an agent", entity.Kind, entity.DisplayName)
			}
			agents[entity.DisplayName] = attributed{entity.Attributes.CreatedBy, entity.Attributes.CreatedAt, entity.Attributes.CreatedBySource, entity.Attributes.OwningTeam}
			sources[entity.Attributes.CreatedBySource]++
		}
	}
	for _, source := range []string{"cloudtrail", "provider_record", "annotation", "label", "codeowners"} {
		if sources[source] == 0 {
			t.Errorf("the demo has no creator from %s: %v", source, sources)
		}
	}
	if len(people) != 3 || people["priya.raman@example.com"] != "Platform Engineering" {
		t.Fatalf("people = %v", people)
	}
	for name, want := range map[string]attributed{
		// A federated session named after an address: the team comes from Okta.
		"warehouse-routing-planner": {"priya.raman@example.com", "2026-10-02T09:41:30Z", "cloudtrail", ""},
		// A pipeline role and an IAM user: a creator, and no person to match.
		"fleet-telemetry-analyst": {"ci-deployer/release-2291", "2026-10-27T11:02:09Z", "cloudtrail", ""},
		"invoice-summarizer":      {"legacy-deploy", "2026-11-03T08:15:00Z", "cloudtrail", ""},
		// An annotation names the owner and a label the team.
		"prod/checkout-assistant": {"marcus.oyelaran@example.com", "2026-06-11T08:30:00Z", "annotation", "checkout"},
		"prod/refund-approver":    {"payments-platform", "2026-07-02T13:45:00Z", "label", "payments"},
		// The record's own creator.
		"Customer service agent":               {"marcus.oyelaran@example.com", "2026-08-14T15:22:10Z", "provider_record", ""},
		"returns-chatbot":                      {"elena.sokolova@example.com", "2026-10-09T12:31:07Z", "provider_record", ""},
		"Incident triage agent":                {"priya.raman", "2026-07-21T09:12:44Z", "provider_record", ""},
		"northwind-robotics/warehouse-copilot": {"@northwind-robotics/warehouse-systems", "", "codeowners", ""},
	} {
		if agents[name] != want {
			t.Errorf("%s = %+v, want %+v", name, agents[name], want)
		}
	}
	// An agent whose provider says nothing has no creator: nothing is guessed.
	for _, name := range []string{"legacy-pricing-bot", "procurement-negotiator", "northwind-robotics/support-agent"} {
		if got, attributedAgent := agents[name]; attributedAgent {
			t.Errorf("%s is attributed without a provider claim: %+v", name, got)
		}
	}
}
