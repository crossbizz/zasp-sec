package demodata

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func testTarget(t *testing.T, key string) Target {
	t.Helper()
	parse := func(text string) domain.ProductID {
		id, err := domain.ParseProductID(text)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	scope, err := domain.NewScope(parse("pid_d0000001-0000-4000-8000-000000000001"), parse("pid_d0000002-0000-4000-8000-000000000002"), parse("pid_d0000003-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Scope: scope, ObservedAt: time.Now().UTC().Truncate(time.Second)}
	target.IntegrationID = derivedID(target, "integration:"+key)
	return target
}

type testEntity struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	DisplayName    string          `json:"display_name"`
	ProductKind    string          `json:"product_kind"`
	Attributes     json.RawMessage `json:"attributes"`
}

// TestPrintCollection prints the entities the collector produces for one
// fixture (DEMO_PRINT=<key>, or "all"). It is the tool for editing the
// dataset: change a fixture, run it, read what the product would show.
func TestPrintCollection(t *testing.T) {
	only := os.Getenv("DEMO_PRINT")
	if only == "" {
		t.Skip("set DEMO_PRINT to a fixture key, or to all")
	}
	integrations, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, integration := range integrations {
		if integration.Key != only && only != "all" {
			continue
		}
		snapshot, err := Collect(context.Background(), integration, testTarget(t, integration.Key))
		if err != nil {
			t.Fatalf("%s: %v", integration.Key, err)
		}
		var entities []testEntity
		if err := json.Unmarshal(snapshot.Entities, &entities); err != nil {
			t.Fatal(err)
		}
		for _, entity := range entities {
			t.Logf("%-8s %-28s %-40s %s", entity.ProductKind, entity.Kind, entity.DisplayName, entity.Attributes)
		}
		t.Logf("%s: %d entities, unanswered %v", integration.Key, len(entities), snapshot.Unanswered)
	}
}
