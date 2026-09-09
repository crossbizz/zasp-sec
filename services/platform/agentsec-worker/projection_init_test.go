package main

import (
	"context"
	"slices"
	"testing"
)

type searchSchemaInitStub struct {
	name  string
	steps *[]string
	fail  string
}

func (index *searchSchemaInitStub) InitializeSchema(context.Context) error {
	*index.steps = append(*index.steps, index.name+"-init")
	if index.fail == "init" {
		return errRuntimeUnavailable
	}
	return nil
}
func (index *searchSchemaInitStub) Ready(context.Context) error {
	*index.steps = append(*index.steps, index.name+"-ready")
	if index.fail == "ready" {
		return errRuntimeUnavailable
	}
	return nil
}
func TestProductionSearchInitIncludesAllThreeFixedSchemas(t *testing.T) {
	var steps []string
	inventory := &searchSchemaInitStub{name: "inventory", steps: &steps}
	raw := &searchSchemaInitStub{name: "raw", steps: &steps}
	sessions := &searchSchemaInitStub{name: "sessions", steps: &steps}
	if err := initializeProductionSearchSchemas(context.Background(), inventory, raw, sessions); err != nil || !slices.Equal(steps, []string{"inventory-init", "inventory-ready", "raw-init", "raw-ready", "sessions-init", "sessions-ready"}) {
		t.Fatalf("incomplete bootstrap: %v err=%v", steps, err)
	}
	for _, failure := range []string{"init", "ready"} {
		steps = nil
		raw.fail = failure
		if initializeProductionSearchSchemas(context.Background(), inventory, raw, sessions) == nil || slices.Contains(steps, "sessions-init") {
			t.Fatal("bootstrap ignored failed raw schema")
		}
	}
	if initializeProductionSearchSchemas(context.Background(), inventory, nil, sessions) == nil {
		t.Fatal("missing schema authority accepted")
	}
}
