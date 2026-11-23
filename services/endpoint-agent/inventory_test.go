package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestLargeRootStaysPartialAndInvalidReportCannotRemoveInstallations(t *testing.T) {
	b := newFixture(t).b
	roots := []map[string]string{{"scope": "project", "root": ".agents/skills", "status": "complete"}}
	items := []map[string]string{}
	submit := func() error {
		raw, err := json.Marshal(map[string]any{"schema_version": "zaspctl.local.v1", "command": "inventory", "status": "complete", "coverage": map[string]any{"mode": "local_only", "roots": roots}, "items": items})
		if err != nil {
			t.Fatal(err)
		}
		return b.queueInventory(raw, "/work/one")
	}
	if err := submit(); err != nil {
		t.Fatal(err)
	}
	for i := range 129 {
		items = append(items, map[string]string{"scope": "project", "path": fmt.Sprintf(".agents/skills/install-%d", i)})
	}
	if err := submit(); err != nil {
		t.Fatal(err)
	}
	for _, queued := range b.store.state.Inventory {
		if len(queued) != 2 || !*queued[0].Complete || *queued[1].Complete || len(queued[1].Items) != 128 {
			t.Fatal("oversized root must preserve older complete snapshot")
		}
	}
	before := b.store.state.InventorySequence
	items = items[:1]
	items[0]["path"] = "../foreign"
	if err := submit(); err == nil || b.store.state.InventorySequence != before {
		t.Fatal("malformed path superseded prior roots")
	}
}
