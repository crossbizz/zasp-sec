package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type existingTestCapabilityDatabase struct {
	boundaryDatabase
	available bool
	err       error
	seen      context.Context
}

func (db *existingTestCapabilityDatabase) SecurityAgentExistingTestDefinitionsAvailable(ctx context.Context) (bool, error) {
	db.seen = ctx
	return db.available, db.err
}

func TestTracedDatabasePreservesExistingTestDraftAuthority(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		next := &existingTestCapabilityDatabase{available: true}
		var inner apiserver.JSONDatabase = next
		if legacy {
			inner = boundaryDatabase{}
		}
		db := &tracedJSONDatabase{next: inner}
		capability, ok := any(db).(interface {
			SecurityAgentExistingTestDefinitionsAvailable(context.Context) (bool, error)
		})
		if !ok {
			t.Fatal("production tracing erased existing-test draft authority")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		available, err := capability.SecurityAgentExistingTestDefinitionsAvailable(ctx)
		if available == legacy || err != nil || !legacy && next.seen != ctx {
			t.Fatalf("forwarded capability=%v error=%v context-preserved=%v", available, err, next.seen == ctx)
		}
		if !legacy {
			next.available = false
			next.err = apiserver.ErrRepositoryUnavailable
			if available, err := capability.SecurityAgentExistingTestDefinitionsAvailable(ctx); available || !errors.Is(err, apiserver.ErrRepositoryUnavailable) {
				t.Fatalf("warm decorator cached healthy55: %v %v", available, err)
			}
		}
		cancel()
		if available, err := capability.SecurityAgentExistingTestDefinitionsAvailable(ctx); available || err == nil {
			t.Fatal("canceled draft authority accepted")
		}
	}
}
