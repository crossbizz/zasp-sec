package main

import (
	"context"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type attackLabCompositionDatabase struct {
	auditExportRuntimeDatabase
	installed bool
	err       error
}

func (db *attackLabCompositionDatabase) SecurityAgentAttackLabAvailable(context.Context) (bool, error) {
	return db.installed, db.err
}

func TestAttackLabProductionDecoratorPreservesAdmission(t *testing.T) {
	db := &attackLabCompositionDatabase{installed: true}
	traced := &tracedJSONDatabase{next: db}
	capability, ok := any(traced).(interface {
		SecurityAgentAttackLabAvailable(context.Context) (bool, error)
	})
	if !ok {
		t.Fatal("production database decorator drops migration57 admission authority")
	}
	for _, installed := range []bool{false, true, false} {
		db.installed = installed
		if got, err := capability.SecurityAgentAttackLabAvailable(context.Background()); err != nil || got != installed {
			t.Fatalf("admission=%v error=%v installed=%v", got, err, installed)
		}
	}
	db.err = apiserver.ErrRepositoryUnavailable
	if got, err := capability.SecurityAgentAttackLabAvailable(context.Background()); got || err == nil {
		t.Fatal("corrupt57 did not fail closed")
	}
}

func TestAttackLabProductionDecoratorDefaultsCatalogOff(t *testing.T) {
	db := &attackLabCompositionDatabase{installed: true}
	traced := &tracedJSONDatabase{next: db}
	capability, ok := any(traced).(interface {
		SecurityAgentAttackLabWorkflowAvailable(context.Context) (bool, error)
	})
	if !ok {
		t.Fatal("production database decorator has no connected catalog gate")
	}
	if got, err := capability.SecurityAgentAttackLabWorkflowAvailable(context.Background()); got || err != nil {
		t.Fatalf("default catalog gate=%v error=%v", got, err)
	}
	db.err = apiserver.ErrRepositoryUnavailable
	if got, err := capability.SecurityAgentAttackLabWorkflowAvailable(context.Background()); got || err == nil {
		t.Fatal("unconfigured catalog masked corrupt57")
	}
}
