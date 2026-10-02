package migrations

import (
	"context"
	"errors"
	"testing"
)

func TestSecurityAgentPublicExtensionRunnerRejectsUnboundDatabase(t *testing.T) {
	for _, runner := range []*Runner{nil, {}} {
		if err := runner.UpProductionSecurityAgentPublic(context.Background()); !errors.Is(err, ErrInvalidRunner) {
			t.Fatal("unbound extension up", err)
		}
		if err := runner.DownProductionSecurityAgentPublic(context.Background()); !errors.Is(err, ErrInvalidRunner) {
			t.Fatal("unbound extension down", err)
		}
	}
}
