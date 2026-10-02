package apiserver

import (
	"context"
	"errors"
	"testing"
)

type auditRunContextDatabase struct {
	*discoveryCallDatabase
	releaseErr error
}

func (d *auditRunContextDatabase) SecurityAgentRunContextAvailable(context.Context) (bool, error) {
	return true, d.releaseErr
}

// A warmed audit adapter must recheck application-pinned54 trust before SQL
// readiness can accept coherently rewritten database metadata.
func TestAuditExportRunContextTrustChanges(t *testing.T) {
	repository, base, _, _ := auditExportRepositoryFixture(t)
	database := &auditRunContextDatabase{discoveryCallDatabase: base}
	repository.database = database
	if err := repository.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(base.queries)
	database.releaseErr = errors.New("untrusted54")
	if err := repository.Ready(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("untrusted54 readiness accepted: %v", err)
	}
	if len(base.queries) != before {
		t.Fatal("untrusted54 reached legacy SQL readiness")
	}
}
