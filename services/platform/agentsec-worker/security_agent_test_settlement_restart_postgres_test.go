package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
)

// Fail only after the real database driver has received a successful committed
// settlement. Production client code never receives the acknowledgement.
type settlementExitAfterCommitQuery struct{ existingTestQuery }

func (q settlementExitAfterCommitQuery) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	raw, err := q.existingTestQuery.QueryJSON(ctx, query, args...)
	if err == nil && strings.HasPrefix(query, "SELECT zasp_production_security_agent_existing_tests_reconcile_settle(") {
		os.Exit(24)
	}
	return raw, err
}
