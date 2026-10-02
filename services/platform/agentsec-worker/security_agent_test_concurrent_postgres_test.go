package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Test-only boundary after the real claim commits. The parent observes both
// durable leases before permitting either composed runtime to release work.
type concurrentHeldClaimQuery struct{ existingTestQuery }

func (q concurrentHeldClaimQuery) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	raw, err := q.existingTestQuery.QueryJSON(ctx, query, args...)
	if err == nil && strings.HasPrefix(query, "SELECT zasp_production_security_agent_existing_tests_reconcile_claim(") {
		var claims []json.RawMessage
		if json.Unmarshal(raw, &claims) != nil || len(claims) != 1 {
			return nil, fmt.Errorf("concurrent fixture requires one actual claim")
		}
		fmt.Println("RECONCILE_CLAIM_HELD")
		line, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
		if readErr != nil || line != "continue\n" || ctx.Err() != nil {
			return nil, fmt.Errorf("concurrent claim barrier interrupted")
		}
	}
	return raw, err
}
