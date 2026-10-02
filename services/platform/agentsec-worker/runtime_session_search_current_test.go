package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type currentSearchRoutingDatabase struct {
	statements []string
	ready      bool
}

func (d *currentSearchRoutingDatabase) QueryJSON(_ context.Context, q string, a ...any) (json.RawMessage, error) {
	d.statements = append(d.statements, q)
	if strings.Contains(q, ".ready(") || strings.Contains(q, "readiness(") {
		if d.ready {
			return json.RawMessage(`true`), nil
		}
		return json.RawMessage(`false`), nil
	}
	return json.RawMessage(`null`), nil
}
func TestCurrentRuntimeSearchRoutesEveryMutation(t *testing.T) {
	for _, operation := range []string{"claim", "heartbeat", "finish"} {
		for _, ready := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/closed", true: "/ready"}[ready], func(t *testing.T) {
				db := &currentSearchRoutingDatabase{ready: ready}
				a, err := newCurrentPostgresRuntimeSessionSearchAuthority(db)
				if err != nil {
					t.Fatal(err)
				}
				lease, _, _ := sessionSearchWorkerFixture(t)
				lease.indexName = "zasp-runtime-sessions-v2"
				lease.projectionImplementationVersion = "runtime-projection-v3"
				switch operation {
				case "claim":
					_, _ = a.Claim(context.Background(), "search-worker", "search-worker-token", 30)
				case "heartbeat":
					_, _ = a.Heartbeat(context.Background(), lease, "search-worker", "search-worker-token", 30)
				case "finish":
					_ = a.Finish(context.Background(), lease, "search-worker", "search-worker-token", "indexed", lease.DocumentIDs, 0)
				}
				want := 1
				if ready {
					want = 2
				}
				if len(db.statements) != want {
					t.Fatal("wrong current search admission", db.statements)
				}
				for _, q := range db.statements {
					if !strings.Contains(q, "zasp_authorization80_runtime.") {
						t.Fatal("search escaped current profile", q)
					}
				}
			})
		}
	}
}
