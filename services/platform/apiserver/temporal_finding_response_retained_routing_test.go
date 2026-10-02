package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type findingRetainedRouteDB struct {
	JSONDatabase
	present string
	fail    bool
	calls   []string
}

func (d *findingRetainedRouteDB) QueryJSON(_ context.Context, q string, _ ...any) (json.RawMessage, error) {
	d.calls = append(d.calls, q)
	if strings.Contains(q, "to_regnamespace") {
		return json.RawMessage(d.present), nil
	}
	if d.fail {
		return nil, ErrRepositoryUnavailable
	}
	return json.RawMessage(`{"created":0}`), nil
}
func TestTemporalFindingResponseRetainedRouting(t *testing.T) {
	for _, tc := range []struct {
		name, present, target string
		fail                  bool
		count                 int
	}{
		{"absent preserves retained70", "false", "zasp_temporal70.op02", false, 2},
		{"present uses78", "true", "zasp_temporal78.retained_schedule", false, 2},
		{"invalid present never falls back", "true", "zasp_temporal78.retained_schedule", true, 2},
		{"malformed presence refuses", "null", "", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &findingRetainedRouteDB{present: tc.present, fail: tc.fail}
			compat := securityAgentCompatibilityDatabase{JSONDatabase: d}
			_, err := compat.QueryJSON(context.Background(), "SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)", "worker", 5, "checksum", "fingerprint")
			if (err != nil) != tc.fail || len(d.calls) != tc.count || tc.target != "" && !strings.Contains(d.calls[len(d.calls)-1], tc.target) {
				t.Fatalf("routing failure=%t calls=%v", err != nil, d.calls)
			}
			if tc.fail && !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatal("wrong unavailable classification")
			}
		})
	}
}
