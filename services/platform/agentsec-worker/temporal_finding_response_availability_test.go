package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestFindingResponseRuntimeAvailability(t *testing.T) {
	for _, mode := range []string{"absent", "ready", "invalid", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			db := singleDeliveryDatabaseFunc(func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				calls++
				switch sql {
				case `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`:
					if mode == "absent" {
						return json.RawMessage(`false`), nil
					}
					return json.RawMessage(`true`), nil
				case `SELECT to_jsonb(zasp_temporal78.client_ready($1,$2))`:
					if len(args) != 2 || args[0] != migrations.TemporalFindingResponseChecksum() || args[1] != migrations.TemporalFindingResponseFingerprint() {
						t.Fatal("unbound finding readiness")
					}
					if mode == "invalid" {
						return json.RawMessage(`false`), nil
					}
					if mode == "malformed" {
						return json.RawMessage(`null`), nil
					}
					return json.RawMessage(`true`), nil
				default:
					t.Fatal("unrelated family fallback", sql)
					return nil, nil
				}
			})
			available, err := findingResponseRuntimeAvailable(context.Background(), db)
			if available != (mode == "ready") || (err != nil) != (mode == "invalid" || mode == "malformed") || mode == "absent" && calls != 1 {
				t.Fatal("finding readiness", available, err, calls)
			}
		})
	}
}
