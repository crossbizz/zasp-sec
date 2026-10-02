package redteamadapter

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func TestRelease61JournalComposition(t *testing.T) {
	for _, mode := range []string{"ready", "drift", "principal", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			db := &jsonDatabaseStub{responses: map[string]json.RawMessage{`SELECT to_jsonb(zasp_sa_multistep_prior.test_adapter_ready($1,$2))`: json.RawMessage(`true`), `SELECT to_jsonb(zasp_red_team_principal_ready($1))`: json.RawMessage(`true`)}}
			if mode == "drift" {
				db.responses[`SELECT to_jsonb(zasp_sa_multistep_prior.test_adapter_ready($1,$2))`] = json.RawMessage(`false`)
			}
			if mode == "principal" {
				db.responses[`SELECT to_jsonb(zasp_red_team_principal_ready($1))`] = json.RawMessage(`false`)
			}
			base, _ := NewPostgresInvocationJournal(db, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
			entry, ok := any(base).(interface {
				Release61(context.Context) (*PostgresInvocationJournal, error)
			})
			if !ok {
				t.Fatal("explicit dormant release61 journal composition absent")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			journal, err := entry.Release61(ctx)
			if mode == "ready" {
				if err != nil || journal == nil {
					t.Fatal("exact composition rejected", err)
				}
			} else if err == nil || journal != nil {
				t.Fatal("unready journal exposed")
			}
			if mode == "cancelled" && len(db.statements) != 0 {
				t.Fatal("cancelled context reached database")
			}
		})
	}
}
