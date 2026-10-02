package redteamadapter

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/legacytests"
	"testing"
)

func TestLegacyJournalRouterClosedSelection(t *testing.T) {
	const single = `SELECT zasp_temporal71.op06($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	const retained = `SELECT zasp_sa_multistep_prior.test_invocation_start($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	for _, protocol := range []string{"legacy_single_test", "retained_ordered", "unknown", "malformed", "denied"} {
		t.Run(protocol, func(t *testing.T) {
			request := journalRequestFixture(t)
			raw := json.RawMessage(`{"protocol":"` + protocol + `"}`)
			if protocol == "malformed" {
				raw = json.RawMessage(`{"protocol":"legacy_single_test","extra":true}`)
			}
			db := &jsonDatabaseStub{responses: map[string]json.RawMessage{legacytests.ReadySQL: json.RawMessage(`true`), `SELECT to_jsonb(zasp_sa_multistep_prior.test_adapter_ready($1,$2))`: json.RawMessage(`true`), `SELECT to_jsonb(zasp_red_team_principal_ready($1))`: json.RawMessage(`true`), legacyJournalProtocolSQL: raw, single: journalReceiptFixture(request, false), retained: journalReceiptFixture(request, false)}}
			router, err := NewLegacyJournalRouter(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if protocol == "denied" {
				db.responses[legacyJournalProtocolSQL] = json.RawMessage(`{"protocol":"legacy_single_test"}`)
				db.responses[single] = json.RawMessage(`{}`)
			}
			db.statements = nil
			_, err = router.Start(context.Background(), request)
			if protocol == "legacy_single_test" || protocol == "retained_ordered" {
				if err != nil {
					t.Fatal(err)
				}
				expected := single
				if protocol == "retained_ordered" {
					expected = retained
				}
				if len(db.statements) != 2 || db.statements[1] != expected {
					t.Fatal("wrong authority selection", db.statements)
				}
			} else {
				if err == nil {
					t.Fatal("invalid classification or selected refusal accepted")
				}
				for _, q := range db.statements {
					if q == retained {
						t.Fatal("refusal fell back")
					}
				}
			}
		})
	}
}
