package legacytests

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type captureDB struct {
	query string
	args  []any
}

func (d *captureDB) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	d.query = q
	d.args = args
	return json.RawMessage(`true`), nil
}

func TestClosedRoleSeparatedRouting(t *testing.T) {
	db := &captureDB{}
	adapter := Database{DB: db, Role: "zasp_red_team_adapter"}
	if _, err := adapter.QueryJSON(context.Background(), `SELECT zasp_production_security_agent_existing_tests_invocation_complete($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`); err != nil || db.query != `SELECT zasp_temporal71.op07($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)` {
		t.Fatal("exact public completion wrapper", db.query, err)
	}
	for _, q := range []string{`SELECT zasp_temporal71.body02($1)`, `SELECT zasp_production_security_agent_existing_tests_worker_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)`, `SELECT 1`} {
		if _, err := adapter.QueryJSON(context.Background(), q); err == nil {
			t.Fatal("ungranted statement accepted", q)
		}
	}
	if _, err := adapter.QueryJSON(context.Background(), Ready55SQL, "changed", migrations.SecurityAgentExistingTestsFingerprint()); err == nil {
		t.Fatal("changed prior identity accepted")
	}
	if _, err := adapter.QueryJSON(context.Background(), Ready55SQL, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()); err != nil || db.query != ReadySQL {
		t.Fatal("current readiness", err)
	}
	if got := db.args[2]; got != "zasp_red_team_adapter" {
		t.Fatal("role lost", got)
	}
}
