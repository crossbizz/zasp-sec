package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The configured periodic caller uses current sources and the same matcher and
// receipt identity. A draft visit and25 lower-severity sources consume nothing.
func TestTemporalAutomaticDefinitionCatchupPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `CREATE ROLE definition_catchup_executor LOGIN; CREATE ROLE definition_catchup_compensation LOGIN; SELECT zasp_temporal68.register_principals('definition_catchup_executor','definition_catchup_compensation'); SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":1,"enabled":true}')`); err != nil {
			t.Fatal(err)
		}
		c := owner.Config().Copy()
		c.User = "definition_catchup_executor"
		executor, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1; UPDATE zasp_risk_findings SET severity='low'`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		original := time.Now().UTC().Truncate(time.Second).Add(-48 * time.Hour)
		ids := make([]string, 26)
		for i := range ids {
			ids[i] = automaticSourceID(5000 + i)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,created_at,updated_at) SELECT $1,$2,$3,id,'posture','credential','Preactivation source',CASE WHEN id=$6 THEN 'high' ELSE 'low' END,'open',$5,$5 FROM unnest($4::text[]) id`, o, w, e, ids, original, ids[25]); err != nil {
			t.Fatal(err)
		}
		var base json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&base); err != nil {
			t.Fatal(err)
		}
		definition := automaticSourceID(5100)
		createAutomaticPageDefinition(t, ctx, api, o, w, e, actor, definition, base, 5101, true)
		ref := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": definition}
		type page struct {
			After    string `json:"after"`
			More     bool   `json:"more"`
			Retry    bool   `json:"retry"`
			Scanned  int    `json:"scanned"`
			Admitted int    `json:"admitted"`
		}
		call := func(after string) page {
			t.Helper()
			q, _ := json.Marshal(map[string]any{"ref": ref, "revision": 1, "after": after})
			var raw json.RawMessage
			started := time.Now()
			bounded, stop := context.WithTimeout(ctx, 25*time.Second)
			defer stop()
			if err := executor.QueryRow(bounded, `SELECT zasp_temporal77.catchup_definition($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Logf("configured catch-up page elapsed=%s", time.Since(started))
				t.Fatal("registered configured catch-up", err)
			}
			t.Logf("configured catch-up page elapsed=%s result=%s", time.Since(started), raw)
			var p page
			if json.Unmarshal(raw, &p) != nil || p.Scanned < 0 || p.Scanned > 25 || p.Admitted < 0 || p.Admitted > p.Scanned {
				t.Fatal("invalid source page", string(raw))
			}
			return p
		}
		if p := call(""); p.Scanned != 0 || p.Admitted != 0 || p.More || p.Retry {
			t.Fatal("draft visit performed admission work", p)
		}
		activateAutomaticPageDefinition(t, ctx, api, o, w, e, actor, definition, 5104)
		first := call("")
		if first.Scanned != 5 || first.Admitted != 0 || !first.More || first.Retry {
			t.Fatal("source page counts matches instead of bounded visits", first)
		}
		last := first
		visited, admitted := first.Scanned, first.Admitted
		for i := 0; i < 8 && last.More; i++ {
			prior := last.After
			last = call(prior)
			if last.After <= prior || last.Scanned > 5 || last.Retry || last.More && last.Admitted != 0 {
				t.Fatal("current-source cursor lost bounded progress", last)
			}
			visited += last.Scanned
			admitted += last.Admitted
		}
		if last.Scanned < 1 || last.More || last.Retry || last.Admitted != 1 || admitted != 1 || visited < 26 {
			t.Fatal("preactivation matching source lost", last)
		}
		var originalAt time.Time
		var event string
		var count int
		if err := owner.QueryRow(ctx, `SELECT s.source_at,s.event_id,(SELECT count(*) FROM zasp_temporal77.occurrences WHERE definition_id=$1) FROM zasp_temporal77.occurrences a JOIN zasp_temporal77.source_events s USING(organization_id,workspace_id,environment_id,event_id) WHERE a.definition_id=$1 AND s.source_id=$2`, definition, ids[25]).Scan(&originalAt, &event, &count); err != nil || !originalAt.Equal(original) || count != 1 {
			t.Fatal("catch-up consumed nonmatches or manufactured source time", originalAt, count, err)
		}
		q, _ := json.Marshal(map[string]any{"ref": ref, "revision": 1, "event_id": event})
		var raw json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, q).Scan(&raw); err != nil {
			t.Fatal("event/catch-up duplicate", err)
		}
		var result struct {
			Disposition string `json:"disposition"`
		}
		if json.Unmarshal(raw, &result) != nil || result.Disposition != "replayed" {
			t.Fatal("event and catch-up use different receipts", string(raw))
		}
	})
}
