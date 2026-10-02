package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A blocked early definition must not starve the26th matching responder. The
// page boundary counts visited definitions, including duplicate/refused ones.
func TestTemporalAutomaticPagesPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 6*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `CREATE ROLE automatic_pages_executor LOGIN; CREATE ROLE automatic_pages_compensation LOGIN; SELECT zasp_temporal68.register_principals('automatic_pages_executor','automatic_pages_compensation'); SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":1,"enabled":true}')`); err != nil {
			t.Fatal(err)
		}
		c := owner.Config().Copy()
		c.User = "automatic_pages_executor"
		executor, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		var base json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&base); err != nil {
			t.Fatal(err)
		}
		definitions := make([]string, 26)
		for i := range definitions {
			definitions[i] = automaticSourceID(1000 + i*20)
			createAutomaticPageDefinition(t, ctx, api, o, w, e, actor, definitions[i], base, 1001+i*20)
		}
		insertSource := func(id string) string {
			t.Helper()
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Page source','high','open')`, o, w, e, id); err != nil {
				t.Fatal(err)
			}
			var event string
			if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE source_id=$1`, id).Scan(&event); err != nil {
				t.Fatal(err)
			}
			return event
		}
		occupied := insertSource(automaticSourceID(2000))
		ref := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": definitions[0]}
		q, _ := json.Marshal(map[string]any{"ref": ref, "revision": 1, "event_id": occupied})
		var raw json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, q).Scan(&raw); err != nil {
			t.Fatal("registered occupancy", err)
		}
		event := insertSource(automaticSourceID(2001))
		type page struct {
			After    string `json:"after"`
			More     bool   `json:"more"`
			Retry    bool   `json:"retry"`
			Scanned  int    `json:"scanned"`
			Admitted int    `json:"admitted"`
		}
		call := func(after string) page {
			t.Helper()
			q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "event_id": event, "after": after})
			started := time.Now()
			bounded, stop := context.WithTimeout(ctx, 25*time.Second)
			defer stop()
			if err := executor.QueryRow(bounded, `SELECT zasp_temporal77.dispatch_page($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Logf("definition page elapsed=%s", time.Since(started))
				t.Fatal("actual definition page", err)
			}
			t.Logf("definition page elapsed=%s result=%s", time.Since(started), raw)
			var p page
			if json.Unmarshal(raw, &p) != nil || p.Scanned < 0 || p.Scanned > 25 || p.Admitted < 0 || p.Admitted > p.Scanned {
				t.Fatal("invalid page", string(raw))
			}
			return p
		}
		first := call("")
		if first.Scanned != 5 || first.Admitted != 4 || !first.More || !first.Retry || first.After != definitions[4] {
			t.Fatal("first page lost progress/capacity deferral", first)
		}
		executor.Close(ctx)
		executor, err = pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		last := first
		visited, created := first.Scanned, first.Admitted
		for i := 0; i < 6 && last.More; i++ {
			prior := last.After
			last = call(prior)
			if last.After <= prior || last.Retry || last.Scanned > 5 || last.Admitted != last.Scanned {
				t.Fatal("later page lost progress", last)
			}
			visited += last.Scanned
			created += last.Admitted
		}
		if last.Scanned != 1 || last.Admitted != 1 || last.More || last.Retry || last.After != definitions[25] || visited != 26 || created != 25 {
			t.Fatal("later definition starved", last, visited, created)
		}
		retry := call("")
		if retry.Scanned != 5 || retry.Admitted != 0 || !retry.Retry || !retry.More {
			t.Fatal("duplicate retry reset page/consumed capacity refusal", retry)
		}
		lastRetry := retry
		visited = retry.Scanned
		for i := 0; i < 6 && lastRetry.More; i++ {
			prior := lastRetry.After
			lastRetry = call(prior)
			if lastRetry.After <= prior || lastRetry.Retry || lastRetry.Scanned > 5 || lastRetry.Admitted != 0 {
				t.Fatal("duplicate later page", lastRetry)
			}
			visited += lastRetry.Scanned
		}
		if lastRetry.Scanned != 1 || lastRetry.Admitted != 0 || lastRetry.More || visited != 26 {
			t.Fatal("duplicate later page", lastRetry, visited)
		}
		var admitted, blocked int
		if err := owner.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE definition_id=$2) FROM zasp_temporal77.occurrences WHERE event_id=$1`, event, definitions[0]).Scan(&admitted, &blocked); err != nil || admitted != 25 || blocked != 0 {
			t.Fatal("capacity refusal consumed event or retries duplicated", admitted, blocked, err)
		}
	})
}

func createAutomaticPageDefinition(t *testing.T, ctx context.Context, api *pgx.Conn, o, w, e, actor, id string, base json.RawMessage, sequence int, draftOnly ...bool) {
	t.Helper()
	var body map[string]any
	if json.Unmarshal(base, &body) != nil {
		t.Fatal("base definition")
	}
	body["id"] = id
	body["enabled"] = false
	body["trigger_rules"] = map[string]any{"version": 1, "mode": "automatic", "cooldown_seconds": 600, "finding": map[string]any{"family": "credential", "minimum_severity": "high"}}
	raw, _ := json.Marshal(body)
	delete(body, "id")
	intent, _ := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": body})
	next := func() string { sequence++; return automaticSourceID(sequence) }
	var result json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write('create',$1,$2,$3,$4,$5,'createSecurityAgent',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`, id, o, w, e, actor, "automatic77-pages-create-"+id, intent, raw, next(), next(), next()).Scan(&result); err != nil {
		t.Fatal("actual page definition create", err)
	}
	if len(draftOnly) > 0 && draftOnly[0] {
		return
	}
	activateAutomaticPageDefinition(t, ctx, api, o, w, e, actor, id, sequence)
}

func activateAutomaticPageDefinition(t *testing.T, ctx context.Context, api *pgx.Conn, o, w, e, actor, id string, sequence int) {
	t.Helper()
	next := func() string { sequence++; return automaticSourceID(sequence) }
	var result json.RawMessage
	for i, state := range []string{"validated", "supervised", "autonomous"} {
		if err := api.QueryRow(ctx, `SELECT zasp_temporal74.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, o, w, e, id, actor, fmt.Sprintf("automatic77-pages-%s-%s", id, state), i+1, state, time.Now().UTC().Add(4*time.Minute), next(), next(), next()).Scan(&result); err != nil {
			t.Fatal("actual page definition activation", state, err)
		}
	}
}
