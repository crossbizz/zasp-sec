package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This group tests the private shared matcher against canonical stored sources.
// Finding/path prerequisites are seeded here; actual writer coverage is separate.
// It is not yet enabled-definition, service-grant, admission or Temporal proof.
func TestTemporalAutomaticMatchingPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, testID, actor string) {
		installAutomaticSourceFixture(t, ctx, owner)
		now := time.Now().UTC().Truncate(time.Second)
		finding, path := automaticSourceID(60), automaticSourceID(61)
		if _, err := owner.Exec(ctx, `
INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Matcher fixture','high','open');
INSERT INTO zasp_risk_attack_paths(organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES($1,$2,$3,$5,$6,$7,'potential');
INSERT INTO zasp_risk_attack_path_nodes(organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES($1,$2,$3,$5,1,$6),($1,$2,$3,$5,2,$7);
INSERT INTO zasp_risk_attack_path_evidence(organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES($1,$2,$3,$5,1,$8)`, pgx.QueryExecModeSimpleProtocol, o, w, e, finding, path, automaticSourceID(62), automaticSourceID(63), automaticSourceID(64)); err != nil {
			t.Fatal(err)
		}
		eventID := func(kind, id string, version int) string {
			var value string
			if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE (organization_id,workspace_id,environment_id,source_kind,source_id,source_version)=($1,$2,$3,$4,$5,$6)`, o, w, e, kind, id, version).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		check := func(name, scopeE, id, body string, at time.Time, want bool) {
			t.Run(name, func(t *testing.T) {
				var matched bool
				err := owner.QueryRow(ctx, `SELECT zasp_temporal77.source_match($1,$2,$3,$4,$5::jsonb,$6) IS NOT NULL`, o, w, scopeE, id, body, at).Scan(&matched)
				if err != nil || matched != want {
					t.Fatalf("matched=%v want=%v err=%v", matched, want, err)
				}
			})
		}
		findingBody := `{"trigger_kind":"finding","trigger_source":"credential","trigger_rules":{"version":1,"mode":"automatic","cooldown_seconds":60,"finding":{"family":"credential","minimum_severity":"high"}}}`
		findingEvent := eventID("finding", finding, 1)
		check("finding threshold positive", e, findingEvent, findingBody, now, true)
		check("foreign environment", automaticSourceID(99), findingEvent, findingBody, now, false)
		check("manual never automatic", e, findingEvent, `{"trigger_kind":"finding","trigger_source":"credential","trigger_rules":{"version":1,"mode":"manual"}}`, now, false)
		check("missing rules belongs to legacy", e, findingEvent, `{"trigger_kind":"finding","trigger_source":"credential"}`, now, false)
		check("higher severity", e, findingEvent, replaceAutomaticJSON(t, findingBody, "minimum_severity", "critical"), now, false)
		check("different family", e, findingEvent, `{"trigger_kind":"finding","trigger_source":"exposure","trigger_rules":{"version":1,"mode":"automatic","cooldown_seconds":60,"finding":{"family":"exposure","minimum_severity":"low"}}}`, now, false)
		t.Run("finding final same version snapshot", func(t *testing.T) {
			before := automaticMatchSnapshot(t, ctx, owner, o, w, e, findingEvent, findingBody, now)
			if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET title='Final committed title' WHERE id=$1`, finding); err != nil {
				t.Fatal(err)
			}
			after := automaticMatchSnapshot(t, ctx, owner, o, w, e, findingEvent, findingBody, now)
			if before["digest"] == after["digest"] {
				t.Fatal("same-version finalized content absent from digest", before, after)
			}
			projection := after["evidence"].(map[string]any)
			if projection["source"].(map[string]any)["title"] != "Final committed title" {
				t.Fatal("not final source", after)
			}
		})
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=2,status='under_review',updated_at=clock_timestamp() WHERE id=$1`, finding); err != nil {
			t.Fatal(err)
		}
		check("stale finding occurrence", e, findingEvent, findingBody, now, false)
		check("nonopen current finding", e, eventID("finding", finding, 2), findingBody, now, false)
		pathEvent := eventID("attack_path", path, 1)
		pathBody := func(state string) string {
			return `{"trigger_kind":"attack_path","trigger_source":"` + state + `","trigger_rules":{"version":1,"mode":"automatic","cooldown_seconds":60,"attack_path":{"state":"` + state + `"}}}`
		}
		check("potential distinct positive", e, pathEvent, pathBody("potential"), now, true)
		check("potential never observed", e, pathEvent, pathBody("observed"), now, false)
		check("potential never verified", e, pathEvent, pathBody("verified"), now, false)
		t.Run("path final same version child snapshot", func(t *testing.T) {
			before := automaticMatchSnapshot(t, ctx, owner, o, w, e, pathEvent, pathBody("potential"), now)
			if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_path_evidence SET evidence_id=$2 WHERE path_id=$1`, path, automaticSourceID(67)); err != nil {
				t.Fatal(err)
			}
			after := automaticMatchSnapshot(t, ctx, owner, o, w, e, pathEvent, pathBody("potential"), now)
			if before["digest"] == after["digest"] {
				t.Fatal("same-version finalized children absent from digest", before, after)
			}
			projection := after["evidence"].(map[string]any)
			children := projection["evidence"].([]any)
			if len(children) != 1 || children[0].(map[string]any)["evidence_id"] != automaticSourceID(67) {
				t.Fatal("not final child evidence", after)
			}
		})
		if _, err := owner.Exec(ctx, `DELETE FROM zasp_risk_attack_path_evidence WHERE path_id=$1`, path); err != nil {
			t.Fatal(err)
		}
		check("path child authority missing", e, pathEvent, pathBody("potential"), now, false)
		_, repo, _, event := seedAutomaticRuntimeGateway(t, ctx, owner, o, w, e)
		event.OccurredAt = now
		if err := repo.Record(ctx, event); err != nil {
			t.Fatal(err)
		}
		runtimeEvent := eventID("runtime_decision", event.EventID, 1)
		runtimeBody := `{"trigger_kind":"runtime_decision","trigger_source":"block","trigger_rules":{"version":1,"mode":"automatic","cooldown_seconds":60,"runtime":{"decision":"block","action":"tool_execute","risk":"high","count":2,"window_seconds":60}}}`
		check("one event below count", e, runtimeEvent, runtimeBody, now, false)
		if err := repo.Record(ctx, event); err != nil {
			t.Fatal(err)
		}
		check("duplicate replay not another count", e, runtimeEvent, runtimeBody, now, false)
		event.EventID = automaticSourceID(65)
		event.ExpectedFloor = 1
		event.NextFloor = 2
		if err := repo.Record(ctx, event); err != nil {
			t.Fatal(err)
		}
		check("actual block requested classification counts", e, runtimeEvent, runtimeBody, now, true)
		check("normalized action not transport", e, runtimeEvent, replaceAutomaticJSON(t, runtimeBody, "action", "mcp"), now, false)
		check("risk exact mismatch", e, runtimeEvent, replaceAutomaticJSON(t, runtimeBody, "risk", "critical"), now, false)
		check("future events excluded", e, runtimeEvent, runtimeBody, now.Add(-time.Second), false)
		check("expired window excluded", e, runtimeEvent, runtimeBody, now.Add(61*time.Second), false)
		event.EventID = automaticSourceID(66)
		event.ExpectedFloor = 2
		event.NextFloor = 3
		event.Evaluation.Risk = ""
		if err := repo.Record(ctx, event); err != nil {
			t.Fatal(err)
		}
		check("unknown risk anchor cannot match", e, eventID("runtime_decision", event.EventID, 3), runtimeBody, now, false)
		countThree := strings.Replace(runtimeBody, `"count":2`, `"count":3`, 1)
		check("unknown risk never pads known count", e, runtimeEvent, countThree, now, false)
		event.EventID = automaticSourceID(68)
		event.ExpectedFloor = 3
		event.NextFloor = 4
		event.Evaluation.Risk = "high"
		event.Evaluation.SessionID = automaticSourceID(69)
		event.Classification["session_id"] = event.Evaluation.SessionID
		if err := repo.Record(ctx, event); err != nil {
			t.Fatal(err)
		}
		check("different session never pads count", e, runtimeEvent, countThree, now, false)
		if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE id=$1`, event.CredentialID); err != nil {
			t.Fatal(err)
		}
		check("revoked runtime source authority", e, runtimeEvent, runtimeBody, now, false)
	})
}

func automaticMatchSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, event, body string, at time.Time) map[string]any {
	t.Helper()
	var raw json.RawMessage
	var bound bool
	if err := owner.QueryRow(ctx, `SELECT result,result->>'digest'=encode(digest(convert_to((result->'evidence')::text,'UTF8'),'sha256'),'hex') FROM (SELECT zasp_temporal77.source_match($1,$2,$3,$4,$5::jsonb,$6) result) matched`, o, w, e, event, body, at).Scan(&raw, &bound); err != nil {
		t.Fatal(err)
	}
	if !bound {
		t.Fatal("returned snapshot detached from digest", string(raw))
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil || result == nil {
		t.Fatal("missing matched snapshot", string(raw), err)
	}
	return result
}

func replaceAutomaticJSON(t *testing.T, raw, key, value string) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	rules := body["trigger_rules"].(map[string]any)
	for _, nested := range []string{"finding", "runtime"} {
		if v, ok := rules[nested].(map[string]any); ok {
			v[key] = value
		}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
