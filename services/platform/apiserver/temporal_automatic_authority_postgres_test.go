package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Source rows and the explicit service-grant revocation are controlled database
// prerequisites. Definitions, activation, desired and admission use actual roles.
func TestTemporalAutomaticAuthorityPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `CREATE ROLE automatic_authority_executor LOGIN;CREATE ROLE automatic_authority_compensation LOGIN;SELECT zasp_temporal68.register_principals('automatic_authority_executor','automatic_authority_compensation');SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":86400,"enabled":true}');UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "automatic_authority_executor"
		executor, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		var base json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&base); err != nil {
			t.Fatal(err)
		}
		sequence := 10000
		next := func() string { sequence++; return automaticSourceID(sequence) }
		create := func(kind, source string, rules map[string]any) string {
			t.Helper()
			id := next()
			var body map[string]any
			json.Unmarshal(base, &body)
			body["id"], body["enabled"], body["trigger_kind"], body["trigger_source"], body["trigger_rules"] = id, false, kind, source, rules
			raw, _ := json.Marshal(body)
			delete(body, "id")
			intent, _ := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": body})
			var result json.RawMessage
			if err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write('create',$1,$2,$3,$4,$5,'createSecurityAgent',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`, id, o, w, e, actor, "automatic77-authority-create-"+id, intent, raw, next(), next(), next()).Scan(&result); err != nil {
				t.Fatal("actual authority definition create", err)
			}
			activateAutomaticPageDefinition(t, ctx, api, o, w, e, actor, id, sequence)
			sequence += 10
			return id
		}
		manual := create("finding", "credential", map[string]any{"version": 1, "mode": "manual"})
		ref := func(id string) map[string]any {
			return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": id}
		}
		q, _ := json.Marshal(ref(manual))
		var desired json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.desired($1::jsonb)`, q).Scan(&desired); err != nil {
			t.Fatal(err)
		}
		var desiredFields struct {
			Enabled   bool `json:"enabled"`
			Automatic bool `json:"automatic"`
		}
		if json.Unmarshal(desired, &desiredFields) != nil || desiredFields.Enabled || !desiredFields.Automatic {
			t.Fatal("activated manual rule scheduled automatic work", string(desired))
		}
		finding := next()
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Authority fixture','high','open')`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		event := func(id string) string {
			t.Helper()
			var value string
			if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE source_id=$1 ORDER BY source_version DESC LIMIT 1`, id).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		admit := func(def, ev string) (string, error) {
			q, _ := json.Marshal(map[string]any{"ref": ref(def), "revision": 1, "event_id": ev})
			var raw json.RawMessage
			err := executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, q).Scan(&raw)
			return string(raw), err
		}
		want := func(def, ev, disposition string) {
			t.Helper()
			raw, err := admit(def, ev)
			var result struct {
				Disposition string `json:"disposition"`
			}
			if err != nil || json.Unmarshal([]byte(raw), &result) != nil || result.Disposition != disposition {
				t.Fatal("configured authority decision", raw, disposition, err)
			}
		}
		want(manual, event(finding), "ignored")
		legacyQ, _ := json.Marshal(map[string]any{"ref": ref(manual), "revision": 1})
		var raw json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal75.admit($1::jsonb)`, legacyQ).Scan(&raw); err != nil || string(raw) != `{"created": 0}` {
			t.Fatal("manual bypass through75", string(raw), err)
		}
		findingRules := map[string]any{"version": 1, "mode": "automatic", "cooldown_seconds": 600, "finding": map[string]any{"family": "credential", "minimum_severity": "high"}}
		revoked := create("finding", "credential", findingRules)
		// Explicitly seeded revocation isolates grant authority from disabled/draft
		// short-circuiting. Existing74 tests cover the actual configuration writer.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal74.grant_revocations(organization_id,workspace_id,environment_id,definition_id,definition_version,actor_id,audit_id) VALUES($1,$2,$3,$4,4,$5,$6)`, o, w, e, revoked, actor, next()); err != nil {
			t.Fatal(err)
		}
		if raw, err := admit(revoked, event(finding)); err == nil || !strings.Contains(err.Error(), "42501") {
			t.Fatal("revoked service grant admitted", raw, err)
		}
		for _, id := range []string{manual, revoked} {
			var clean bool
			if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences WHERE definition_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE definition_id=$1)`, id).Scan(&clean); err != nil || !clean {
				t.Fatal("refusal consumed occurrence", clean, err)
			}
		}
		pathRule := func(state string) map[string]any {
			return map[string]any{"version": 1, "mode": "automatic", "cooldown_seconds": 600, "attack_path": map[string]any{"state": state}}
		}
		observed, verified := create("attack_path", "observed", pathRule("observed")), create("attack_path", "verified", pathRule("verified"))
		path, entry, sink, evidence := next(), next(), next(), next()
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_attack_paths(organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES($1,$2,$3,$4,$5,$6,'potential');INSERT INTO zasp_risk_attack_path_nodes(organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES($1,$2,$3,$4,1,$5),($1,$2,$3,$4,2,$6);INSERT INTO zasp_risk_attack_path_evidence(organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$7)`, pgx.QueryExecModeSimpleProtocol, o, w, e, path, entry, sink, evidence); err != nil {
			t.Fatal(err)
		}
		want(observed, event(path), "ignored")
		want(verified, event(path), "ignored")
		for _, state := range []string{"observed", "verified"} {
			if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state=$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1`, path, state); err != nil {
				t.Fatal(err)
			}
			ev := event(path)
			matching, other := observed, verified
			if state == "verified" {
				matching, other = verified, observed
			}
			want(other, ev, "ignored")
			want(matching, ev, "admitted")
			want(matching, ev, "replayed")
			var bound bool
			if err := owner.QueryRow(ctx, `SELECT a.snapshot->'source'->>'state'=$3 AND a.snapshot_digest=digest(convert_to(a.snapshot::text,'UTF8'),'sha256') AND tr.trigger_kind='attack_path' AND tr.trigger_id=$4 AND tr.trigger_version=(a.snapshot->'source'->>'version')::bigint FROM zasp_temporal77.occurrences a JOIN zasp_security_agent_trigger_receipts tr USING(organization_id,workspace_id,environment_id,definition_id,run_id) WHERE a.definition_id=$1 AND a.event_id=$2`, matching, ev, state, path).Scan(&bound); err != nil || !bound {
				t.Fatal("path admission snapshot/receipt not bound", state, bound, err)
			}
		}
		t.Log("configured manual/refused grant and distinct observed/verified path admission/replay passed; canonical paths and explicit revocation were seeded")
	})
}
