package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Catches rule-blind admission, consumed drafts, duplicate admission and cooldown
// reset across definition edits. Canonical finding rows are fixture prerequisites;
// configuration/activation/admission use their actual registered SQL principals.
func TestTemporalAutomaticAdmissionPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalTestSelector(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE automatic_admission_executor LOGIN; CREATE ROLE automatic_admission_compensation LOGIN; SELECT zasp_temporal68.register_principals('automatic_admission_executor','automatic_admission_compensation'); SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":1,"enabled":true}')`); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "automatic_admission_executor"
		executor, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		// Produce the legacy occurrence receipt through75 before77 exists.
		preRef := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": temporalTestLegacyProved}
		preQ, _ := json.Marshal(map[string]any{"ref": preRef, "revision": 1})
		var preResult json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal75.admit($1::jsonb)`, preQ).Scan(&preResult); err != nil || string(preResult) != `{"created": 1}` {
			t.Fatal("actual pre77 admission", string(preResult), err)
		}
		var preRun, preFinding string
		if err := owner.QueryRow(ctx, `SELECT run_id,trigger_id FROM zasp_security_agent_trigger_receipts WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&preRun, &preFinding); err != nil {
			t.Fatal(err)
		}
		legacyEvidence := func() string {
			t.Helper()
			var value string
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('run',to_jsonb(r),'receipt',(SELECT to_jsonb(tr) FROM zasp_security_agent_trigger_receipts tr WHERE tr.run_id=r.run_id),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE a.run_id=r.run_id))::text FROM zasp_security_agent_runs r WHERE run_id=$1`, preRun).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		preEvidence := legacyEvidence()
		installAutomaticSourceAfterSelectorFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		sequence := 600
		next := func() string { sequence++; return automaticSourceID(sequence) }
		definition, finding := next(), next()
		var body json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT (body-'id')||jsonb_build_object('id',$2::text,'enabled',false,'trigger_rules','{"version":1,"mode":"automatic","cooldown_seconds":600,"finding":{"family":"credential","minimum_severity":"high"}}'::jsonb) FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved, definition).Scan(&body); err != nil {
			t.Fatal(err)
		}
		write := func(action string, version int64, rule string) {
			t.Helper()
			var b map[string]any
			if json.Unmarshal(body, &b) != nil {
				t.Fatal("definition fixture")
			}
			b["enabled"] = false
			if rule != "" {
				var r any
				if json.Unmarshal([]byte(rule), &r) != nil {
					t.Fatal("rule fixture")
				}
				b["trigger_rules"] = r
			}
			body, _ = json.Marshal(b)
			delete(b, "id")
			resource := definition
			operation := "updateSecurityAgent"
			if action == "create" {
				resource = ""
				operation = "createSecurityAgent"
			}
			intent, _ := json.Marshal(map[string]any{"resource_id": resource, "expected_version": version, "body": b})
			var result json.RawMessage
			if err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, action, definition, o, w, e, actor, operation, fmt.Sprintf("automatic77-admission-write-%s-%d", definition, version), version, intent, body, next(), next(), next()).Scan(&result); err != nil {
				t.Fatal("registered definition write", err)
			}
		}
		write("create", 0, "")
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Configured source','high','open')`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		event := func() string {
			t.Helper()
			var id string
			if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE source_id=$1 ORDER BY source_version DESC LIMIT 1`, finding).Scan(&id); err != nil {
				t.Fatal(err)
			}
			return id
		}
		firstEvent := event()
		ref := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": definition}
		admit := func(id string, want string) string {
			t.Helper()
			q, _ := json.Marshal(map[string]any{"ref": ref, "revision": 1, "event_id": id})
			var raw json.RawMessage
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Fatal("registered occurrence admission", err)
			}
			var result struct {
				Disposition string `json:"disposition"`
				RunID       string `json:"run_id"`
			}
			if json.Unmarshal(raw, &result) != nil || result.Disposition != want {
				t.Fatalf("admission=%s want=%s", raw, want)
			}
			return result.RunID
		}
		activate := func(version int64) {
			t.Helper()
			for i, state := range []string{"validated", "supervised", "autonomous"} {
				var result json.RawMessage
				if err := api.QueryRow(ctx, `SELECT zasp_temporal74.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, o, w, e, definition, actor, fmt.Sprintf("automatic77-admission-activate-%s-%d-%s", definition, version, state), version+int64(i), state, time.Now().UTC().Add(4*time.Minute), next(), next(), next()).Scan(&result); err != nil {
					t.Fatal("registered configured activation", state, err)
				}
			}
		}
		admit(firstEvent, "ignored")
		activate(1)
		// An old rule-blind caller must not bypass the new occurrence authority.
		legacyQ, _ := json.Marshal(map[string]any{"ref": ref, "revision": 1})
		var legacyResult json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal75.admit($1::jsonb)`, legacyQ).Scan(&legacyResult); err != nil || string(legacyResult) != `{"created": 0}` {
			t.Fatal("raw75 admitted configured occurrence without77 decision", string(legacyResult), err)
		}
		var untouched bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE definition_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_trigger_receipts WHERE definition_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences WHERE definition_id=$1)`, definition).Scan(&untouched); err != nil || !untouched {
			t.Fatal("rule-blind refusal left admission side effects", untouched, err)
		}
		firstRun := admit(firstEvent, "admitted")
		if firstRun == "" || admit(firstEvent, "replayed") != firstRun {
			t.Fatal("duplicate changed canonical run")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, finding); err != nil {
			t.Fatal(err)
		}
		secondEvent := event()
		admit(secondEvent, "cooldown")
		write("update", 4, `{"version":1,"mode":"automatic","cooldown_seconds":1,"finding":{"family":"credential","minimum_severity":"high"}}`)
		admit(firstEvent, "ignored")
		activate(5)
		if admit(firstEvent, "replayed") != firstRun {
			t.Fatal("definition edit reset permanent occurrence")
		}
		admit(secondEvent, "replayed")
		if _, err := owner.Exec(ctx, `UPDATE zasp_temporal77.cooldowns SET admitted_at=clock_timestamp()-interval '2 seconds' WHERE definition_id=$1`, definition); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, finding); err != nil {
			t.Fatal(err)
		}
		admit(event(), "cooldown")
		// This mutable clock checkpoint is advanced only in the disposable fixture;
		// immutable receipts and source timestamps are never rewritten.
		if _, err := owner.Exec(ctx, `UPDATE zasp_temporal77.cooldowns SET admitted_at=clock_timestamp()-interval '601 seconds',admitted_until=clock_timestamp()-interval '1 second' WHERE definition_id=$1`, definition); err != nil {
			t.Fatal(err)
		}
		admit(secondEvent, "replayed")
		var bound bool
		if err := owner.QueryRow(ctx, `SELECT snapshot_digest=digest(convert_to(snapshot::text,'UTF8'),'sha256') AND snapshot->'source'->>'title'='Configured source' FROM zasp_temporal77.occurrences WHERE definition_id=$1 AND event_id=$2`, definition, firstEvent).Scan(&bound); err != nil || !bound {
			t.Fatal("immutable admission lacks final source snapshot", bound, err)
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_runs WHERE definition_id=$1`, definition).Scan(&count); err != nil || count != 1 {
			t.Fatal("replay/cooldown created another run", count, err)
		}
		// Old-version receipts are permanently consumed, not75 replay conflicts.
		definition, finding = temporalTestLegacyProved, preFinding
		ref["definition_id"] = definition
		if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, definition).Scan(&body); err != nil {
			t.Fatal(err)
		}
		write("update", 4, `{"version":1,"mode":"automatic","cooldown_seconds":600,"finding":{"family":"credential","minimum_severity":"low"}}`)
		activate(5)
		for i := 0; i < 3; i++ {
			if _, err := executor.Exec(ctx, `SELECT zasp_temporal77.scan_sources(100)`); err != nil {
				t.Fatal(err)
			}
		}
		oldEvent := event()
		if got := admit(oldEvent, "consumed"); got != preRun {
			t.Fatal("legacy receipt replaced", got, preRun)
		}
		if got := admit(oldEvent, "replayed"); got != preRun {
			t.Fatal("legacy consumed retry changed run", got)
		}
		if after := legacyEvidence(); after != preEvidence {
			t.Fatal("legacy run/receipt/audit rewritten", preEvidence, after)
		}
		// The pre77 run is still active. A distinct new source cannot evade its
		// shared definition capacity merely by changing admission owners.
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, finding); err != nil {
			t.Fatal(err)
		}
		freshEvent := event()
		capacityQ, _ := json.Marshal(map[string]any{"ref": ref, "revision": 1, "event_id": freshEvent})
		var refused json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, capacityQ).Scan(&refused); err == nil || !strings.Contains(err.Error(), "40001") {
			t.Fatal("new77 admission bypassed active75 capacity", string(refused), err)
		}
		var absent bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences WHERE definition_id=$1 AND event_id=$2) AND (SELECT count(*)=1 FROM zasp_security_agent_runs WHERE definition_id=$1)`, definition, freshEvent).Scan(&absent); err != nil || !absent || legacyEvidence() != preEvidence {
			t.Fatal("capacity refusal consumed source or rewrote legacy evidence", absent, err)
		}
	})
}
