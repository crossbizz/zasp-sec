package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Omission must not erase an active window established by a configured run.
// The source version advances through real capture; clock expiry is a named
// fixture prerequisite, never a rewrite of occurrence or run receipts.
func TestTemporalFindingResponseOmittedCooldownPostgres(t *testing.T) {
	runFindingResponseFixture(t, func(ctx context.Context, f findingResponseFixture) {
		finding := f.next()
		if _, err := f.owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Cooldown source','high','open')`, f.o, f.w, f.e, finding); err != nil {
			t.Fatal(err)
		}
		ref := map[string]any{"organization_id": f.o, "workspace_id": f.w, "environment_id": f.e, "definition_id": f.definition}
		event := func() string {
			t.Helper()
			var id string
			if err := f.owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE source_id=$1 ORDER BY source_version DESC LIMIT 1`, finding).Scan(&id); err != nil {
				t.Fatal(err)
			}
			return id
		}
		admit := func(id, want string) {
			t.Helper()
			q, _ := json.Marshal(map[string]any{"ref": ref, "revision": 1, "event_id": id})
			var raw json.RawMessage
			if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal77.admit_occurrence($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Fatal("omitted cooldown admission", err)
			}
			var got struct {
				Disposition string `json:"disposition"`
			}
			if json.Unmarshal(raw, &got) != nil || got.Disposition != want {
				t.Fatal("omitted cooldown disposition", string(raw), want)
			}
		}
		originalEvent := event()
		admit(originalEvent, "admitted")
		var deadline time.Time
		var originalReceipt string
		if err := f.owner.QueryRow(ctx, `SELECT admitted_until FROM zasp_temporal77.cooldowns WHERE definition_id=$1`, f.definition).Scan(&deadline); err != nil {
			t.Fatal(err)
		}
		if err := f.owner.QueryRow(ctx, `SELECT to_jsonb(t)::text FROM zasp_security_agent_trigger_receipts t WHERE definition_id=$1`, f.definition).Scan(&originalReceipt); err != nil {
			t.Fatal(err)
		}
		var start json.RawMessage
		if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest,'reason','workflow_cancelled') FROM zasp_temporal78.run_owners WHERE definition_id=$1`, f.definition).Scan(&start); err != nil {
			t.Fatal(err)
		}
		cfg := f.owner.Config().Copy()
		cfg.User = "finding78_compensation"
		compensation, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer compensation.Close(context.Background())
		var raw json.RawMessage
		if err := compensation.QueryRow(ctx, `SELECT zasp_temporal78.cleanup($1::jsonb)`, start).Scan(&raw); err != nil {
			t.Fatal("settle original queued run", err)
		}
		if err := f.owner.QueryRow(ctx, `SELECT (body-'trigger_rules')||'{"enabled":false}'::jsonb FROM zasp_security_agent_definitions WHERE definition_id=$1`, f.definition).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		body["trigger_source"] = "posture"
		raw, _ = json.Marshal(body)
		delete(body, "id")
		intent, _ := json.Marshal(map[string]any{"resource_id": f.definition, "expected_version": 4, "body": body})
		if err := f.api.QueryRow(ctx, `SELECT zasp_temporal78.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, "update", f.definition, f.o, f.w, f.e, f.actor, "updateSecurityAgent", "finding78-omit-active-cooldown", 4, intent, raw, f.next(), f.next(), f.next()).Scan(&raw); err != nil {
			t.Fatal("registered omission edit", err)
		}
		for i, target := range []string{"validated", "supervised", "autonomous"} {
			if _, err := f.repository.ActivateSecurityAgent(ctx, f.identity, SecurityAgentActivation{DefinitionID: f.definition, ExpectedVersion: int64(i + 5), TargetActivation: target, FreshAuthExpiresAt: f.identity.FreshAuthExpiresAt, IdempotencyKey: "finding78-omitted-window-" + target, AuditID: f.next(), CorrelationID: f.next(), ReceiptID: f.next()}); err != nil {
				t.Fatal(target, err)
			}
		}
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_risk_findings SET rule=NULL,severity='low',version=2 WHERE id=$1`, finding); err != nil {
			t.Fatal(err)
		}
		suppressed := event()
		admit(suppressed, "cooldown")
		var same bool
		if err := f.owner.QueryRow(ctx, `SELECT admitted_until=$2 AND admitted_until>clock_timestamp() AND (SELECT count(*)=1 FROM zasp_temporal78.run_owners WHERE definition_id=$1) AND (SELECT to_jsonb(t)::text=$3 FROM zasp_security_agent_trigger_receipts t WHERE definition_id=$1) FROM zasp_temporal77.cooldowns WHERE definition_id=$1`, f.definition, deadline, originalReceipt).Scan(&same); err != nil || !same {
			t.Fatal("omission reset live cooldown or receipt", same, err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_temporal77.cooldowns SET admitted_at=clock_timestamp()-interval '601 seconds',admitted_until=clock_timestamp()-interval '1 second' WHERE definition_id=$1`, f.definition); err != nil {
			t.Fatal(err)
		}
		admit(suppressed, "replayed")
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=3 WHERE id=$1`, finding); err != nil {
			t.Fatal(err)
		}
		admit(event(), "admitted")
		if err := f.owner.QueryRow(ctx, `SELECT admitted_until<clock_timestamp() AND (SELECT count(*)=2 FROM zasp_temporal78.run_owners WHERE definition_id=$1) AND NOT(SELECT body?'trigger_rules' FROM zasp_security_agent_definitions WHERE definition_id=$1) FROM zasp_temporal77.cooldowns WHERE definition_id=$1`, f.definition).Scan(&same); err != nil || !same {
			t.Fatal("omitted admission invented another cooldown", same, err)
		}
	})
}
