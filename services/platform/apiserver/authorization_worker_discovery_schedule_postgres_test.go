package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Both phases share the parent-owned database. Occurrences use the persisted
// schedule and real database clock, never synthesized runs or altered due times.
func discovery72ScheduledPhase(t *testing.T, ctx context.Context, owner *pgx.Conn, phase, o, w, e, actor, integration string, call func(string, string, string, int64) *httptest.ResponseRecorder, reconcile func(), runWorker func(string, json.RawMessage), requestForKey func(string) json.RawMessage) {
	t.Helper()
	version := func() int64 {
		t.Helper()
		var value int64
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, integration).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	revision := func() int64 {
		t.Helper()
		var value int64
		if err := owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	restoreMember := func() {
		t.Helper()
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2`, o, actor); err != nil {
			t.Fatal(err)
		}
		reconcile()
	}
	manual := func(key string) json.RawMessage {
		t.Helper()
		response := call("syncIntegration", key, `{}`, version())
		if response.Code != http.StatusAccepted {
			t.Fatalf("schedule companion admission %s: %d %s", key, response.Code, response.Body.String())
		}
		reconcile()
		return requestForKey(key)
	}
	var schedule string
	var scheduleVersion int64
	var due time.Time
	readSchedule := func() {
		t.Helper()
		if err := owner.QueryRow(ctx, `SELECT id,version,next_run_at FROM zasp_temporal72.schedules WHERE (organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4) AND state='enabled' AND cadence_seconds=300`, o, w, e, integration).Scan(&schedule, &scheduleVersion, &due); err != nil {
			t.Fatal("persisted enabled schedule", err)
		}
	}
	if phase == "1" {
		var previous int64
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_temporal72.schedules WHERE (organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4)`, o, w, e, integration).Scan(&previous); err != nil {
			t.Fatal(err)
		}
		body := `{"cadence_seconds":300,"state":"enabled"}`
		enabled := call("putIntegrationSchedule", "discovery72-scheduled-enable-0001", body, previous)
		if enabled.Code != http.StatusOK {
			t.Fatalf("schedule enable: %d %s", enabled.Code, enabled.Body.String())
		}
		reconcile()
		replayed := call("putIntegrationSchedule", "discovery72-scheduled-enable-0001", body, previous)
		if replayed.Code != http.StatusOK || !bytes.Equal(enabled.Body.Bytes(), replayed.Body.Bytes()) {
			t.Fatal("checked schedule replay changed receipt")
		}
		readSchedule()
		firstDue := due
		runWorker("TestP7Discovery72PartialRevokeNative", manual("discovery72-scheduled-partial-0001"))
		restoreMember()
		sourceRequest := manual("discovery72-scheduled-source-0001")
		if tag, err := owner.Exec(ctx, `UPDATE zasp_integrations SET version=version+1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, integration); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("owned integration version transition", err)
		}
		reconcile()
		runWorker("TestP7Discovery72RevokedSourceNative", sourceRequest)
		readSchedule()
		if !due.Equal(firstDue) {
			t.Fatal("companion controls changed schedule due time")
		}
	} else if phase != "2" {
		t.Fatal("unsupported schedule phase")
	}
	readSchedule()
	t.Log("waiting for actual persisted schedule occurrence", phase, due.UTC())
	for {
		var seconds float64
		if err := owner.QueryRow(ctx, `SELECT extract(epoch FROM $1::timestamptz-clock_timestamp())::double precision`, due).Scan(&seconds); err != nil {
			t.Fatal(err)
		}
		if seconds <= 0 {
			break
		}
		delay := min(time.Duration(seconds*float64(time.Second))+time.Millisecond, 10*time.Second)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
	}
	var login string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_temporal72.principals WHERE authority_role='zasp_discovery_scheduler'`).Scan(&login); err != nil {
		t.Fatal(err)
	}
	cfg := owner.Config().Copy()
	cfg.User = login
	scheduler, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = scheduler.Close(cleanup)
	}()
	var admitted json.RawMessage
	if err := scheduler.QueryRow(ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,$6,$7)`, o, w, e, schedule, integration, scheduleVersion, due).Scan(&admitted); err != nil {
		t.Fatal("real due schedule admission", err)
	}
	var result struct {
		Outcome string `json:"outcome"`
	}
	if json.Unmarshal(admitted, &result) != nil || result.Outcome != "admitted" {
		t.Fatal("due occurrence not admitted", string(admitted))
	}
	var key string
	if err := owner.QueryRow(ctx, `SELECT s.idempotency_key FROM zasp_temporal72.runs r JOIN zasp_discovery_syncs s ON(s.organization_id,s.workspace_id,s.environment_id,s.id)=(r.organization_id,r.workspace_id,r.environment_id,r.sync_id) WHERE(r.organization_id,r.workspace_id,r.environment_id,r.schedule_id,r.scheduled_for)=($1,$2,$3,$4,$5)`, o, w, e, schedule, due).Scan(&key); err != nil {
		t.Fatal("native occurrence identity", err)
	}
	reconcile()
	request := requestForKey(key)
	if phase == "1" {
		runWorker("TestP7Discovery72ProductMachineNative", request)
		restoreMember()
		// A matching real credential transition changes old captured facts but
		// leaves a valid credential available to the later scheduled occurrence.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,expires_at) VALUES($1,$2,$3,'pid_72008035-0000-4000-8000-000000000035',$4,'aws','aws_external_id','ref:aws/external-id/customer-0001',1,clock_timestamp()+interval '1 hour')`, o, w, e, integration); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_connector_credentials SET version=2 WHERE organization_id=$1 AND id='pid_72008035-0000-4000-8000-000000000035'`, o); err != nil {
			t.Fatal(err)
		}
		reconcile()
		t.Log("first real scheduled occurrence completed; captured source invalidated for mixed second occurrence")
		return
	}
	var mixed bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=2 AND count(*) FILTER(WHERE s.current_source)=1 AND count(*) FILTER(WHERE NOT s.current_source)=1 FROM zasp_authorization80_worker.discovery_associations a JOIN zasp_authorization80_worker.discovery_state s USING(organization_id,workspace_id,environment_id,job_id) WHERE(a.organization_id,a.workspace_id,a.environment_id,a.schedule_id)=($1,$2,$3,$4)`, o, w, e, schedule).Scan(&mixed); err != nil || !mixed {
		t.Fatal("two real occurrences did not produce mixed captured authority", err)
	}
	before := revision()
	disabled := call("putIntegrationSchedule", "discovery72-scheduled-disable-0001", `{"cadence_seconds":300,"state":"disabled"}`, scheduleVersion)
	if disabled.Code != http.StatusOK || revision() != before+1 {
		t.Fatalf("mixed schedule disable status=%d desired delta=%d", disabled.Code, revision()-before)
	}
	reconcile()
	runWorker("TestP7Discovery72RevokedSourceNative", request)
	before = revision()
	reenabled := call("putIntegrationSchedule", "discovery72-scheduled-reenable-0001", `{"cadence_seconds":300,"state":"enabled"}`, scheduleVersion+1)
	if reenabled.Code != http.StatusOK || revision() != before {
		t.Fatal("schedule re-enable revived old captured authority", reenabled.Code)
	}
	reconcile()
	deleted := call("deleteIntegrationSchedule", "discovery72-scheduled-delete-0001", "", scheduleVersion+2)
	if deleted.Code != http.StatusNoContent || revision() != before {
		t.Fatalf("schedule delete status=%d desired delta=%d", deleted.Code, revision()-before)
	}
	var revived bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.discovery_associations a JOIN zasp_authorization80_worker.discovery_state s USING(organization_id,workspace_id,environment_id,job_id) WHERE(a.organization_id,a.workspace_id,a.environment_id,a.schedule_id)=($1,$2,$3,$4) AND s.current_source)`, o, w, e, schedule).Scan(&revived); err != nil || revived {
		t.Fatal("old scheduled capture revived", err)
	}
	reconcile()
	// Revocation at the actual transport boundary must prevent the HTTP send.
	// Lost-response ownership is verified separately by the boundary pair.
	runWorker("TestP7Discovery72PerSendRevokeNative", manual("discovery72-scheduled-persend-0001"))
	t.Log("two real schedule occurrences, exact revision invalidation, source denial and per-send revocation checked")
}
