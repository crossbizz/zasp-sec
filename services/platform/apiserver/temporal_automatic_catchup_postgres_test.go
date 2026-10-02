package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestTemporalAutomaticCatchupPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		original := time.Now().UTC().Truncate(time.Second).Add(-48 * time.Hour)
		ids := make([]string, 41)
		for i := range ids {
			ids[i] = automaticSourceID(100 + i)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,created_at,updated_at) SELECT $1,$2,$3,id,'posture','credential','Preinstallation catch-up','high','open',$5,$5 FROM unnest($4::text[]) id`, o, w, e, ids, original); err != nil {
			t.Fatal(err)
		}
		path := automaticSourceID(150)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_attack_paths(organization_id,workspace_id,environment_id,id,entry_id,sink_id,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'potential',$7,$7)`, o, w, e, path, automaticSourceID(151), automaticSourceID(152), original); err != nil {
			t.Fatal(err)
		}
		_, gateway, _, runtimeEvent := seedAutomaticRuntimeGateway(t, ctx, owner, o, w, e)
		runtimeEvent.Evaluation = nil
		if err := gateway.Record(ctx, runtimeEvent); err != nil {
			t.Fatal("actual pre77 runtime writer", err)
		}
		for i := 0; i < 30; i++ {
			next := runtimeEvent
			next.EventID = automaticSourceID(300 + i)
			next.ExpectedFloor = uint64(i + 1)
			next.NextFloor = uint64(i + 2)
			if err := gateway.Record(ctx, next); err != nil {
				t.Fatal("same-timestamp pre77 writer", err)
			}
		}
		expiredEnvironment := "pid_00000077-0000-4000-8000-000000000001"
		seedAutomaticExpiredRuntimeScope(t, ctx, owner, o, w, expiredEnvironment, runtimeEvent.CredentialID, original)
		installAutomaticSourceFixture(t, ctx, owner)
		count := func() int {
			var n int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.source_events WHERE source_id=ANY($1::text[])`, ids).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if count() != 0 {
			t.Fatal("migration eagerly backfilled source data")
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE catchup_executor LOGIN; CREATE ROLE catchup_compensation LOGIN; SELECT zasp_temporal68.register_principals('catchup_executor','catchup_compensation')`); err != nil {
			t.Fatal(err)
		}
		connect := func() *pgx.Conn {
			config := owner.Config().Copy()
			config.User = "catchup_executor"
			conn, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close(context.Background()) })
			return conn
		}
		executor := connect()
		type pageResult struct {
			Scanned  int  `json:"scanned"`
			Captured int  `json:"captured"`
			Wrapped  bool `json:"wrapped"`
		}
		page := func(limit int) pageResult {
			var raw json.RawMessage
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.scan_sources($1)`, limit).Scan(&raw); err != nil {
				t.Fatal("actual bounded source scan", err)
			}
			var result pageResult
			if err := json.Unmarshal(raw, &result); err != nil || result.Scanned < 0 || result.Scanned > limit || result.Captured < 0 || result.Captured > result.Scanned {
				t.Fatal("unbounded/invalid page", string(raw), err)
			}
			return result
		}
		if _, err := executor.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		rolledBack := page(25)
		if rolledBack.Scanned != 25 || count() != 0 {
			t.Fatal("scan not bounded or leaked uncommitted source", rolledBack, count())
		}
		if _, err := executor.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if count() != 0 {
			t.Fatal("rolled-back scanner left occurrences")
		}
		// A writer transaction overlaps the scan. The scan reads the committed
		// old version; it neither captures dirty data nor waits on the source row.
		if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=2,updated_at=clock_timestamp() WHERE id=$1`, ids[0]); err != nil {
			t.Fatal(err)
		}
		first := page(25)
		if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if first.Scanned != 25 || first.Wrapped || count() < 1 || count() > 25 {
			t.Fatal("first committed page", first, count())
		}
		var cursorBefore, cursorAfter json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(c) FROM zasp_temporal77.source_scan c`).Scan(&cursorBefore); err != nil {
			t.Fatal(err)
		}
		beforeCount := count()
		executor.Close(ctx)
		executor = connect()
		second := page(25)
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(c) FROM zasp_temporal77.source_scan c`).Scan(&cursorAfter); err != nil {
			t.Fatal(err)
		}
		if string(cursorBefore) == string(cursorAfter) || count() <= beforeCount {
			t.Fatal("reconnected client repeated consumed scan prefix", second, string(cursorBefore), string(cursorAfter), count())
		}
		wrapped := second.Wrapped
		runtimeScanned := 0
		runtimeReconnected := false
		for i := 0; i < 20 && !wrapped; i++ {
			var kind string
			if err := owner.QueryRow(ctx, `SELECT source_kind FROM zasp_temporal77.source_scan`).Scan(&kind); err != nil {
				t.Fatal(err)
			}
			result := page(25)
			wrapped = result.Wrapped
			if kind == "runtime_decision" {
				runtimeScanned += result.Scanned
			}
			var current int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.source_events WHERE source_kind='runtime_decision' AND environment_id=$1`, e).Scan(&current); err != nil {
				t.Fatal(err)
			}
			if current > 0 && current < 31 && !runtimeReconnected {
				executor.Close(ctx)
				executor = connect()
				runtimeReconnected = true
			}
		}
		if !wrapped || count() != 41 {
			t.Fatal("scan failed durable continuation/wrap", wrapped, count())
		}
		var recentCount, expiredCount int
		if err := owner.QueryRow(ctx, `SELECT count(*) FILTER(WHERE environment_id=$1),count(*) FILTER(WHERE environment_id=$2) FROM zasp_temporal77.source_events WHERE source_kind='runtime_decision'`, e, expiredEnvironment).Scan(&recentCount, &expiredCount); err != nil || recentCount != 31 || expiredCount != 0 || !runtimeReconnected {
			t.Fatal("scope/timestamp reconnect lost or fabricated runtime source", recentCount, expiredCount, runtimeReconnected, err)
		}
		if runtimeScanned != 31 {
			t.Fatal("runtime cursor traversed expired history instead of recent indexed range", runtimeScanned)
		}
		var pathAt, runtimeAt time.Time
		if err := owner.QueryRow(ctx, `SELECT (SELECT source_at FROM zasp_temporal77.source_events WHERE source_kind='attack_path' AND source_id=$1),(SELECT source_at FROM zasp_temporal77.source_events WHERE source_kind='runtime_decision' AND source_id=$2)`, path, runtimeEvent.EventID).Scan(&pathAt, &runtimeAt); err != nil || !pathAt.Equal(original) || !runtimeAt.Equal(runtimeEvent.OccurredAt) {
			t.Fatal("family transition lost original path/runtime time", pathAt, runtimeAt, err)
		}
		var canonical bool
		if err := owner.QueryRow(ctx, `SELECT bool_and(source_version=1 AND source_at=$2 AND event_id=zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'automatic_source_v1',concat_ws(chr(31),source_kind,source_id,source_version))) FROM zasp_temporal77.source_events WHERE source_id=ANY($1::text[])`, ids, original).Scan(&canonical); err != nil || !canonical {
			t.Fatal("catch-up manufactured identity/time or dirty version", canonical, err)
		}
		emptySeen := false
		wrapped = false
		for i := 0; i < 200; i++ {
			result := page(1)
			emptySeen = emptySeen || result.Scanned == 0
			if result.Wrapped {
				wrapped = true
				break
			}
		}
		if !emptySeen || !wrapped {
			t.Fatal("empty family tail page failed transition/wrap", emptySeen, wrapped)
		}
		if count() != 41 {
			t.Fatal("wrap duplicated original occurrences", count())
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=2,updated_at=clock_timestamp() WHERE id=$1`, ids[0]); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 10; i++ {
			if page(25).Wrapped {
				break
			}
		}
		if count() != 42 {
			t.Fatal("concurrent capture and catch-up duplicated/lost version", count())
		}
		if _, err := api.Exec(ctx, `SELECT zasp_temporal77.scan_sources(25)`); err == nil {
			t.Fatal("API consumed global scan progress")
		}
		if _, err := executor.Exec(ctx, `SELECT zasp_temporal77.scan_sources(101)`); err == nil {
			t.Fatal("unbounded scan accepted")
		}
	})
}

// Explicit historical-row fixture, not signed ingestion proof. The current
// scope above is written by the actual27 repository; these older rows only
// establish that an expired-only earlier scope cannot monopolize catch-up.
func seedAutomaticExpiredRuntimeScope(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, sourceCredential string, original time.Time) {
	t.Helper()
	ids := make([]string, 40)
	for i := range ids {
		ids[i] = automaticSourceID(200 + i)
	}
	if _, err := owner.Exec(ctx, `
INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Expired runtime history','production');
INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state,replay_floor,version) VALUES($1,$2,$3,$4,'Expired history gateway','active',40,41);
INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,issued_at,expires_at,consumed_at,format_version,locator_digest,token_generation,device_version_at_issue,v15_issued_at)
SELECT $1,$2,$3,$5,$4,t.audience,t.salt,digest(convert_to($5,'UTF8'),'sha256'),t.issued_at,t.expires_at,t.consumed_at,t.format_version,digest(convert_to($5||':locator','UTF8'),'sha256'),t.token_generation,t.device_version_at_issue,t.v15_issued_at FROM zasp_gateway_enrollment_tokens t JOIN zasp_gateway_credentials c ON c.enrollment_token_id=t.id WHERE c.id=$7;
INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at)
SELECT $1,$2,$3,$6,$4,$5,digest(convert_to($6,'UTF8'),'sha256'),audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at FROM zasp_gateway_credentials WHERE id=$7;
INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,policy_ids,occurred_at)
SELECT $1,$2,$3,$4,$6,item.id,item.n,digest(convert_to(jsonb_build_object('credential_id',$6::text,'device_id',$4::text,'event_id',item.id,'expected_floor',item.n-1,'next_floor',item.n,'policy_version',v.policy_version,'decision',v.decision,'action_kind',v.action_kind,'classification',v.classification,'policy_ids',v.policy_ids,'occurred_at',to_char($9::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text,'UTF8'),'sha256'),v.policy_version,v.decision,v.action_kind,v.classification,v.policy_ids,$9
FROM unnest($8::text[]) WITH ORDINALITY item(id,n) CROSS JOIN(SELECT * FROM zasp_runtime_gateway_events WHERE credential_id=$7 ORDER BY sequence LIMIT 1)v`, pgx.QueryExecModeSimpleProtocol, o, w, e, automaticSourceID(170), automaticSourceID(171), automaticSourceID(172), sourceCredential, ids, original); err != nil {
		t.Fatal("expired-only scope prerequisites", err)
	}
}
