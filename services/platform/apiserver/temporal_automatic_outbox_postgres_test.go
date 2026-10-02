package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Application delivery state must remain atomic, fairly retryable and distinct
// from completion. SQL receipt tests do not attest that a Temporal RPC happened.
func TestTemporalAutomaticOutboxPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `CREATE ROLE automatic_outbox_executor LOGIN; CREATE ROLE automatic_outbox_compensation LOGIN; SELECT zasp_temporal68.register_principals('automatic_outbox_executor','automatic_outbox_compensation'); SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":1,"enabled":true}')`); err != nil {
			t.Fatal(err)
		}
		c := owner.Config().Copy()
		c.User = "automatic_outbox_executor"
		connect := func() *pgx.Conn {
			t.Helper()
			conn, err := pgx.ConnectConfig(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close(context.Background()) })
			return conn
		}
		executor := connect()
		ids := make([]string, 26)
		for i := range ids {
			ids[i] = automaticSourceID(6000 + i)
		}
		insert := func(conn *pgx.Conn, values []string) {
			t.Helper()
			if _, err := conn.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) SELECT $1,$2,$3,id,'posture','credential','Outbox source','high','open' FROM unnest($4::text[]) id`, o, w, e, values); err != nil {
				t.Fatal(err)
			}
		}
		insert(owner, ids)
		type reference struct {
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
			EventID        string `json:"event_id"`
		}
		foreign := reference{OrganizationID: automaticSourceID(6201), WorkspaceID: automaticSourceID(6202), EnvironmentID: automaticSourceID(6203)}
		pending := func() []reference {
			t.Helper()
			var raw json.RawMessage
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.pending_sources(25)`).Scan(&raw); err != nil {
				t.Fatal("registered pending source query", err)
			}
			var refs []reference
			if json.Unmarshal(raw, &refs) != nil || len(refs) > 25 {
				t.Fatal("unbounded pending result", string(raw))
			}
			for _, r := range refs {
				localScope := r.OrganizationID == o && r.WorkspaceID == w && r.EnvironmentID == e
				foreignScope := r.OrganizationID == foreign.OrganizationID && r.WorkspaceID == foreign.WorkspaceID && r.EnvironmentID == foreign.EnvironmentID
				if (!localScope && !foreignScope) || r.EventID == "" {
					t.Fatal("foreign/invalid source", r)
				}
			}
			return refs
		}
		first := pending()
		if len(first) != 25 {
			t.Fatal("pending prefix", len(first))
		}
		poison := first[0]
		attempt := func(r reference) {
			t.Helper()
			var accepted bool
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.attempt_source($1,$2,$3,$4)`, r.OrganizationID, r.WorkspaceID, r.EnvironmentID, r.EventID).Scan(&accepted); err != nil || !accepted {
				t.Fatal("durable attempt ordering", accepted, err)
			}
		}
		attempt(poison)
		executor.Close(ctx)
		executor = connect()
		next := pending()
		if len(next) != 25 {
			t.Fatal("reconnect lost pending rows", len(next))
		}
		for _, r := range next {
			if r == poison {
				t.Fatal("failed prefix did not rotate across reconnect")
			}
		}
		var queued, accepted int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal77.source_pending),(SELECT count(*) FROM zasp_temporal77.source_acceptances)`).Scan(&queued, &accepted); err != nil || queued != 26 || accepted != 0 {
			t.Fatal("attempt masqueraded as acceptance", queued, accepted, err)
		}
		for _, r := range next {
			attempt(r)
		}
		if again := pending(); len(again) != 25 || again[0] != poison {
			t.Fatal("rotated failure was stranded", again)
		}
		workflowID := "automatic-source/v1/" + o + "/" + w + "/" + e + "/" + poison.EventID
		var ok bool
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.ack_source($1,$2,$3,$4,$5)`, o, w, e, poison.EventID, workflowID+"/foreign").Scan(&ok); err == nil {
			t.Fatal("foreign Workflow identity acknowledged")
		}
		for i := 0; i < 2; i++ {
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.ack_source($1,$2,$3,$4,$5)`, o, w, e, poison.EventID, workflowID).Scan(&ok); err != nil || !ok {
				t.Fatal("exact acceptance/replay", ok, err)
			}
		}
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal77.source_pending),(SELECT count(*) FROM zasp_temporal77.source_acceptances)`).Scan(&queued, &accepted); err != nil || queued != 25 || accepted != 1 {
			t.Fatal("acceptance duplicated/lost source", queued, accepted, err)
		}
		if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		insert(owner, []string{automaticSourceID(6100)})
		var own int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.source_pending`).Scan(&own); err != nil || own != 26 {
			t.Fatal("source lacks atomic pending row", own, err)
		}
		if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.source_pending`).Scan(&own); err != nil || own != 25 {
			t.Fatal("rollback left delivery state", own, err)
		}
		if _, err := api.Exec(ctx, `SELECT zasp_temporal77.pending_sources(25)`); err == nil {
			t.Fatal("API principal acquired global source delivery")
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_temporal75.configure('{"revision":2,"cadence_seconds":1,"enabled":false}')`); err != nil {
			t.Fatal(err)
		}
		if paused := pending(); len(paused) != 0 {
			t.Fatal("paused dispatch released pending sources", len(paused))
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_temporal75.configure('{"revision":3,"cadence_seconds":1,"enabled":true}')`); err != nil {
			t.Fatal(err)
		}
		if resumed := pending(); len(resumed) != 25 {
			t.Fatal("paused source state lost", len(resumed))
		}
		// The relay intentionally enumerates scopes globally, but mutation keys
		// must bind the exact existing tenant. Reuse the finding ID in tenant2.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Automatic source second tenant','automatic-source-second.invalid'); INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Automatic source second workspace'); INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Automatic source staging','staging'); INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Other tenant source','high','open')`, pgx.QueryExecModeSimpleProtocol, foreign.OrganizationID, foreign.WorkspaceID, foreign.EnvironmentID, ids[0]); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE organization_id=$1 AND source_id=$2`, foreign.OrganizationID, ids[0]).Scan(&foreign.EventID); err != nil {
			t.Fatal(err)
		}
		foreignState := func() string {
			t.Helper()
			var state string
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('pending',to_jsonb(p),'acceptances',(SELECT count(*) FROM zasp_temporal77.source_acceptances WHERE organization_id=$1))::text FROM zasp_temporal77.source_pending p WHERE(organization_id,event_id)=($1,$2)`, foreign.OrganizationID, foreign.EventID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			return state
		}
		before := foreignState()
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.attempt_source($1,$2,$3,$4)`, o, w, e, foreign.EventID).Scan(&ok); err == nil {
			t.Fatal("wrong-scope attempt changed foreign pending row")
		}
		wrongWorkflow := "automatic-source/v1/" + o + "/" + w + "/" + e + "/" + foreign.EventID
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.ack_source($1,$2,$3,$4,$5)`, o, w, e, foreign.EventID, wrongWorkflow).Scan(&ok); err == nil {
			t.Fatal("wrong-scope acceptance changed foreign pending row")
		}
		if after := foreignState(); after != before {
			t.Fatal("foreign source delivery mutated", before, after)
		}
		attempt(first[1])
		foundForeign := false
		for _, r := range pending() {
			foundForeign = foundForeign || r == foreign
		}
		if !foundForeign {
			t.Fatal("global relay omitted existing foreign scope")
		}
	})
}
