package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

type graphProofDatabase struct{ conn *pgx.Conn }

func (db graphProofDatabase) QueryJSON(ctx context.Context, s string, a ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := db.conn.QueryRow(ctx, s, a...).Scan(&raw)
	return raw, err
}

// The two services must be disposable. Use the same TLS Neo4j fixture as the
// runtime pipeline, and an installed PostgreSQL DB with the graph login.
func TestInstalledActionEvidenceGraphEndToEnd(t *testing.T) {
	dsn := os.Getenv("ZASP_ACTION_GRAPH_E2E_POSTGRES")
	if dsn == "" {
		t.Skip("paired disposable PostgreSQL and Neo4j services required")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/action_graph_e2e" {
		t.Fatal("disposable local action_graph_e2e database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	graph := newRuntimePipelineGraphFixture(t, ctx)
	connect := func(dsn string) *pgx.Conn {
		t.Helper()
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	db := connect(dsn)
	w := *u
	w.User = url.User("zasp_svc_projection_graph")
	worker := graphProofDatabase{connect(w.String())}
	row := actionGraphExample(t)
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	actionID := strings.Repeat("a", 64)
	seed("INSERT INTO public.zasp_endpoint_observations(organization_id,workspace_id,environment_id,device_id,credential_generation,action_id,observation) VALUES($1,$2,$3,$4,1,$5,jsonb_build_object('observed_at',clock_timestamp(),'verdict','deny','session_ref',$5::text,'local_uid',123))", row.Organization, row.Workspace, row.Environment, row.Fact.Subject, actionID)
	seed("INSERT INTO public.zasp_workload_actions(organization_id,workspace_id,environment_id,credential_id,action_id,principal_id,request,receipt) VALUES($1,$2,$3,$4,'proof','proof_principal','{}',jsonb_build_object('decision_id',$5::text,'verdict','block'))", row.Organization, row.Workspace, row.Environment, row.Fact.Session, row.Fact.Evidence)
	seed("UPDATE public.zasp_workload_actions SET observed_at=clock_timestamp(),outcome='{\"status\":\"not_dispatched\"}' WHERE (organization_id,workspace_id,environment_id,credential_id)=($1,$2,$3,$4)", row.Organization, row.Workspace, row.Environment, row.Fact.Session)
	counts := func() (int, int) {
		t.Helper()
		var total, done int
		if err := db.QueryRow(ctx, "SELECT count(*),count(projected_at) FROM public.zasp_action_graph_evidence WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)", row.Organization, row.Workspace, row.Environment).Scan(&total, &done); err != nil {
			t.Fatal(err)
		}
		return total, done
	}
	if all, done := counts(); all != 3 || done != 0 {
		t.Fatalf("pending %d/%d", done, all)
	}
	opURL := *u
	opURL.User = url.User("zasp_operator")
	operator := connect(opURL.String())
	rebuild := func() {
		t.Helper()
		var n int64
		if e := operator.QueryRow(ctx, "SELECT public.zasp_action_graph_rebuild($1,$2,$3)", row.Organization, row.Workspace, row.Environment).Scan(&n); e != nil || n != 3 {
			t.Fatalf("rebuild %d %v", n, e)
		}
	}
	processor := actionEvidenceGraphProcessor{database: worker, store: &actionGraphSinkFixture{err: errors.New("paused graph")}, limit: 50, leaseSeconds: 60}
	if processor.RunOnce(ctx) == nil {
		t.Fatal("outage acknowledged")
	}
	if _, done := counts(); done != 0 {
		t.Fatal("outage hid lag")
	}
	processor.store = graph
	project := func() {
		t.Helper()
		for i := 0; i < 50; i++ {
			if e := processor.RunOnce(ctx); e != nil {
				t.Fatal("projection", e)
			}
			if _, done := counts(); done == 3 {
				return
			}
		}
		t.Fatal("projection did not drain")
	}
	rebuild()
	project()
	var payload json.RawMessage
	if err := db.QueryRow(ctx, "SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'fact',fact) FROM public.zasp_action_graph_evidence WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND fact->>'source'='signed_endpoint'", row.Organization, row.Workspace, row.Environment).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &row); err != nil {
		t.Fatal(err)
	}
	scope, projection, fact, ok := row.projection()
	if !ok {
		t.Fatal("signed hook receipt missing")
	}
	want := graphstore.ReadRequest{RootID: fact.EvidenceID, Direction: graphstore.DirectionBoth, MaximumDepth: 2, MaximumNodes: 20, MaximumEdges: 20}
	check := func() {
		t.Helper()
		actual, err := graph.Read(ctx, scope, want)
		if err != nil || len(actual.Nodes) != 3 || len(actual.Edges) != 2 {
			t.Fatalf("hook provenance nodes=%d edges=%d err=%v", len(actual.Nodes), len(actual.Edges), err)
		}
	}
	check()
	rebuild()
	project()
	check()
	// The immutable graph metadata is read back during every upsert. An
	// attempted changed verdict must roll back, and exact replay must still pass.
	changed := fact
	changed.Verdict = "continue"
	if graph.UpsertActionEvidence(ctx, scope, projection, changed) == nil || graph.UpsertActionEvidence(ctx, scope, projection, fact) != nil {
		t.Fatal("immutable metadata drift or replay")
	}
	other := actionGraphExample(t)
	foreign, _ := recoveryScope(other.Organization, other.Workspace, other.Environment)
	if got, err := graph.Read(ctx, foreign, want); err != nil || len(got.Nodes) != 0 {
		t.Fatal("cross-environment projection visible", err)
	}
	did, _ := domain.ParseProductID(row.Fact.Subject)
	if did.IsZero() {
		t.Fatal("lost attested device")
	}
}
