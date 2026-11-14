package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// TestRedTeamRouterAdmitsStandaloneRunsOnInstalledBaselinePostgres needs
// ZASP_BASELINE_RELEASE_TEST_DSN, and the apiserver test
// TestRedTeamStandaloneRunOnInstalledBaselinePostgres to have run on that
// database first: it leaves completion.sql sections WS2a to WS2f installed,
// finished standalone runs and one queued run that is a linked test step.
//
// The production router of the red team worker, built for the worker login,
// sees the linked authority installed, routes a standalone run to the worker
// functions, and still refuses to treat a linked run as standalone.
func TestRedTeamRouterAdmitsStandaloneRunsOnInstalledBaselinePostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_BASELINE_RELEASE_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_BASELINE_RELEASE_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, config.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var o, w, e, standaloneRun, linkedRun string
	if err := admin.QueryRow(ctx, `SELECT r.organization_id,r.workspace_id,r.environment_id,r.run_id,l.test_run_id FROM zasp_red_team_runs r JOIN zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id)
 WHERE r.state='complete' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_links x WHERE x.test_run_id=r.run_id) AND EXISTS(SELECT 1 FROM zasp_red_team_probe_results p WHERE p.run_id=r.run_id) ORDER BY r.queued_at DESC LIMIT 1`).Scan(&o, &w, &e, &standaloneRun, &linkedRun); err != nil {
		t.Skipf("run TestRedTeamStandaloneRunOnInstalledBaselinePostgres on this database first: %v", err)
	}
	config.ConnConfig.User = "zasp_svc_red_team_worker"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRoutedRedTeamAuthority(db)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	if !router.installedLinked || !router.standaloneInstalled || router.legacy == nil || router.Ready(ctx) != nil || router.ReadyArtifacts(ctx) != nil {
		t.Fatalf("router installedLinked=%t standalone=%t ready=%v", router.installedLinked, router.standaloneInstalled, router.Ready(ctx))
	}
	organization, _ := domain.ParseProductID(o)
	workspace, _ := domain.ParseProductID(w)
	environment, _ := domain.ParseProductID(e)
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	if protocol, err := router.protocol(ctx, scope, standaloneRun); err != nil || protocol != "legacy" {
		t.Fatalf("standalone run protocol=%q err=%v", protocol, err)
	}
	// The run is finished, so the routed claim reaches the worker function and
	// reports it terminal instead of failing to classify it.
	if claim, err := router.ClaimRedTeamRun(ctx, scope, standaloneRun, "probe-worker", strings.Repeat("e", 32), 60); err != nil || claim.Disposition != "ack_terminal" {
		t.Fatalf("routed claim of a finished standalone run: %+v %v", claim, err)
	}
	// The linked run of that tenant is a fabricated link without a Security
	// Agent parent: the installed authority refuses it and the router does not
	// fall back to the standalone path.
	if protocol, err := router.protocol(ctx, scope, linkedRun); err == nil {
		t.Fatalf("a linked run without a parent was routed as %q", protocol)
	}
	if claim, err := router.ClaimRedTeamRun(ctx, scope, linkedRun, "probe-worker", strings.Repeat("e", 32), 60); err == nil {
		t.Fatalf("a linked run was claimed through the router: %+v", claim)
	}
	// Without the standalone authority the router behaves as before: only
	// linked runs.
	router.standaloneInstalled = false
	if protocol, err := router.protocol(ctx, scope, standaloneRun); err == nil {
		t.Fatalf("a standalone run was routed as %q without the standalone authority", protocol)
	}
}
