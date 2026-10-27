package apiserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Observe the immediate grant through the same registered outbox snapshot used
// by production. A direct bootstrap query of the view is a separate RLS case:
// view-owner permission checks do not change SQL current_user expressions.
// Neither observation projects tuples or acknowledges a revision.
func assertApprovalImmediateProjection(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run string, active bool) {
	t.Helper()
	var rawVisible, permissionContext bool
	if err := owner.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM zasp_approval_maintenance.delivery_grants WHERE organization_id=$1),
 current_user<>'zasp_discovery_authority'
 AND EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.oid='zasp_approval_maintenance.delivery_grants'::regclass AND r.rolname='zasp_discovery_authority' AND NOT(r.rolsuper OR r.rolbypassrls))
 AND EXISTS(SELECT 1 FROM pg_class c JOIN pg_policy p ON p.polrelid=c.oid WHERE c.oid='zasp_authorization79.organizations'::regclass AND c.relrowsecurity AND c.relforcerowsecurity AND p.polname='authority' AND pg_get_expr(p.polqual,p.polrelid) LIKE '%CURRENT_USER%zasp_discovery_authority%')`, o).Scan(&rawVisible, &permissionContext); err != nil {
		t.Fatal("immediate approval raw-view permission observation unavailable")
	}
	if !permissionContext || rawVisible {
		t.Fatal("bootstrap raw-view permission boundary changed")
	}
	var originsJSON []byte
	if err := owner.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('principal_id',delegation->>'principal_id','task_id',delegation->>'task_id','checks',facts->'checks')) FROM zasp_approval_maintenance.origins WHERE(organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&originsJSON); err != nil {
		t.Fatal("immediate approval origin unavailable")
	}
	var origins []struct {
		PrincipalID string `json:"principal_id"`
		TaskID      string `json:"task_id"`
		Checks      []struct {
			Kind       string `json:"kind"`
			ID         string `json:"id"`
			Permission string `json:"permission"`
		} `json:"checks"`
	}
	if json.Unmarshal(originsJSON, &origins) != nil || len(origins) != 1 || len(origins[0].Checks) < 2 || len(origins[0].Checks) > 128 {
		t.Fatal("immediate approval origin cardinality changed")
	}
	origin := origins[0]
	for _, id := range []string{o, w, e, run, origin.PrincipalID, origin.TaskID} {
		if _, err := domain.ParseProductID(id); err != nil {
			t.Fatal("immediate approval identity invalid")
		}
	}
	expected := make([]authorization.ProjectionGrant, 0, len(origin.Checks))
	for _, check := range origin.Checks {
		expected = append(expected, authorization.ProjectionGrant{
			ProjectionResource: authorization.ProjectionResource{ProjectionScope: authorization.ProjectionScope{OrganizationID: o, WorkspaceID: w, EnvironmentID: e}, Kind: check.Kind, ID: check.ID},
			PrincipalKind:      "service", PrincipalID: origin.PrincipalID, TaskID: origin.TaskID, Permission: check.Permission,
		})
	}
	var outbox string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM public.zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
		t.Fatal("registered approval projection principal unavailable")
	}
	cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
	if err != nil {
		t.Fatal("approval projection connection unavailable")
	}
	cfg.ConnConfig.User, cfg.MaxConns = outbox, 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("approval projection pool unavailable")
	}
	defer pool.Close()
	connectorPin := ""
	if active {
		connectorPin, err = migrations.ConnectorMaintenanceProfileChecksum()
		if err != nil {
			t.Fatal("approval projection connector pin unavailable")
		}
	}
	projection, err := authorization.NewCurrentMaintenanceProjectionRepository(ctx, pool, migrations.ApprovalMaintenanceProfileChecksum(), connectorPin)
	if err != nil {
		t.Fatal("current approval projection selector refused")
	}
	readRevision := func() authorization.Revision {
		t.Helper()
		var revision authorization.Revision
		if err := owner.QueryRow(ctx, `SELECT organization_id,desired,applied,generation,store_id,model_id FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&revision.OrganizationID, &revision.Desired, &revision.Applied, &revision.Generation, &revision.StoreID, &revision.ModelID); err != nil {
			t.Fatal("immediate approval revision unavailable")
		}
		return revision
	}
	if err := projection.WithOrganization(ctx, o, func(session authorization.ProjectionSession) error {
		before := readRevision()
		snapshot, err := session.Snapshot(ctx)
		if err != nil {
			return err
		}
		if snapshot.Revision != before || readRevision() != before {
			t.Fatal("approval grant observation changed projection revision")
		}
		if !approvalImmediateGrantSetMatches(expected, snapshot.Grants, active) {
			t.Fatal("immediate production approval grant set mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal("immediate production approval snapshot refused")
	}
}

func approvalImmediateGrantSetMatches(expected, actual []authorization.ProjectionGrant, active bool) bool {
	if len(expected) < 2 || len(expected) > 128 {
		return false
	}
	base := expected[0]
	task := base.TaskID
	want := make(map[authorization.ProjectionGrant]bool, len(expected))
	for _, grant := range expected {
		if grant.TaskID == "" || grant.TaskID != task || grant.PrincipalKind != "service" || grant.PrincipalID == "" || grant.PrincipalID != base.PrincipalID || grant.Permission == "" || grant.Kind == "" || grant.ID == "" || grant.OrganizationID == "" || grant.ProjectionScope != base.ProjectionScope || grant.WorkspaceID == "" || grant.EnvironmentID == "" || want[grant] {
			return false
		}
		want[grant] = true
	}
	seen := make(map[authorization.ProjectionGrant]bool, len(expected))
	for _, grant := range actual {
		if grant.TaskID != task {
			continue
		}
		if !active || !want[grant] || seen[grant] {
			return false
		}
		seen[grant] = true
	}
	return !active || len(seen) == len(want)
}

func TestApprovalImmediateGrantSetPermissionCases(t *testing.T) {
	base := authorization.ProjectionGrant{ProjectionResource: authorization.ProjectionResource{ProjectionScope: authorization.ProjectionScope{OrganizationID: "org", WorkspaceID: "workspace", EnvironmentID: "environment"}, Kind: "security_agent", ID: "definition"}, PrincipalKind: "service", PrincipalID: "delivery", TaskID: "notification", Permission: "manage_workflows"}
	run := base
	run.Kind, run.ID = "security_agent_run", "run"
	expected := []authorization.ProjectionGrant{base, run}
	if !approvalImmediateGrantSetMatches(expected, expected, true) || !approvalImmediateGrantSetMatches(expected, nil, false) {
		t.Fatal("exact active or inactive grant set refused")
	}
	other := base
	other.TaskID = "another-task"
	if !approvalImmediateGrantSetMatches(expected, append([]authorization.ProjectionGrant{other}, expected...), true) {
		t.Fatal("independent task grant changed exact task comparison")
	}
	for _, mutate := range []func(*authorization.ProjectionGrant){
		func(g *authorization.ProjectionGrant) { g.OrganizationID = "foreign" },
		func(g *authorization.ProjectionGrant) { g.WorkspaceID = "foreign" },
		func(g *authorization.ProjectionGrant) { g.EnvironmentID = "foreign" },
		func(g *authorization.ProjectionGrant) { g.PrincipalKind = "user" },
		func(g *authorization.ProjectionGrant) { g.PrincipalID = "foreign" },
		func(g *authorization.ProjectionGrant) { g.Kind = "integration" },
		func(g *authorization.ProjectionGrant) { g.ID = "foreign" },
		func(g *authorization.ProjectionGrant) { g.Permission = "manage_identity" },
	} {
		extra := base
		mutate(&extra)
		if approvalImmediateGrantSetMatches(expected, append(append([]authorization.ProjectionGrant{}, expected...), extra), true) {
			t.Fatal("same-task foreign or widened grant accepted")
		}
	}
	if approvalImmediateGrantSetMatches(expected, expected[:1], true) || approvalImmediateGrantSetMatches(expected, append(append([]authorization.ProjectionGrant{}, expected...), base), true) || approvalImmediateGrantSetMatches(expected, expected, false) || approvalImmediateGrantSetMatches([]authorization.ProjectionGrant{base, base}, expected, true) || approvalImmediateGrantSetMatches(expected[:1], expected, true) {
		t.Fatal("missing, duplicate, inactive or malformed grant set accepted")
	}
	foreign := run
	foreign.OrganizationID = "foreign"
	if approvalImmediateGrantSetMatches([]authorization.ProjectionGrant{base, foreign}, []authorization.ProjectionGrant{base, foreign}, true) {
		t.Fatal("inconsistent expected grant scope accepted")
	}
}
