package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
	"github.com/zasp-ai/zasp-sec/services/platform/demoseed"
	"github.com/zasp-ai/zasp-sec/services/platform/demoseed/demoseedtest"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// demoRulesNoCollectorProduces are the finding rules of the compliance
// mapping that no collector can produce today, so the demo cannot show
// them: the posture flags behind them (a human credential, a production
// write, an unapproved remote tool, a destructive tool, a CI/CD write that
// reaches production secrets) are declared in the posture model but set by
// no collector, and unrestricted egress and sensitive data reach are set
// by different collectors, never on one agent. skill_scripts_production
// needs a GitHub agent project with production access, which only a
// production Environment gives it; the demo Environment is not one, because
// red team tests are refused there.
var demoRulesNoCollectorProduces = map[string]bool{
	"human_credential": true, "untrusted_production_write": true, "egress_sensitive": true, "unapproved_tool": true,
	"destructive_no_control": true, "cicd_production_secret": true, "skill_scripts_production": true,
}

// serialRevisionReader lets the authorizer's concurrent target checks (a
// collection of more than a few targets is checked by several readers) share
// the harness's one administrative connection.
type serialRevisionReader struct {
	mutex  sync.Mutex
	reader authorization.RevisionReader
}

func (serial *serialRevisionReader) Revision(ctx context.Context, organization string) (authorization.Revision, error) {
	serial.mutex.Lock()
	defer serial.mutex.Unlock()
	return serial.reader.Revision(ctx, organization)
}

// installedDemoMember is the browser session of a member the seeder
// provisioned: the stand-in for that person signing in. The membership and
// the authorized scope are the seeder's; only the session row is the test's.
func installedDemoMember(baseline *installedBaseline, principal, organization, workspace, environment string) installedPrincipal {
	baseline.t.Helper()
	permissions := baseline.text(`SELECT permissions::text FROM zasp_authorized_scopes WHERE (principal_id,organization_id,workspace_id,environment_id)=($1,$2,$3,$4)`, principal, organization, workspace, environment)
	if permissions == "" {
		baseline.t.Fatalf("principal %s has no authorized scope for environment %s", principal, environment)
	}
	var listed []string
	if err := json.Unmarshal([]byte(permissions), &listed); err != nil {
		baseline.t.Fatal(err)
	}
	secret := "demo-session-" + principal + environment
	digest := sha256.Sum256([]byte(secret))
	session := "session-" + strings.ReplaceAll(principal[4:], "-", "")[:16] + strings.ReplaceAll(environment[4:], "-", "")[:16]
	csrf := strings.Repeat("d", 16) + strings.ReplaceAll(environment[4:], "-", "")[:16]
	var authenticated time.Time
	baseline.seed(func() {
		if err := baseline.admin.QueryRow(baseline.ctx, `INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,clock_timestamp(),clock_timestamp()+interval '1 hour') RETURNING authenticated_at`, digest[:], session, principal, organization, workspace, environment, permissions, csrf).Scan(&authenticated); err != nil {
			baseline.t.Fatalf("session: %v", err)
		}
	})
	parse := func(text string) domain.ProductID {
		id, err := domain.ParseProductID(text)
		if err != nil {
			baseline.t.Fatal(err)
		}
		return id
	}
	scope, err := domain.NewScope(parse(organization), parse(workspace), parse(environment))
	if err != nil {
		baseline.t.Fatal(err)
	}
	binding := CredentialBinding{Kind: CredentialBrowserSession, ID: session, Digest: digest}
	identity := RequestIdentity{PrincipalID: parse(principal), Scope: scope, Permissions: listed, CSRFToken: csrf, CredentialKind: CredentialBrowserSession, FreshAuthenticated: true, FreshAuthExpiresAt: authenticated.UTC().Add(5 * time.Minute), credentialBinding: binding}
	return installedPrincipal{identity: identity, binding: binding}
}

// TestDemoSeedOnInstalledBaselinePostgres needs
// ZASP_BASELINE_RELEASE_TEST_DSN (see
// security_agent_remediation_installed_postgres_test.go).
//
// The demo seeder runs on the installed baseline as the migration operator
// (the zasp_operator login), with an in-memory identity provider. What it
// seeded is then read through the product's HTTP handlers as the person it
// was seeded for: every statement of a request runs as the API login inside
// the authorization fence, as in the other tests of this harness. The
// decision of the authorization model is the harness's (a member is
// allowed), which is the one part of the request path that is not in the
// database.
//
// It proves that the person sees the demo's agents, findings, MCP servers,
// attack paths and compliance controls; that every finding rule a collector
// can produce is there; that a member of another Organization sees none of
// it; that a second seeding changes no count; that the demo can also live
// in a workspace of an existing Organization without showing in that
// Organization's own Environment; that an Environment with anything else in
// it is refused; and that removal leaves the other tenant as it was.
func TestDemoSeedOnInstalledBaselinePostgres(t *testing.T) {
	baseline := startInstalledBaseline(t)
	ctx := baseline.ctx
	if err := baseline.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	baseline.authorizer.Reader = &serialRevisionReader{reader: baseline.authorizer.Reader}
	repository, err := NewPostgresRepository(baseline.product)
	if err != nil {
		t.Fatalf("product repository on the installed baseline: %v", err)
	}
	inventoryRepository, err := NewPostgresInventoryRepository(baseline.product)
	if err != nil {
		t.Fatalf("inventory repository: %v", err)
	}
	key := bytes.Repeat([]byte{0x44}, 32)
	inventory, err := newInventoryHTTPHandler(inventoryRepository, key)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := newRiskHTTPHandler(repository, key, nil, FindingTicketCreatorFunc(func(context.Context, FindingTicketCommand) (FindingTicket, error) {
		return FindingTicket{}, ErrRepositoryUnavailable
	}))
	if err != nil {
		t.Fatal(err)
	}
	workflows, err := newWorkflowHTTPHandler(repository, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	compliance, err := NewComplianceReadHandler(ctx, baseline.product, key)
	if err != nil {
		t.Fatalf("compliance reads: %v", err)
	}

	// list reads every page of a collection as a principal.
	list := func(handler http.Handler, principal installedPrincipal, operation, path string) []map[string]any {
		t.Helper()
		var items []map[string]any
		cursor := ""
		for page := 0; page < 20; page++ {
			target := path + "?limit=100"
			if cursor != "" {
				target += "&cursor=" + cursor
			}
			response := baseline.serve(handler, principal, operation, http.MethodGet, target, nil, "", nil)
			if response.Code != http.StatusOK {
				t.Fatalf("%s as %s: %d %s", operation, principal.identity.PrincipalID, response.Code, response.Body.String())
			}
			var body struct {
				Items    []map[string]any `json:"items"`
				PageInfo struct {
					NextCursor *string `json:"next_cursor"`
				} `json:"page_info"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("%s: %v: %s", operation, err, response.Body.String())
			}
			items = append(items, body.Items...)
			if body.PageInfo.NextCursor == nil || *body.PageInfo.NextCursor == "" {
				return items
			}
			cursor = url.QueryEscape(*body.PageInfo.NextCursor)
		}
		t.Fatalf("%s did not end", operation)
		return nil
	}
	type view struct{ agents, findings, servers, paths, integrations int }
	look := func(principal installedPrincipal) view {
		t.Helper()
		return view{
			agents:       len(list(inventory, principal, "listAgents", "/api/v1/agents")),
			findings:     len(list(risk, principal, "listFindings", "/api/v1/findings")),
			servers:      len(list(inventory, principal, "listMCPServers", "/api/v1/mcp-servers")),
			paths:        len(list(risk, principal, "listAttackPaths", "/api/v1/attack-paths")),
			integrations: len(list(workflows, principal, "listIntegrations", "/api/v1/integrations")),
		}
	}

	// The other tenant: the harness's Organization, with a member and an
	// integration of its own in its Production Environment.
	// The harness writes its tenant with triggers off, so its Environment
	// was not given the typed inventory an Environment gets at creation.
	baseline.exec(`SELECT zasp_inventory_backfill_scope($1,$2,$3)`, baseline.o, baseline.w, baseline.e)
	baseline.exec(`SELECT zasp_inventory_cutover_scope($1,$2,$3)`, baseline.o, baseline.w, baseline.e)
	other := baseline.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	otherIntegration := baseline.id()
	baseline.exec(postgresDiscoveryCreateIntegrationSQL, baseline.o, baseline.w, baseline.e, otherIntegration, "aws", "1.0.0", "Production account", `{"external_id_reference":"ref:aws/external-id/other-tenant-0001","region":"us-east-1","role_arn":"arn:aws:iam::444455556666:role/zasp-discovery"}`, "")
	otherRows := func() string {
		t.Helper()
		return baseline.text(`SELECT concat_ws(',',(SELECT count(*) FROM zasp_integrations WHERE organization_id=$1),(SELECT count(*) FROM zasp_inventory_entities WHERE organization_id=$1 AND environment_id=$2),(SELECT count(*) FROM zasp_risk_findings WHERE organization_id=$1 AND environment_id=$2),
 (SELECT count(*) FROM zasp_environments WHERE organization_id=$1 AND id=$2),(SELECT count(*) FROM zasp_authorized_scopes WHERE organization_id=$1 AND environment_id=$2),(SELECT count(*) FROM zasp_identity_memberships WHERE organization_id=$1))`, baseline.o, baseline.e)
	}
	otherBefore, otherViewBefore := otherRows(), look(other)
	if otherViewBefore.agents != 0 {
		t.Fatalf("other tenant before seeding: %+v", otherViewBefore)
	}

	// The seeder, on the operator's own login.
	operator := baseline.login("zasp_operator")
	directory := demoseedtest.NewDirectory()
	var log bytes.Buffer
	seeder, err := demoseed.New(operator, directory.Adapter(t), &log)
	if err != nil {
		t.Fatal(err)
	}
	email := "demo-" + baseline.o[4:12] + "@example.com"
	request := demoseed.Request{Email: email, Dedicated: true, Domain: "demo-" + baseline.o[4:12] + ".example.com", AuthorizationStoreID: installedStore, AuthorizationModelID: installedModel}
	report, err := seeder.Seed(ctx, request)
	if err != nil {
		t.Fatalf("seed: %v\n%s", err, log.String())
	}
	if !report.OrganizationCreated || !report.MemberCreated || !report.Dedicated || directory.Invitations() != 1 || len(report.Integrations) < 11 || report.Agents < 40 || report.Agents > 80 || report.OrganizationName != demoseed.DefaultName {
		t.Fatalf("seed report: %+v, invitations %d", report, directory.Invitations())
	}
	if report.OrganizationID == baseline.o {
		t.Fatal("the demo went into the other tenant")
	}

	// The person the demo was seeded for signs in and reads it.
	person := installedDemoMember(baseline, report.PrincipalID, report.OrganizationID, report.WorkspaceID, report.EnvironmentID)
	seen := look(person)
	if seen.agents != report.Agents || seen.servers != report.MCPServers || seen.paths != report.AttackPaths || seen.integrations != len(report.Integrations) || seen.findings < report.OpenFindings {
		t.Fatalf("the person sees %+v, the seeder reported %+v", seen, report)
	}
	if seen.paths == 0 || seen.servers < 10 {
		t.Fatalf("the demo has %d attack paths and %d MCP servers", seen.paths, seen.servers)
	}
	for _, integration := range list(workflows, person, "listIntegrations", "/api/v1/integrations") {
		if name, _ := integration["name"].(string); !strings.HasPrefix(name, "Demo: ") {
			t.Fatalf("integration without the demo prefix: %v", integration)
		}
	}
	// Where every agent lives, which integration found it and, where the
	// provider says so, who created it. Nobody has assigned an owner in the
	// demo, so the creator is the suggested owner, and the team is the one a
	// label names or the creator's department in the demo's Okta tenant.
	attributed := map[string]InventoryAttribution{}
	creators := 0
	for _, agent := range list(inventory, person, "listAgents", "/api/v1/agents") {
		raw, _ := json.Marshal(agent["attribution"])
		var attribution InventoryAttribution
		if err := decodeStrictInventory(raw, &attribution); err != nil {
			t.Fatalf("agent %v: attribution %s: %v", agent["name"], raw, err)
		}
		if attribution.Location == nil || attribution.Integration == nil || !strings.HasPrefix(attribution.Integration.Name, "Demo: ") {
			t.Fatalf("agent %v has no location or integration: %s", agent["name"], raw)
		}
		if agent["owner"] != "" || (attribution.Creator == nil) != (attribution.SuggestedOwner == nil) {
			t.Fatalf("agent %v: owner %v, attribution %s", agent["name"], agent["owner"], raw)
		}
		if attribution.Creator != nil {
			creators++
		}
		attributed[agent["name"].(string)] = attribution
	}
	if creators < 8 {
		t.Fatalf("%d demo agents have a creator", creators)
	}
	created := "2026-10-02T09:41:30Z"
	planner := attributed["warehouse-routing-planner"]
	if planner.Location == nil || *planner.Location != (InventoryLocation{Kind: "aws_account", ID: "111122223333", Label: "111122223333"}) || planner.Integration.Name != "Demo: AWS production account" ||
		planner.Creator == nil || planner.Creator.Identity != "priya.raman@example.com" || planner.Creator.Source != "cloudtrail" || planner.Creator.CreatedAt == nil || *planner.Creator.CreatedAt != created ||
		*planner.SuggestedOwner != (InventorySuggestion{Value: "priya.raman@example.com", Source: "cloudtrail"}) || planner.SuggestedTeam == nil || *planner.SuggestedTeam != (InventorySuggestion{Value: "Platform Engineering", Source: "okta"}) {
		t.Fatalf("warehouse-routing-planner: %+v", planner)
	}
	if checkout := attributed["prod/checkout-assistant"]; checkout.Location == nil || checkout.Location.Kind != "kubernetes_namespace" || !strings.HasSuffix(checkout.Location.ID, "/prod") || checkout.Creator == nil || checkout.Creator.Source != "annotation" ||
		checkout.SuggestedTeam == nil || *checkout.SuggestedTeam != (InventorySuggestion{Value: "checkout", Source: "label"}) {
		t.Fatalf("prod/checkout-assistant: %+v", checkout)
	}
	if service := attributed["Customer service agent"]; service.Location == nil || *service.Location != (InventoryLocation{Kind: "salesforce_org", ID: "00D8a000001NwRbEAK", Label: "Northwind Robotics"}) || service.Creator == nil || service.Creator.Source != "provider_record" ||
		service.SuggestedTeam == nil || service.SuggestedTeam.Value != "Customer Support Engineering" {
		t.Fatalf("Customer service agent: %+v", service)
	}
	if copilot := attributed["northwind-robotics/warehouse-copilot"]; copilot.Location == nil || *copilot.Location != (InventoryLocation{Kind: "github_repository", ID: "northwind-robotics/warehouse-copilot", Label: "northwind-robotics/warehouse-copilot"}) ||
		copilot.Creator == nil || copilot.Creator.Source != "codeowners" || copilot.Creator.CreatedAt != nil || copilot.SuggestedTeam != nil {
		t.Fatalf("warehouse-copilot: %+v", copilot)
	}
	// An agent whose provider says nothing has a location and no creator.
	if legacy := attributed["legacy-pricing-bot"]; legacy.Location == nil || legacy.Creator != nil || legacy.SuggestedOwner != nil || legacy.SuggestedTeam != nil {
		t.Fatalf("legacy-pricing-bot: %+v", legacy)
	}
	// Every rule of the compliance mapping a collector can produce fires,
	// and no rule fires that the mapping does not know. ownerless_agent is
	// among them: a suggested owner is not an assigned one.
	fired := map[string]bool{}
	for _, finding := range list(risk, person, "listFindings", "/api/v1/findings") {
		rule, _ := finding["rule"].(string)
		fired[rule] = true
	}
	var missing, unexpected []string
	for _, rule := range compliancemap.Rules() {
		if !fired[rule] && !demoRulesNoCollectorProduces[rule] {
			missing = append(missing, rule)
		}
		if fired[rule] && demoRulesNoCollectorProduces[rule] {
			unexpected = append(unexpected, rule)
		}
	}
	sort.Strings(missing)
	if !fired["ownerless_agent"] {
		t.Fatal("ownerless_agent does not fire in a demo where no owner is assigned")
	}
	if len(missing) != 0 || len(unexpected) != 0 {
		t.Fatalf("rules that do not fire: %v; rules listed as unreachable that fire: %v", missing, unexpected)
	}
	// Compliance: the controls are readable and the AI frameworks carry
	// findings.
	controls := baseline.serve(compliance, person, "listComplianceControls", http.MethodGet, "/api/v1/compliance/controls", nil, "", map[string]string{"Cookie": browserSessionCookie + "=demo-session-" + report.PrincipalID + report.EnvironmentID})
	if controls.Code != http.StatusOK || !bytes.Contains(controls.Body.Bytes(), []byte(`"items"`)) {
		t.Fatalf("compliance controls: %d %s", controls.Code, controls.Body.String())
	}
	if frameworks := baseline.text(`SELECT count(DISTINCT framework)::text FROM zasp_compliance_ai_rule_controls() control JOIN zasp_risk_findings finding ON finding.rule=control.rule WHERE (finding.organization_id,finding.workspace_id,finding.environment_id)=($1,$2,$3) AND finding.status='open'`, report.OrganizationID, report.WorkspaceID, report.EnvironmentID); frameworks != "6" {
		t.Fatalf("AI frameworks with open demo findings = %s", frameworks)
	}

	// The other tenant sees none of it and lost nothing.
	if after := look(other); after != otherViewBefore || otherRows() != otherBefore {
		t.Fatalf("the other tenant changed: view %+v rows %s (before %+v %s)", after, otherRows(), otherViewBefore, otherBefore)
	}

	// A second seeding refreshes: the same counts, no second invitation, no
	// second Organization, and no projection work left for a worker.
	again, err := seeder.Seed(ctx, request)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if again.OrganizationCreated || again.MemberCreated || directory.Invitations() != 1 || again.OrganizationID != report.OrganizationID || again.EnvironmentID != report.EnvironmentID ||
		again.Agents != report.Agents || again.OpenFindings != report.OpenFindings || again.MCPServers != report.MCPServers || again.AttackPaths != report.AttackPaths || len(again.Extras) != 0 {
		t.Fatalf("second seed: %+v\nfirst: %+v", again, report)
	}
	if refreshed := look(person); refreshed != seen {
		t.Fatalf("after the second seeding the person sees %+v, before %+v", refreshed, seen)
	}
	if pending := baseline.text(`SELECT count(*)::text FROM zasp_projection_work WHERE organization_id=$1 AND state NOT IN('cancelled','succeeded')`, report.OrganizationID); pending != "0" {
		t.Fatalf("%s projection work rows are left for the workers", pending)
	}
	if outbox := baseline.text(`SELECT count(*)::text FROM zasp_discovery_outbox WHERE organization_id=$1`, report.OrganizationID); outbox != "0" {
		t.Fatalf("%s discovery outbox events were queued for the workers", outbox)
	}

	// The demo inside an existing Organization: the other tenant's member
	// gets a workspace of its own there. Its Production Environment shows
	// none of it.
	otherEmail := "member-" + baseline.o[4:12] + "@example.com"
	directory.AddMember("organization-"+baseline.o[4:12], otherEmail, "member-"+other.identity.PrincipalID.String()[4:12])
	inside, err := seeder.Seed(ctx, demoseed.Request{Email: otherEmail, ExistingOrganizationID: baseline.o, Providers: []string{"aws", "kubernetes"}})
	if err != nil {
		t.Fatalf("seed into the existing organization: %v", err)
	}
	if inside.Dedicated || inside.OrganizationID != baseline.o || inside.EnvironmentID == baseline.e || inside.WorkspaceID == baseline.w || inside.PrincipalID != other.identity.PrincipalID.String() || inside.EnvironmentName != demoseed.DefaultExistingEnvironment || directory.Invitations() != 1 {
		t.Fatalf("seed into the existing organization: %+v", inside)
	}
	if production := look(other); production != otherViewBefore {
		t.Fatalf("the organization's own environment shows the demo: %+v", production)
	}
	insideMember := installedDemoMember(baseline, inside.PrincipalID, inside.OrganizationID, inside.WorkspaceID, inside.EnvironmentID)
	if view := look(insideMember); view.agents != inside.Agents || view.agents == 0 || view.integrations != 2 {
		t.Fatalf("the member sees %+v in the demo environment, the seeder reported %+v", view, inside)
	}
	// Somebody who is not a member of the Organization is refused, and
	// nothing is created for them.
	if _, err := seeder.Seed(ctx, demoseed.Request{Email: "stranger@example.com", ExistingOrganizationID: baseline.o}); !errors.Is(err, demoseed.ErrNotMember) || directory.Invitations() != 1 {
		t.Fatalf("a stranger was seeded into an existing organization: %v", err)
	}
	// The Organization's own Environment is never a demo Environment.
	if _, err := seeder.Seed(ctx, demoseed.Request{Email: otherEmail, ExistingOrganizationID: baseline.o, Workspace: "Default", Environment: "Production"}); !errors.Is(err, demoseed.ErrNotDemo) {
		t.Fatalf("seeding into the production environment: %v", err)
	}

	// An Environment that holds anything but demo integrations is refused
	// by seed and by remove, untouched.
	foreign := baseline.id()
	baseline.exec(postgresDiscoveryCreateIntegrationSQL, inside.OrganizationID, inside.WorkspaceID, inside.EnvironmentID, foreign, "aws", "1.0.0", "Somebody's own account", `{"external_id_reference":"ref:aws/external-id/other-tenant-0002","region":"us-east-1","role_arn":"arn:aws:iam::444455556666:role/zasp-discovery"}`, "")
	if _, err := seeder.Seed(ctx, demoseed.Request{Email: otherEmail, ExistingOrganizationID: baseline.o}); !errors.Is(err, demoseed.ErrNotDemo) {
		t.Fatalf("seeding an environment with a foreign integration: %v", err)
	}
	if _, err := seeder.Remove(ctx, ""); !errors.Is(err, demoseed.ErrNotDemo) {
		t.Fatalf("removing an environment with a foreign integration: %v", err)
	}
	if still := look(person); still != seen {
		t.Fatalf("a refused removal changed the dedicated demo: %+v", still)
	}
	baseline.exec(`DELETE FROM zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, inside.OrganizationID, inside.WorkspaceID, inside.EnvironmentID, foreign)

	// Status lists the two demo scopes of this run.
	scopes, err := seeder.Status(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]demoseed.ScopeStatus{}
	for _, scope := range scopes {
		listed[scope.EnvironmentID] = scope
	}
	if listed[report.EnvironmentID].Agents != report.Agents || listed[inside.EnvironmentID].Agents != inside.Agents || listed[report.EnvironmentID].Members != 1 {
		t.Fatalf("status: %+v", scopes)
	}

	// Removal: both demo scopes of this run go, and the other tenant keeps
	// its Organization, its Environment, its member and its integration.
	for _, organization := range []string{report.OrganizationID, baseline.o} {
		removals, err := seeder.Remove(ctx, organization)
		if err != nil || len(removals) != 1 || !removals[0].EnvironmentDeleted || !removals[0].WorkspaceDeleted || removals[0].OrganizationDeleted {
			t.Fatalf("remove the demo of %s: %+v %v", organization, removals, err)
		}
		// What the database keeps is the retired entity rows, nothing else.
		for table, rows := range removals[0].Remaining {
			if table != "zasp_inventory_entities" && table != "zasp_inventory_identity_bindings" || rows == 0 {
				t.Fatalf("remove left %d rows in %s", rows, table)
			}
		}
	}
	for _, gone := range []struct{ organization, workspace, environment string }{{report.OrganizationID, report.WorkspaceID, report.EnvironmentID}, {inside.OrganizationID, inside.WorkspaceID, inside.EnvironmentID}} {
		left := baseline.text(`SELECT concat_ws(',',(SELECT count(*) FROM zasp_environments WHERE organization_id=$1 AND id=$3),(SELECT count(*) FROM zasp_workspaces WHERE id=$2),(SELECT count(*) FROM zasp_integrations WHERE environment_id=$3),(SELECT count(*) FROM zasp_risk_findings WHERE environment_id=$3),
 (SELECT count(*) FROM zasp_authorized_scopes WHERE environment_id=$3),(SELECT count(*) FROM zasp_inventory_relationships WHERE environment_id=$3),(SELECT count(*) FROM zasp_inventory_entities WHERE environment_id=$3 AND state<>'tombstoned'),(SELECT count(*) FROM zasp_mcp_registry WHERE environment_id=$3))`, gone.organization, gone.workspace, gone.environment)
		if left != "0,0,0,0,0,0,0,0" {
			t.Fatalf("after removal, environment %s still has %s", gone.environment, left)
		}
	}
	// The dedicated Organization's record is kept, empty, because the
	// permission projection of this installation refers to it. A later
	// seeding uses it again and a later removal empties it again.
	if kept := baseline.text(`SELECT concat_ws(',',(SELECT count(*) FROM zasp_organizations WHERE id=$1),(SELECT count(*) FROM zasp_environments WHERE organization_id=$1))`, report.OrganizationID); kept != "1,0" {
		t.Fatalf("the dedicated organization after removal: %s", kept)
	}
	reseeded, err := seeder.Seed(ctx, demoseed.Request{Email: email, Dedicated: true, Domain: request.Domain, Providers: []string{"aws"}, AuthorizationStoreID: installedStore, AuthorizationModelID: installedModel})
	if err != nil || reseeded.OrganizationID != report.OrganizationID || reseeded.EnvironmentID == report.EnvironmentID || reseeded.PrincipalID != report.PrincipalID || reseeded.Agents == 0 || directory.Invitations() != 1 {
		t.Fatalf("seeding again after a removal: %+v %v", reseeded, err)
	}
	if removals, err := seeder.Remove(ctx, report.OrganizationID); err != nil || len(removals) != 1 || !removals[0].EnvironmentDeleted {
		t.Fatalf("second removal: %+v %v", removals, err)
	}
	if after := look(other); after != otherViewBefore || otherRows() != otherBefore {
		t.Fatalf("removal changed the other tenant: view %+v rows %s (before %+v %s)", after, otherRows(), otherViewBefore, otherBefore)
	}
	if scopes, err := seeder.Status(ctx, baseline.o); err != nil || len(scopes) != 0 {
		t.Fatalf("status after removal: %+v %v", scopes, err)
	}
	// The person's session no longer opens anything.
	if _, err := baseline.checked(person, RoutedOperation{OperationID: "listAgents", PathParameters: map[string]string{}}); err == nil {
		response := baseline.serve(inventory, person, "listAgents", http.MethodGet, "/api/v1/agents?limit=100", nil, "", nil)
		if response.Code == http.StatusOK && !bytes.Contains(response.Body.Bytes(), []byte(`"items":[]`)) {
			t.Fatalf("after removal the person still reads agents: %s", response.Body.String())
		}
	}
}
