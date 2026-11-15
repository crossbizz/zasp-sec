package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// TestInventoryAttributionSectionOnTheInstalledBaselinePostgres applies
// completion.sql section WS11 to the installed released baseline, twice, and
// exercises what it adds:
//
//   - the inventory detail and page both call zasp_inventory_attribution, and
//     a second run of the section changes no function;
//   - the location of an object is read from the stable fields of its winning
//     observation, for every provider, and a tenant with an opaque identifier
//     is labelled with the provider's name for it;
//   - the integration is named;
//   - an agent's creator is what the collector recorded, and a creator that
//     is not an identity, has no known source or sits on something that is
//     not an agent is not shown;
//   - a suggested owner and team exist only while no person assigned one; the
//     team is the label's, otherwise the department of the Okta user of the
//     same Environment with the creator's address, and never one of another
//     Environment;
//   - ownerless_agent keeps firing for an agent that has only a suggestion,
//     and is resolved once a person assigns an owner.
func TestInventoryAttributionSectionOnTheInstalledBaselinePostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	connection := installedBaselineConnection(t, ctx)
	definitions := func() string {
		t.Helper()
		var functions, indexes string
		if err := connection.QueryRow(ctx, `SELECT
 (SELECT md5(string_agg(pg_get_functiondef(p.oid),'' ORDER BY p.oid::regprocedure::text)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prokind='f' AND (n.nspname LIKE 'zasp%' OR n.nspname='public')),
 (SELECT md5(string_agg(indexdef,'' ORDER BY indexname)) FROM pg_indexes WHERE schemaname='public')`).Scan(&functions, &indexes); err != nil {
			t.Fatal(err)
		}
		return functions + indexes
	}
	applyCompletionBlock(t, ctx, connection, "inventory_attribution")
	first := definitions()
	applyCompletionBlock(t, ctx, connection, "inventory_attribution")
	if definitions() != first {
		t.Fatal("a second run of section WS11 changed a function or an index")
	}
	var detail, page, indexes int
	if err := connection.QueryRow(ctx, `SELECT
 (length(pg_get_functiondef('public.zasp_inventory_detail(text,text,text,text,text)'::regprocedure))-length(replace(pg_get_functiondef('public.zasp_inventory_detail(text,text,text,text,text)'::regprocedure),'zasp_inventory_attribution(','')))/length('zasp_inventory_attribution('),
 (length(pg_get_functiondef('public.zasp_inventory_page(text,text,text,text,text,integer)'::regprocedure))-length(replace(pg_get_functiondef('public.zasp_inventory_page(text,text,text,text,text,integer)'::regprocedure),'zasp_inventory_attribution(','')))/length('zasp_inventory_attribution('),
 (SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND indexname IN('zasp_inventory_observations_tenant_ws11_idx','zasp_inventory_observations_person_ws11_idx'))`).Scan(&detail, &page, &indexes); err != nil || detail != 1 || page != 1 || indexes != 2 {
		t.Fatalf("attribution calls: detail=%d page=%d indexes=%d err=%v", detail, page, indexes, err)
	}

	id := func() string {
		t.Helper()
		value, err := domain.NewProductID()
		if err != nil {
			t.Fatal(err)
		}
		return value.String()
	}
	o, w, e, other := id(), id(), id(), id()
	seed, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Rollback(context.Background())
	exec := func(statement string, arguments ...any) {
		t.Helper()
		if _, err := seed.Exec(ctx, statement, arguments...); err != nil {
			t.Fatalf("seed %.70s: %v", statement, err)
		}
	}
	exec(`SET LOCAL session_replication_role=replica`)
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Attribution tenant',$2)`, o, "attribution-"+o[4:12]+".invalid")
	exec(`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Attribution workspace')`, w, o)
	for _, environment := range []string{e, other} {
		exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,$4,'staging')`, o, w, environment, "Attribution "+environment[4:12])
	}
	integrations := map[string]string{}
	integration := func(environment, provider, name string) string {
		t.Helper()
		key := environment + "/" + name
		if known, seen := integrations[key]; seen {
			return known
		}
		integrationID := id()
		exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,state) VALUES($1,$2,$3,$4,$5,'v1',$6,'active')`, o, w, environment, integrationID, provider, name)
		integrations[key] = integrationID
		return integrationID
	}
	// observe records one observation the way a collection leaves it. Only
	// the columns the attribution reads matter here.
	observe := func(environment, provider, integrationName, sourceKind, productKind, display, stable, attributes string) (entity, integrationID string) {
		t.Helper()
		entity, integrationID = id(), integration(environment, provider, integrationName)
		exec(`INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'present',$9::jsonb,now()-interval '1 minute',now()-interval '1 minute',$5,$10,$11,$12::jsonb,$10,$13,1,decode(repeat('ab',32),'hex'),$14,9500,now()-interval '1 minute',now()+interval '1 hour',1,80,1)`,
			o, w, environment, integrationID, provider, entity, sourceKind+":"+entity, id(), attributes, sourceKind, display, stable, productKind, id())
		return entity, integrationID
	}
	attribution := func(environment, entity, kind, integrationID, provider, attributes, annotation string) InventoryAttribution {
		t.Helper()
		var raw []byte
		if err := seed.QueryRow(ctx, `SELECT public.zasp_inventory_attribution($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb)`, o, w, environment, entity, kind, integrationID, provider, attributes, annotation).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Attribution *InventoryAttribution `json:"attribution"`
		}
		if err := decodeStrictInventory(raw, &envelope); err != nil || envelope.Attribution == nil {
			t.Fatalf("attribution = %s (%v)", raw, err)
		}
		// What the function returns is what the API accepts for the kind.
		summary := InventorySummary{Attribution: envelope.Attribution}
		var stored struct{ Owner, Team string }
		_ = json.Unmarshal([]byte(annotation), &stored)
		summary.Owner, summary.Team = stored.Owner, stored.Team
		if !validInventoryAttribution(summary, InventoryKind(kind)) {
			t.Fatalf("the API refuses this attribution: %s", raw)
		}
		return *envelope.Attribution
	}
	const unassigned = `{"owner":"","team":"","tags":[]}`

	// Location, per provider, from the stable fields of the observation.
	for name, test := range map[string]struct {
		provider, sourceKind, stable string
		kind, locationID, label      string
	}{
		"an AWS agent":                   {"aws", "aws_bedrock_agent", `{"account_id":"123456789012","agent_id":"A1","arn":"arn:aws:bedrock:us-east-1:123456789012:agent/A1","name":"a","region":"us-east-1"}`, "aws_account", "123456789012", "123456789012"},
		"a Google Cloud agent":           {"gcp", "gcp_agent_engine", `{"location":"us-central1","name":"a","object_type":"reasoning_engine","project":"prod-ml","scope":"organizations/42"}`, "gcp_project", "prod-ml", "prod-ml"},
		"a Google Cloud scope":           {"gcp", "gcp_scope", `{"name":"organizations/42","scope":"organizations/42"}`, "gcp_scope", "organizations/42", "organizations/42"},
		"a GitHub agent project":         {"github", "github_agent_project", `{"installation_id":9001,"name":"acme/alpha","owner":"acme","repository":"alpha"}`, "github_repository", "acme/alpha", "acme/alpha"},
		"a GitHub organization":          {"github", "github_organization", `{"installation_id":9001,"name":"acme","owner":"acme"}`, "github_organization", "acme", "acme"},
		"a Kubernetes workload":          {"kubernetes", "kubernetes_agent", `{"api_group":"apps","api_version":"v1","cluster":"prod-us","name":"bot","namespace":"support","resource_kind":"Deployment","service_account":"bot"}`, "kubernetes_namespace", "prod-us/support", "prod-us/support"},
		"a Kubernetes cluster role":      {"kubernetes", "kubernetes_cluster_role", `{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"prod-us","name":"admin","resource_kind":"ClusterRole","scope":"cluster"}`, "kubernetes_cluster", "prod-us", "prod-us"},
		"an Azure AI resource":           {"microsoft", "microsoft_ai_resource", `{"name":"r","object_type":"account","region":"eastus","subscription":"0f000000-0000-4000-8000-000000000001","tenant":"1f000000-0000-4000-8000-000000000001"}`, "microsoft_subscription", "0f000000-0000-4000-8000-000000000001", "0f000000-0000-4000-8000-000000000001"},
		"a Copilot Studio agent":         {"microsoft", "microsoft_copilot_agent", `{"environment":"org1234.crm.dynamics.com","name":"a","object_type":"copilot_studio_agent","tenant":"1f000000-0000-4000-8000-000000000001"}`, "power_platform_environment", "org1234.crm.dynamics.com", "org1234.crm.dynamics.com"},
		"an Okta application":            {"okta", "okta_ai_application", `{"name":"a","object_type":"application","tenant":"acme.okta.com"}`, "okta_tenant", "acme.okta.com", "acme.okta.com"},
		"an object with no stable field": {"aws", "aws_account", `{}`, "", "", ""},
	} {
		entity, integrationID := observe(e, test.provider, "Location "+name, test.sourceKind, "asset", "Object", test.stable, `{}`)
		got := attribution(e, entity, "asset", integrationID, test.provider, `{}`, unassigned)
		if got.Integration == nil || got.Integration.ID != integrationID || got.Integration.Name != "Location "+name || got.Creator != nil || got.SuggestedOwner != nil || got.SuggestedTeam != nil {
			t.Fatalf("%s: attribution = %+v", name, got)
		}
		if test.kind == "" {
			if got.Location != nil {
				t.Fatalf("%s: location = %+v", name, got.Location)
			}
			continue
		}
		if got.Location == nil || *got.Location != (InventoryLocation{Kind: test.kind, ID: test.locationID, Label: test.label}) {
			t.Fatalf("%s: location = %+v", name, got.Location)
		}
	}
	// A tenant whose identifier is opaque is labelled with the name the
	// provider gives it: the tenant record of the same integration.
	for name, test := range map[string]struct{ provider, tenantKind, tenantStable, tenantName, sourceKind, stable, kind, locationID string }{
		"a Microsoft agent identity": {"microsoft", "microsoft_tenant", `{"name":"Contoso","tenant":"1f000000-0000-4000-8000-000000000001"}`, "Contoso", "microsoft_agent_identity", `{"name":"a","object_type":"agent_identity","tenant":"1f000000-0000-4000-8000-000000000001"}`, "microsoft_tenant", "1f000000-0000-4000-8000-000000000001"},
		"a Salesforce agent":         {"salesforce", "salesforce_org", `{"name":"Acme Sales","org":"00D5g000004C9ACEA0"}`, "Acme Sales", "salesforce_agent", `{"name":"a","object_type":"bot_definition","org":"00D5g000004C9ACEA0"}`, "salesforce_org", "00D5g000004C9ACEA0"},
		"a SaaS agent":               {"saas", "saas_tenant", `{"name":"Acme workspace","platform":"slack","tenant":"T0123ABCD"}`, "Acme workspace", "saas_agent", `{"name":"a","object_type":"app","platform":"slack","tenant":"T0123ABCD"}`, "saas_workspace", "T0123ABCD"},
	} {
		observe(e, test.provider, "Tenant "+name, test.tenantKind, "asset", test.tenantName, test.tenantStable, `{}`)
		entity, integrationID := observe(e, test.provider, "Tenant "+name, test.sourceKind, "agent", "Agent", test.stable, `{}`)
		got := attribution(e, entity, "agent", integrationID, test.provider, `{}`, unassigned)
		if got.Location == nil || *got.Location != (InventoryLocation{Kind: test.kind, ID: test.locationID, Label: test.tenantName}) {
			t.Fatalf("%s: location = %+v", name, got.Location)
		}
	}

	// The people of this Environment's identity provider, and one person of
	// another Environment who must never be matched.
	observe(e, "okta", "Okta", "okta_user", "identity", "Dana Reyes", `{"name":"Dana Reyes","object_type":"user","tenant":"acme.okta.com"}`, `{"status":"ACTIVE","email":"dana.reyes@example.com","department":"Customer Platform"}`)
	observe(e, "okta", "Okta", "okta_user", "identity", "Eli Okafor", `{"name":"Eli Okafor","object_type":"user","tenant":"acme.okta.com"}`, `{"status":"ACTIVE","email":"eli@example.com"}`)
	observe(other, "okta", "Okta elsewhere", "okta_user", "identity", "Mina Park", `{"name":"Mina Park","object_type":"user","tenant":"other.okta.com"}`, `{"status":"ACTIVE","email":"mina@example.com","department":"Another Environment"}`)
	agentStable := `{"account_id":"123456789012","agent_id":"A1","arn":"arn:aws:bedrock:us-east-1:123456789012:agent/A1","name":"a","region":"us-east-1"}`
	agent, awsIntegration := observe(e, "aws", "AWS production", "aws_bedrock_agent", "agent", "Support agent", agentStable, `{}`)
	text := func(value *string) string {
		if value == nil {
			return "<nil>"
		}
		return *value
	}
	type expectation struct {
		attributes, annotation string
		creator, createdAt     string
		source                 string
		owner, team, teamFrom  string
	}
	for name, test := range map[string]expectation{
		"a CloudTrail creator who is an Okta user": {`{"created_by":"Dana.Reyes@example.com","created_at":"2026-10-01T09:30:15Z","created_by_source":"cloudtrail"}`, unassigned, "Dana.Reyes@example.com", "2026-10-01T09:30:15Z", "cloudtrail", "Dana.Reyes@example.com", "Customer Platform", "okta"},
		"an Okta user without a department":        {`{"created_by":"eli@example.com","created_by_source":"provider_record"}`, unassigned, "eli@example.com", "<nil>", "provider_record", "eli@example.com", "", ""},
		"a person of another Environment":          {`{"created_by":"mina@example.com","created_by_source":"provider_record"}`, unassigned, "mina@example.com", "<nil>", "provider_record", "mina@example.com", "", ""},
		"a role session":                           {`{"created_by":"ci-deployer/release-481","created_at":"2026-09-12T18:00:00Z","created_by_source":"cloudtrail"}`, unassigned, "ci-deployer/release-481", "2026-09-12T18:00:00Z", "cloudtrail", "ci-deployer/release-481", "", ""},
		"a label names the team before Okta does":  {`{"created_by":"dana.reyes@example.com","created_by_source":"annotation","owning_team":"support-eng"}`, unassigned, "dana.reyes@example.com", "<nil>", "annotation", "dana.reyes@example.com", "support-eng", "label"},
		"a team label without a creator":           {`{"owning_team":"payments"}`, unassigned, "", "", "", "", "payments", "label"},
		"an opaque audit log account":              {`{"created_by":"712020:aaaa-bbbb","created_at":"2026-08-01T00:00:00Z","created_by_source":"audit_log"}`, unassigned, "712020:aaaa-bbbb", "2026-08-01T00:00:00Z", "audit_log", "", "", ""},
		"a CODEOWNERS team":                        {`{"created_by":"@acme/platform","created_by_source":"codeowners"}`, unassigned, "@acme/platform", "<nil>", "codeowners", "@acme/platform", "", ""},
		"a time that is not UTC is not shown":      {`{"created_by":"dana.reyes@example.com","created_at":"2026-10-01T09:30:15+02:00","created_by_source":"cloudtrail"}`, unassigned, "dana.reyes@example.com", "<nil>", "cloudtrail", "dana.reyes@example.com", "Customer Platform", "okta"},
		"an owner was assigned":                    {`{"created_by":"dana.reyes@example.com","created_by_source":"cloudtrail"}`, `{"owner":"Priya","team":"","tags":[]}`, "dana.reyes@example.com", "<nil>", "cloudtrail", "", "Customer Platform", "okta"},
		"an owner and a team were assigned":        {`{"created_by":"dana.reyes@example.com","created_by_source":"cloudtrail","owning_team":"support-eng"}`, `{"owner":"Priya","team":"Risk","tags":[]}`, "dana.reyes@example.com", "<nil>", "cloudtrail", "", "", ""},
		"free text is not a creator":               {`{"created_by":"Dana Reyes (platform)","created_by_source":"label"}`, unassigned, "", "", "", "", "", ""},
		"a creator without a source is not shown":  {`{"created_by":"dana.reyes@example.com"}`, unassigned, "", "", "", "", "", ""},
		"a source the product does not know":       {`{"created_by":"dana.reyes@example.com","created_by_source":"guess"}`, unassigned, "", "", "", "", "", ""},
		"an agent the provider says nothing about": {`{}`, unassigned, "", "", "", "", "", ""},
		"an identity longer than an owner may be":  {`{"created_by":"` + strings.Repeat("a", 200) + `","created_by_source":"provider_record"}`, unassigned, strings.Repeat("a", 200), "<nil>", "provider_record", "", "", ""},
	} {
		got := attribution(e, agent, "agent", awsIntegration, "aws", test.attributes, test.annotation)
		if got.Location == nil || got.Location.Kind != "aws_account" || got.Integration == nil || got.Integration.Name != "AWS production" {
			t.Fatalf("%s: location %+v integration %+v", name, got.Location, got.Integration)
		}
		if test.creator == "" {
			if got.Creator != nil {
				t.Fatalf("%s: creator = %+v", name, got.Creator)
			}
		} else if got.Creator == nil || got.Creator.Identity != test.creator || got.Creator.Source != test.source || text(got.Creator.CreatedAt) != test.createdAt {
			t.Fatalf("%s: creator = %+v", name, got.Creator)
		}
		if test.owner == "" {
			if got.SuggestedOwner != nil {
				t.Fatalf("%s: suggested owner = %+v", name, got.SuggestedOwner)
			}
		} else if got.SuggestedOwner == nil || *got.SuggestedOwner != (InventorySuggestion{Value: test.owner, Source: test.source}) {
			t.Fatalf("%s: suggested owner = %+v", name, got.SuggestedOwner)
		}
		if test.team == "" {
			if got.SuggestedTeam != nil {
				t.Fatalf("%s: suggested team = %+v", name, got.SuggestedTeam)
			}
		} else if got.SuggestedTeam == nil || *got.SuggestedTeam != (InventorySuggestion{Value: test.team, Source: test.teamFrom}) {
			t.Fatalf("%s: suggested team = %+v", name, got.SuggestedTeam)
		}
	}
	// Only an agent has a creator or a suggestion.
	if got := attribution(e, agent, "tool", awsIntegration, "aws", `{"created_by":"dana.reyes@example.com","created_by_source":"cloudtrail","owning_team":"support-eng"}`, unassigned); got.Creator != nil || got.SuggestedOwner != nil || got.SuggestedTeam != nil || got.Location == nil {
		t.Fatalf("a tool was attributed: %+v", got)
	}

	// A suggestion is not an assignment: ownerless_agent fires for an agent
	// that has only a suggested owner, and is resolved by an assigned one.
	snapshot, evidence := id(), id()
	exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,product_kind,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,observed_at,fresh_until,projection_version,winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection,winning_attributes)
 VALUES($1,$2,$3,$4,'agent','Support agent','{}','active',now()-interval '1 minute',now()-interval '1 minute',1,'agent',9500,$5,$6,1,now()-interval '1 minute',now()+interval '1 hour',1,$7,'aws','aws',$8,1,1,'{"created_by":"dana.reyes@example.com","created_by_source":"cloudtrail","discovery":{"method":"provider_api","platform":"bedrock_agent","signals":[]}}')`,
		o, w, e, agent, evidence, snapshot, awsIntegration, "aws_bedrock_agent:"+agent)
	ownerless := func() string {
		t.Helper()
		if _, err := seed.Exec(ctx, `SELECT public.zasp_inventory_refresh_posture_findings($1,$2,$3)`, o, w, e); err != nil {
			t.Fatalf("posture refresh: %v", err)
		}
		var status string
		if err := seed.QueryRow(ctx, `SELECT COALESCE((SELECT status FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,agent_id,rule)=($1,$2,$3,$4,'ownerless_agent')),'absent')`, o, w, e, agent).Scan(&status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	if status := ownerless(); status != "open" {
		t.Fatalf("ownerless_agent on an agent with a suggested owner = %s", status)
	}
	exec(`INSERT INTO zasp_inventory_annotations(organization_id,workspace_id,environment_id,entity_id,owner_value,team_value) VALUES($1,$2,$3,$4,'dana.reyes@example.com','Customer Platform')`, o, w, e, agent)
	if status := ownerless(); status != "resolved" {
		t.Fatalf("ownerless_agent after an owner was assigned = %s", status)
	}
	// The section applied to an installed database breaks the seal by
	// design; it is refreshed as a rebuilt baseline is sealed.
	if err := seed.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_baseline.seal SET content=zasp_baseline.content(),marker=zasp_baseline.marker()`); err != nil {
		t.Fatal(err)
	}
	var intact bool
	if err := connection.QueryRow(ctx, `SELECT zasp_baseline.intact()`).Scan(&intact); err != nil || !intact {
		t.Fatalf("the installation is not intact after section WS11: intact=%t err=%v", intact, err)
	}
}
