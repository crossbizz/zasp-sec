package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/gcpdiscovery/gcptest"
	"github.com/zasp-ai/zasp-sec/services/platform/inventoryprojection"
)

const (
	gcpProviderFederation = `{"audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws","identity_reference":"ref:gcp/workload-identity/acme-security/zasp-reader","scope":"projects/alpha-prod"}`
	gcpProviderKey        = `{"identity_reference":"ref:gcp/service-account-key/customer-0001","scope":"organizations/123456789012"}`
)

// gcpProviderSections are the blocks of completion.sql section X3d.
var gcpProviderSections = []string{"ws8_gcp_provider", "ws8_gcp_rule_catalog", "ws8_gcp_coverage_gaps"}

// Section X3d of completion.sql (Google Cloud) against the installed released
// baseline: the section applies; a second run of it and of every section it
// builds on changes nothing; the widened constraints and functions accept
// exactly the gcp grammar; a gcp integration is created; the typed snapshot
// the Google Cloud collector produces is applied to the inventory; the
// collector's checks are accepted by the finding channel; and the Google
// APIs the collection could not read are the integration's coverage gaps.
func TestGCPProviderSectionOnTheInstalledBaselinePostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	connection := installedBaselineConnection(t, ctx)

	definitions := func() string {
		t.Helper()
		var functions, constraints string
		if err := connection.QueryRow(ctx, `SELECT
 (SELECT md5(string_agg(pg_get_functiondef(p.oid),'' ORDER BY p.oid::regprocedure::text)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prokind='f' AND (n.nspname LIKE 'zasp%' OR n.nspname='public')),
 (SELECT md5(string_agg(c.conrelid::regclass::text||c.conname||pg_get_constraintdef(c.oid),'' ORDER BY c.conrelid::regclass::text,c.conname)) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname LIKE 'zasp%' OR n.nspname='public')`).Scan(&functions, &constraints); err != nil {
			t.Fatal(err)
		}
		return functions + constraints
	}
	var rules int
	var digest string
	catalog := func() {
		t.Helper()
		if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_inventory_identity_rules),(SELECT value FROM zasp_schema_metadata WHERE key='typed_inventory_rule_catalog_digest')`).Scan(&rules, &digest); err != nil {
			t.Fatal(err)
		}
	}
	// The predecessor is the released baseline: one built before this
	// section serves seven providers with 56 rules; one rebuilt with it
	// already serves gcp, and the sections must then change nothing.
	catalog()
	var gcpBefore bool
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_provider_valid('gcp')`).Scan(&gcpBefore); err != nil || !gcpBefore && rules != 56 || gcpBefore && rules < 66 {
		t.Fatalf("predecessor: gcp=%t rules=%d err=%v", gcpBefore, rules, err)
	}
	t.Logf("released baseline serves gcp: %t (%d identity rules)", gcpBefore, rules)
	released := definitions()
	// The sections this one builds on are no-ops on the released baseline.
	predecessors := []string{"saas_providers", "rule_catalog_digest", "integration_coverage_gaps", "saas_generic_provider", "saas_rule_catalog", "ws5_rule_catalog"}
	for _, tag := range predecessors {
		applyCompletionBlock(t, ctx, connection, tag)
	}
	if definitions() != released {
		t.Fatal("re-running the sections X3d builds on changed the released baseline")
	}
	for _, tag := range gcpProviderSections {
		applyCompletionBlock(t, ctx, connection, tag)
	}
	widened := definitions()
	if (widened == released) != gcpBefore {
		t.Fatalf("the gcp section changed the catalog: %t, on a baseline that served gcp already: %t", widened != released, gcpBefore)
	}
	// The whole tail of the file runs again without a change or an error.
	for _, tag := range append(append([]string(nil), predecessors...), gcpProviderSections...) {
		applyCompletionBlock(t, ctx, connection, tag)
	}
	if definitions() != widened {
		t.Fatal("a second run of the sections changed a function or a constraint")
	}
	catalog()
	if compiled := inventoryprojection.RuleCatalogDigest(); !gcpBefore && (rules != 66 || rules != len(inventoryprojection.RuleCatalog()) || digest != hexDigest(compiled)) {
		t.Fatalf("rule catalog: rows=%d digest=%s, compiled rows=%d digest=%s", rules, digest, len(inventoryprojection.RuleCatalog()), hexDigest(compiled))
	}
	// Every gcp rule row equals the compiled rule.
	rows, err := connection.Query(ctx, `SELECT source_kind,identity_namespace,product_kind,rule_version,priority,confidence_basis_points,freshness_seconds FROM zasp_inventory_identity_rules WHERE provider='gcp' ORDER BY source_kind`)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for rows.Next() {
		var sourceKind, namespace, productKind string
		var version, priority, confidence int
		var freshness int64
		if err := rows.Scan(&sourceKind, &namespace, &productKind, &version, &priority, &confidence, &freshness); err != nil {
			t.Fatal(err)
		}
		rule, found := inventoryprojection.LookupRule("gcp", sourceKind)
		if !found || rule.Namespace != namespace || string(rule.ProductKind) != productKind || rule.Version != version || rule.Priority != priority || rule.ConfidenceBasisPoints != confidence || int64(rule.Freshness/time.Second) != freshness {
			t.Fatalf("rule row %s differs from the compiled rule %+v", sourceKind, rule)
		}
		seen++
	}
	rows.Close()
	if seen != 10 {
		t.Fatalf("gcp rule rows = %d", seen)
	}

	// The grammar the functions accept.
	check := func(expression string, want bool) {
		t.Helper()
		var got *bool
		if err := connection.QueryRow(ctx, "SELECT "+expression).Scan(&got); err != nil || got == nil || *got != want {
			t.Fatalf("%s = %v (%v), want %t", expression, got, err, want)
		}
	}
	check(`zasp_connector_provider_valid('gcp')`, true)
	check(`zasp_connector_provider_valid('saas')`, true)
	check(`zasp_connector_provider_valid('azure')`, false)
	for subject, want := range map[string]bool{
		"organizations/123456789012": true, "folders/42": true, "projects/alpha-prod": true,
		"organizations/0": false, "projects/Alpha-Prod": false, "projects/ab": false, "alpha-prod": false, "folders/42/projects/alpha-prod": false, "organizations/123456789012 ": false,
	} {
		check(`zasp_execution_subject_valid('gcp','gcp_scope','`+subject+`')`, want)
	}
	check(`zasp_execution_subject_valid('gcp','aws_account','projects/alpha-prod')`, false)
	check(`zasp_execution_subject_valid('aws','gcp_scope','projects/alpha-prod')`, false)
	check(`zasp_execution_subject_valid('saas','saas_tenant','slack/T024BE7LD')`, true)
	const audience, federation, key = `"audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws"`, `"identity_reference":"ref:gcp/workload-identity/acme-security/zasp-reader"`, `"identity_reference":"ref:gcp/service-account-key/customer-0001"`
	for configuration, want := range map[string]bool{
		gcpProviderFederation: true,
		gcpProviderKey:        true,
		// Federation needs its audience; a key takes none.
		`{` + federation + `,"scope":"projects/alpha-prod"}`:           false,
		`{` + audience + `,` + key + `,"scope":"projects/alpha-prod"}`: false,
		`{` + key + `}`:                          false,
		`{` + key + `,"scope":"projects/Alpha"}`: false,
		`{` + key + `,"scope":123456789012}`:     false,
		`{"identity_reference":"ref:aws/external-id/customer-0001","scope":"projects/alpha-prod"}`:                                                                         false,
		`{"identity_reference":"ref:gcp/service-account-key/short","scope":"projects/alpha-prod"}`:                                                                         false,
		`{"audience":"//iam.example.com/projects/1/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws",` + federation + `,"scope":"projects/alpha-prod"}`: false,
		// Key material is never part of a configuration.
		`{` + key + `,"private_key":"key material","scope":"projects/alpha-prod"}`: false,
		`{` + key + `,"region":"us-central1","scope":"projects/alpha-prod"}`:       false,
	} {
		check(`zasp_reference_authorization_configuration_valid('gcp','`+configuration+`'::jsonb)`, want)
		check(`zasp_authorization80.integration_setup_valid('gcp','`+configuration+`'::jsonb)`, want)
		check(`zasp_reference_authorization_configuration_valid('aws','`+configuration+`'::jsonb)`, false)
	}
	check(`zasp_reference_only('`+gcpProviderFederation+`'::jsonb)`, true)
	check(`zasp_reference_only('`+gcpProviderKey+`'::jsonb)`, true)
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_identity_rules(provider,source_kind,identity_namespace,product_kind,rule_version,priority,confidence_basis_points,freshness_seconds) VALUES('azure','azure_agent','azure_agent','agent',1,170,9500,86400)`); err == nil {
		t.Fatal("an unknown provider was accepted")
	}
	var widenedColumns int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE contype='c' AND (pg_get_constraintdef(oid) LIKE '%''saas''::text, ''gcp''::text%' OR pg_get_constraintdef(oid) LIKE '%''saas_tenant''::text, ''gcp_scope''::text%')`).Scan(&widenedColumns); err != nil || widenedColumns != 10 {
		t.Fatalf("widened CHECK constraints = %d, %v", widenedColumns, err)
	}
	// The scheduler's sweep, the reference binding and the credential class.
	for target, texts := range map[string][]string{
		`zasp_temporal72.release_abandoned_due(integer)`: {`OR x.provider='gcp')`},
		`public.zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)`:                  {`WHEN 'gcp' THEN configuration_value->>'identity_reference'`, `AND provider_value<>'gcp'`},
		`zasp_authorization80.integration_reference_native_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)`:    {`WHEN 'gcp' THEN configuration_value->>'identity_reference'`, `AND provider_value<>'gcp'`},
		`zasp_authorization80.integration_reference_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text)`: {`OR provider_value='gcp')`},
		`zasp_temporal72.prepare_page(text,text,text,text,text,text,timestamptz,bigint,text)`:                                                           {`WHEN 'gcp' THEN 'gcp_access_token'`},
		`public.zasp_typed_inventory_job_input_v13(text,text,text,text,text,text)`:                                                                      {`WHEN 'gcp' THEN 'gcp_access_token'`, `WHEN 'gcp' THEN subject.subject_kind='gcp_scope' AND subject.subject_id=integration.configuration->>'scope'`},
		`zasp_temporal72.require_current_run(zasp_temporal72.runs,timestamptz)`:                                                                         {`WHEN 'gcp' THEN r.subject_kind='gcp_scope' AND r.subject_id=i.configuration->>'scope'`},
	} {
		var definition string
		if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, target).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		for _, text := range texts {
			if strings.Count(definition, text) != 1 {
				t.Fatalf("%s holds %q %d times", target, text, strings.Count(definition, text))
			}
		}
	}

	// A gcp integration, created by the statements the discovery repository runs.
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	organizationID, workspaceID, environmentID := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	const integrationID, syncID, snapshotID = "pid_7c000001-0000-4000-8000-000000000001", "pid_7c000002-0000-4000-8000-000000000002", "pid_7c000003-0000-4000-8000-000000000003"
	if _, err := connection.Exec(ctx, postgresDiscoveryCreateIntegrationSQL, organizationID, workspaceID, environmentID, integrationID, "gcp", "1.0.0", "Google Cloud", gcpProviderFederation, ""); err != nil {
		t.Fatalf("create the gcp integration: %v", err)
	}
	if _, err := connection.Exec(ctx, postgresDiscoveryTransitionIntegrationSQL, organizationID, workspaceID, environmentID, integrationID, int64(1), "active"); err != nil {
		t.Fatal(err)
	}
	var storedKind, storedConfiguration string
	if err := connection.QueryRow(ctx, `SELECT kind,configuration::text FROM zasp_integrations WHERE id=$1`, integrationID).Scan(&storedKind, &storedConfiguration); err != nil || storedKind != "gcp" || !strings.Contains(storedConfiguration, `"scope": "projects/alpha-prod"`) {
		t.Fatalf("stored integration = %s %s (%v)", storedKind, storedConfiguration, err)
	}

	// One project, read by the real collector from the fake Google: a
	// reasoning engine that runs as a project owner, with Model Armor
	// switched off, Cloud Functions refused and Cloud Run switched off.
	const runner = "agent-runner@alpha-prod.iam.gserviceaccount.com"
	google := gcptest.NewGoogle(t)
	google.OK("cloudresourcemanager.googleapis.com", "/v3/projects/alpha-prod", `{"name":"projects/111","projectId":"alpha-prod","parent":"organizations/123456789012","state":"ACTIVE","displayName":"Alpha production"}`)
	google.OK("iam.googleapis.com", "/v1/projects/alpha-prod/serviceAccounts", `{"accounts":[{"email":"`+runner+`"}]}`)
	google.OK("cloudresourcemanager.googleapis.com", "/v3/projects/alpha-prod:getIamPolicy", `{"bindings":[{"role":"roles/owner","members":["serviceAccount:`+runner+`"]}]}`)
	google.OK("aiplatform.googleapis.com", "/v1/projects/alpha-prod/locations", `{"locations":[{"locationId":"us-central1"}]}`)
	google.OK("us-central1-aiplatform.googleapis.com", "/v1/projects/alpha-prod/locations/us-central1/reasoningEngines", `{"reasoningEngines":[{"name":"projects/111/locations/us-central1/reasoningEngines/8001","displayName":"Refund agent","spec":{"agentFramework":"google-adk","serviceAccount":"`+runner+`"}}]}`)
	google.Disabled("modelarmor.googleapis.com", "/v1/projects/alpha-prod/locations/global/floorSetting")
	google.Denied("cloudfunctions.googleapis.com", "/v2/projects/alpha-prod/locations/-/functions")
	google.Disabled("run.googleapis.com", "/v1/projects/alpha-prod/locations")
	collected := gcptest.Collect(t, google, "projects/alpha-prod")
	candidate := collected.Result.Snapshot()
	manifest := collected.Result.Manifest().Descriptor()
	checksum := manifest.Checksum()
	requestDigest := sha256.Sum256([]byte("gcp-typed-sync"))
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'gcp-typed-sync-0001',$6,'manual',$7,'parser_v1','tool_v1')`,
		organizationID, workspaceID, environmentID, syncID, integrationID, requestDigest[:], identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	observed, err := time.Parse(time.RFC3339, collected.Entities[0].ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	apply := func(source string) (SnapshotApplyResult, error) {
		var payload []byte
		var result SnapshotApplyResult
		err := connection.QueryRow(ctx, postgresDiscoveryApplySnapshotSQL, organizationID, workspaceID, environmentID, integrationID, syncID, snapshotID, int64(1), source, manifest.ObjectReference(), checksum[:],
			observed, source, collected.Result.NextCursor().Value, string(candidate.Entities()), string(candidate.Relationships()), string(candidate.Evidence())).Scan(&payload)
		if err == nil {
			err = json.Unmarshal(payload, &result)
		}
		return result, err
	}
	if _, err := apply("azure"); err == nil {
		t.Fatal("a snapshot of an unlisted provider was applied")
	}
	result, err := apply("gcp")
	if err != nil {
		t.Fatalf("apply the gcp typed snapshot: %v", err)
	}
	// The scope, the project, the service account, the engine, ten services.
	if result.SnapshotID != snapshotID || result.DiscoveredCount != 14 || result.RemovedCount != 0 {
		t.Fatalf("apply result = %+v", result)
	}
	inventory, err := connection.Query(ctx, `SELECT observation.source_kind,entity.product_kind,entity.display_name,entity.confidence_basis_points,COALESCE(observation.attributes->'discovery'->>'method','')
 FROM zasp_inventory_entities entity JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.entity_id)=(entity.organization_id,entity.workspace_id,entity.environment_id,entity.id)
 WHERE (entity.organization_id,entity.workspace_id,entity.environment_id)=($1,$2,$3) AND observation.integration_id=$4 AND observation.source_state='present' AND observation.provider='gcp' AND observation.source_kind<>'gcp_service' ORDER BY observation.source_kind`, organizationID, workspaceID, environmentID, integrationID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for inventory.Next() {
		var sourceKind, productKind, name, method string
		var confidence int
		if err := inventory.Scan(&sourceKind, &productKind, &name, &confidence, &method); err != nil {
			t.Fatal(err)
		}
		got = append(got, strings.Join([]string{sourceKind, productKind, name, method}, "|")+"|"+itoa(confidence))
	}
	inventory.Close()
	want := []string{"gcp_agent_engine|agent|Refund agent|provider_api|9500", "gcp_project|asset|Alpha production||9500", "gcp_scope|asset|Alpha production||9500", "gcp_service_account|identity|" + runner + "||9500"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("inventory\n got %v\nwant %v", got, want)
	}
	var engineAttributes string
	if err := connection.QueryRow(ctx, `SELECT attributes::text FROM zasp_inventory_source_observations WHERE integration_id=$1 AND source_kind='gcp_agent_engine'`, integrationID).Scan(&engineAttributes); err != nil ||
		!strings.Contains(engineAttributes, `"model_armor": "none"`) || !strings.Contains(engineAttributes, `"service_account": "`+runner+`"`) || !strings.Contains(engineAttributes, `"agent_framework": "google-adk"`) {
		t.Fatalf("engine attributes = %s (%v)", engineAttributes, err)
	}

	// The collector's two checks on the engine, applied the way the risk
	// projection applies them. The finding channel accepts source gcp.
	var evidence []struct {
		ID        string `json:"id"`
		EntityID  string `json:"entity_id"`
		FindingID string `json:"finding_id"`
		CheckID   string `json:"check_id"`
	}
	if err := json.Unmarshal(candidate.Evidence(), &evidence); err != nil {
		t.Fatal(err)
	}
	var findingItems []map[string]string
	var checks []string
	for _, item := range evidence {
		if item.FindingID != "" {
			findingItems = append(findingItems, map[string]string{"finding_id": item.FindingID, "entity_id": item.EntityID, "check_id": item.CheckID, "evidence_id": item.ID, "source": "gcp"})
			checks = append(checks, item.CheckID)
		}
	}
	sort.Strings(checks)
	if strings.Join(checks, ",") != "agent_model_armor_missing,agent_service_account_admin_role" {
		t.Fatalf("discovery findings in the snapshot = %v", checks)
	}
	encodedFindings, _ := json.Marshal(findingItems)
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_apply_findings($1,$2,$3,$4::jsonb)`, organizationID, workspaceID, environmentID, string(encodedFindings)); err != nil {
		t.Fatalf("apply the gcp discovery findings: %v", err)
	}
	for index := range findingItems {
		findingItems[index]["source"] = "azure"
	}
	encodedFindings, _ = json.Marshal(findingItems)
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_apply_findings($1,$2,$3,$4::jsonb)`, organizationID, workspaceID, environmentID, string(encodedFindings)); err == nil {
		t.Fatal("findings of an unlisted source were applied")
	}
	var storedRules string
	if err := connection.QueryRow(ctx, `SELECT COALESCE(string_agg(rule,',' ORDER BY rule),'') FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND rule LIKE 'agent_%'`, organizationID, workspaceID, environmentID).Scan(&storedRules); err != nil || storedRules != "agent_model_armor_missing,agent_service_account_admin_role" {
		t.Fatalf("stored finding rules = %q (%v)", storedRules, err)
	}

	// Coverage: the freshness of the integration names what was not read.
	// The installed function admits only the discovery API login inside a
	// checked request of the API server, which a bare baseline does not run.
	// Its body is therefore run as installed, statement for statement, under
	// a temporary name and without the principal check.
	var installed string
	if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_temporal72.last_good_freshness(text,text,text,text)'::regprocedure)`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	const installedName, principalCheck = "FUNCTION zasp_temporal72.last_good_freshness(", " PERFORM zasp_temporal72.require_principal('zasp_discovery_api');"
	if strings.Count(installed, installedName) != 1 || strings.Count(installed, principalCheck) != 1 || strings.Count(installed, "'gcp_service'") != 1 || strings.Count(installed, "'aws_service'") != 1 {
		t.Fatalf("installed freshness function is not the one sections X5b and X3d leave:\n%s", installed)
	}
	probe := strings.Replace(strings.Replace(installed, installedName, "FUNCTION pg_temp.zasp_gcp_freshness_probe(", 1), principalCheck, "", 1)
	if _, err := connection.Exec(ctx, probe); err != nil {
		t.Fatalf("install the freshness body under a temporary name: %v", err)
	}
	var gaps string
	if err := connection.QueryRow(ctx, `SELECT (pg_temp.zasp_gcp_freshness_probe($1,$2,$3,$4)->'coverage_gaps')::text`, organizationID, workspaceID, environmentID, integrationID).Scan(&gaps); err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if wantGaps := `[{"name": "Cloud Functions", "status": "access_denied", "service": "cloud-functions"}, {"name": "Cloud Run", "status": "unavailable", "service": "cloud-run"}, {"name": "Model Armor", "status": "unavailable", "service": "model-armor"}]`; gaps != wantGaps {
		t.Fatalf("coverage gaps = %s, want %s", gaps, wantGaps)
	}
}
