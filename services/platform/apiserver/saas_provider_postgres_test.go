package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
	"github.com/zasp-ai/zasp-sec/services/platform/inventoryprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations/baseline"
)

const (
	saasProviderConfiguration = `{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"databricks","tenant_id":"adb-1234567890123456.7.azuredatabricks.net"}`
	saasProviderSubject       = "databricks/adb-1234567890123456.7.azuredatabricks.net"
)

// installedBaselineConnection installs the released baseline artifact in a
// disposable PostgreSQL the way a deployment does (as the non-superuser
// operator) and returns a superuser connection to that database, which is how
// completion.sql runs when the baseline is rebuilt.
func installedBaselineConnection(t *testing.T, ctx context.Context) *pgx.Conn {
	t.Helper()
	dsn := startDisposablePostgres(t)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	for _, statement := range []string{`CREATE ROLE zasp_operator LOGIN CREATEROLE BYPASSRLS`, `CREATE DATABASE baseline OWNER zasp_operator TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'`} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	operator, err := pgx.Connect(ctx, strings.Replace(strings.Replace(dsn, "zasp_test@", "zasp_operator@", 1), "/postgres?", "/baseline?", 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := baseline.Install(ctx, operator); err != nil {
		operator.Close(context.Background())
		t.Fatalf("install the released baseline: %v", err)
	}
	operator.Close(context.Background())
	connection, err := pgx.Connect(ctx, strings.Replace(dsn, "/postgres?", "/baseline?", 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close(context.Background()) })
	return connection
}

// Section X3c of completion.sql (the generic saas provider) against the
// released baseline: the section applies, a second run of it and of the
// sections it builds on (X3b, X4) changes nothing, the widened constraints
// and functions accept exactly the saas grammar, a saas integration is
// created and reference-authorized, and the typed snapshot the saas collector
// produces is applied to the inventory.
func TestSaaSProviderSectionOnTheInstalledBaselinePostgres(t *testing.T) {
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
	// The predecessor is the released baseline. One built before this section
	// has six providers and 43 rules. One rebuilt with it already serves
	// saas; the sections must then change nothing.
	catalog()
	var saasBefore bool
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_provider_valid('saas')`).Scan(&saasBefore); err != nil || !saasBefore && rules != 43 {
		t.Fatalf("predecessor: saas=%t rules=%d err=%v", saasBefore, rules, err)
	}
	t.Logf("released baseline serves saas: %t (%d identity rules)", saasBefore, rules)
	released := definitions()
	// The sections this one builds on are no-ops on the released baseline.
	applyCompletionBlock(t, ctx, connection, "saas_providers")
	applyCompletionBlock(t, ctx, connection, "rule_catalog_digest")
	if definitions() != released {
		t.Fatal("re-running X3b and X4 changed the released baseline")
	}

	applyCompletionBlock(t, ctx, connection, "saas_generic_provider")
	applyCompletionBlock(t, ctx, connection, "saas_rule_catalog")
	widened := definitions()
	if (widened == released) != saasBefore {
		t.Fatalf("the saas section changed the catalog: %t, on a baseline that served saas already: %t", widened != released, saasBefore)
	}
	// The whole tail of the file runs again without a change or an error.
	for _, tag := range []string{"saas_providers", "rule_catalog_digest", "saas_generic_provider", "saas_rule_catalog"} {
		applyCompletionBlock(t, ctx, connection, tag)
	}
	if definitions() != widened {
		t.Fatal("a second run of the sections changed a function or a constraint")
	}
	catalog()
	compiled := inventoryprojection.RuleCatalogDigest()
	if digest != hexDigest(compiled) {
		t.Fatalf("rule catalog: rows=%d digest=%s, compiled digest=%s", rules, digest, hexDigest(compiled))
	}
	// Every rule row equals the compiled rule.
	rows, err := connection.Query(ctx, `SELECT source_kind,identity_namespace,product_kind,rule_version,priority,confidence_basis_points,freshness_seconds FROM zasp_inventory_identity_rules WHERE provider='saas' ORDER BY source_kind`)
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
		rule, found := inventoryprojection.LookupRule("saas", sourceKind)
		if !found || rule.Namespace != namespace || string(rule.ProductKind) != productKind || rule.Version != version || rule.Priority != priority || rule.ConfidenceBasisPoints != confidence || int64(rule.Freshness/time.Second) != freshness {
			t.Fatalf("rule row %s differs from the compiled rule %+v", sourceKind, rule)
		}
		seen++
	}
	rows.Close()
	if seen != 4 {
		t.Fatalf("saas rule rows = %d", seen)
	}

	// The grammar the functions accept.
	check := func(expression string, want bool) {
		t.Helper()
		var got *bool
		if err := connection.QueryRow(ctx, "SELECT "+expression).Scan(&got); err != nil || got == nil || *got != want {
			t.Fatalf("%s = %v (%v), want %t", expression, got, err, want)
		}
	}
	check(`zasp_connector_provider_valid('saas')`, true)
	check(`zasp_connector_provider_valid('servicenow')`, false)
	check(`zasp_execution_subject_valid('saas','saas_tenant','`+saasProviderSubject+`')`, true)
	check(`zasp_execution_subject_valid('saas','saas_tenant','slack/T024BE7LD')`, true)
	check(`zasp_execution_subject_valid('saas','saas_tenant','Slack/T024BE7LD')`, false)
	check(`zasp_execution_subject_valid('saas','saas_tenant','slack')`, false)
	check(`zasp_execution_subject_valid('saas','saas_tenant','slack/T0..1')`, false)
	check(`zasp_execution_subject_valid('saas','saas_tenant','slack/a/b')`, false)
	check(`zasp_execution_subject_valid('saas','okta_tenant','slack/T024BE7LD')`, false)
	check(`zasp_execution_subject_valid('salesforce','saas_tenant','slack/T024BE7LD')`, false)
	check(`zasp_execution_subject_valid('salesforce','salesforce_org','00D5e000000abcdEAA')`, true)
	for configuration, want := range map[string]bool{
		saasProviderConfiguration: true,
		`{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"slack","tenant_id":"T024BE7LD"}`:                                       true,
		`{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"databricks"}`:                                                          false,
		`{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"Databricks","tenant_id":"adb-1234567890123456.7.azuredatabricks.net"}`: false,
		`{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"databricks","tenant_id":"../1"}`:                                       false,
		`{"connection_reference":"ref:kubernetes/connection/customer-0001","platform":"databricks","tenant_id":"adb-1234567890123456.7.azuredatabricks.net"}`:                   false,
		`{"connection_reference":"ref:nango/service-key-0001","platform":"databricks","tenant_id":"adb-1234567890123456.7.azuredatabricks.net"}`:                                false,
		`{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"databricks","tenant_id":1234567890123456}`:                             false,
		`{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"databricks","tenant_id":"1","access_token":"dapi-0001"}`:               false,
	} {
		check(`zasp_reference_authorization_configuration_valid('saas','`+configuration+`'::jsonb)`, want)
		check(`zasp_authorization80.integration_setup_valid('saas','`+configuration+`'::jsonb)`, want)
		check(`zasp_reference_authorization_configuration_valid('salesforce','`+configuration+`'::jsonb)`, false)
	}
	check(`zasp_reference_only('`+saasProviderConfiguration+`'::jsonb)`, true)
	// The provider and subject kind columns admit saas and still refuse others.
	for _, statement := range []string{
		`INSERT INTO zasp_inventory_identity_rules(provider,source_kind,identity_namespace,product_kind,rule_version,priority,confidence_basis_points,freshness_seconds) VALUES('servicenow','servicenow_agent','servicenow_agent','agent',1,160,9500,86400)`,
	} {
		if _, err := connection.Exec(ctx, statement); err == nil {
			t.Fatalf("an unknown provider was accepted: %s", statement)
		}
	}
	var widenedColumns int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE contype='c' AND (pg_get_constraintdef(oid) LIKE '%''salesforce''::text, ''saas''::text%' OR pg_get_constraintdef(oid) LIKE '%''salesforce_org''::text, ''saas_tenant''::text%')`).Scan(&widenedColumns); err != nil || widenedColumns != 10 {
		t.Fatalf("widened CHECK constraints = %d, %v", widenedColumns, err)
	}
	// The scheduler's sweep names every provider.
	var sweep string
	if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_temporal72.release_abandoned_due(integer)'::regprocedure)`).Scan(&sweep); err != nil || !strings.Contains(sweep, `x.provider IN('aws','kubernetes','github','okta','microsoft','salesforce','saas')`) {
		t.Fatalf("release sweep does not name the seven providers: %v", err)
	}

	// A saas integration: created, reference-authorized, bound to its tenant.
	// The statements are the ones the discovery repository runs.
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	organizationID, workspaceID, environmentID := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	const integrationID, syncID, snapshotID = "pid_7a000001-0000-4000-8000-000000000001", "pid_7a000002-0000-4000-8000-000000000002", "pid_7a000003-0000-4000-8000-000000000003"
	if _, err := connection.Exec(ctx, postgresDiscoveryCreateIntegrationSQL, organizationID, workspaceID, environmentID, integrationID, "saas", "1.0.0", "Databricks", saasProviderConfiguration, ""); err != nil {
		t.Fatalf("create the saas integration: %v", err)
	}
	if _, err := connection.Exec(ctx, postgresDiscoveryTransitionIntegrationSQL, organizationID, workspaceID, environmentID, integrationID, int64(1), "active"); err != nil {
		t.Fatal(err)
	}
	var storedKind, storedConfiguration string
	if err := connection.QueryRow(ctx, `SELECT kind,configuration::text FROM zasp_integrations WHERE id=$1`, integrationID).Scan(&storedKind, &storedConfiguration); err != nil || storedKind != "saas" || !strings.Contains(storedConfiguration, `"platform": "databricks"`) {
		t.Fatalf("stored integration = %s %s (%v)", storedKind, storedConfiguration, err)
	}
	// The reference authorization itself (zasp_complete_reference_authorization
	// and its zasp_authorization80 wrappers) needs the product's authorization
	// store and audit authority, which a bare baseline does not run; its saas
	// edits are covered above through the functions it calls.
	for _, target := range []string{
		`public.zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)`,
		`zasp_authorization80.integration_reference_native_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)`,
	} {
		var definition string
		if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, target).Scan(&definition); err != nil || strings.Count(definition, `WHEN 'saas' THEN configuration_value->>'connection_reference'`) != 1 || strings.Count(definition, `AND provider_value<>'saas'`) != 1 {
			t.Fatalf("%s does not bind a saas connection to its Nango reference: %v", target, err)
		}
	}

	// The typed snapshot the saas collector produces for a Databricks
	// workspace, collected through the stand-in Nango, applied to the
	// inventory by the function the worker calls.
	registry, err := platforms.Registry()
	if err != nil {
		t.Fatal(err)
	}
	platform, _ := registry.Platform("databricks")
	standIn := saastest.NewNango(t, registry, map[string]saastest.Route{
		"/api/2.1/unity-catalog/current-metastore-assignment": saastest.Static(`{"metastore_id":"11111111-2222-3333-4444-555555555555","workspace_id":1234567890123456}`),
		"/api/2.0/serving-endpoints": saastest.Static(`{"endpoints":[
 {"name":"support-agent","id":"0a1b2c3d4e5f","state":{"ready":"READY"},"task":"agent/v1/responses","config":{"served_entities":[{"entity_name":"main.agents.support_agent"}]}},
 {"name":"gpt-4o-proxy","id":"1b2c3d4e5f60","state":{"ready":"READY"},"task":"llm/v1/chat","config":{"served_entities":[{"external_model":{"provider":"openai","name":"gpt-4o"}}]}}]}`),
	})
	collected := saastest.Collect(t, standIn, registry, platform, "adb-1234567890123456.7.azuredatabricks.net")
	candidate := collected.Result.Snapshot()
	manifest := collected.Result.Manifest().Descriptor()
	checksum := manifest.Checksum()
	requestDigest := sha256.Sum256([]byte("saas-typed-sync"))
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'saas-typed-sync-0001',$6,'manual',$7,'parser_v1','tool_v1')`,
		organizationID, workspaceID, environmentID, syncID, integrationID, requestDigest[:], identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	// The snapshot is applied at the observation time its entities carry.
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
	// The same snapshot under a provider the lists do not name is refused.
	if _, err := apply("servicenow"); err == nil {
		t.Fatal("a snapshot of an unlisted provider was applied")
	}
	result, err := apply("saas")
	if err != nil {
		t.Fatalf("apply the saas typed snapshot: %v", err)
	}
	if result.SnapshotID != snapshotID || result.DiscoveredCount != 3 || result.RemovedCount != 0 {
		t.Fatalf("apply result = %+v", result)
	}
	inventory, err := connection.Query(ctx, `SELECT observation.source_kind,entity.product_kind,entity.display_name,entity.confidence_basis_points,observation.provider,observation.stable_fields->>'platform',observation.stable_fields->>'tenant',COALESCE(observation.attributes->'discovery'->>'method','')
 FROM zasp_inventory_entities entity JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.entity_id)=(entity.organization_id,entity.workspace_id,entity.environment_id,entity.id)
 WHERE (entity.organization_id,entity.workspace_id,entity.environment_id)=($1,$2,$3) AND observation.integration_id=$4 AND observation.source_state='present' ORDER BY observation.source_kind`, organizationID, workspaceID, environmentID, integrationID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for inventory.Next() {
		var sourceKind, productKind, name, provider, platformField, tenant, method string
		var confidence int
		if err := inventory.Scan(&sourceKind, &productKind, &name, &confidence, &provider, &platformField, &tenant, &method); err != nil {
			t.Fatal(err)
		}
		if provider != "saas" || platformField != "databricks" || tenant != "adb-1234567890123456.7.azuredatabricks.net" {
			t.Fatalf("%s is not bound to the saas tenant: %s %s %s", sourceKind, provider, platformField, tenant)
		}
		got = append(got, strings.Join([]string{sourceKind, productKind, name, method}, "|")+"|"+itoa(confidence))
	}
	inventory.Close()
	want := []string{"saas_agent|agent|support-agent|provider_api|9500", "saas_ai_application|agent|gpt-4o-proxy|inferred|7000", "saas_tenant|asset|Databricks workspace adb-1234567890123456.7.azuredatabricks.net||9500"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("inventory\n got %v\nwant %v", got, want)
	}
}

func hexDigest(value [sha256.Size]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(value)*2)
	for _, b := range value {
		out = append(out, digits[b>>4], digits[b&15])
	}
	return string(out)
}

func itoa(value int) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
