package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func fixtureID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSlackLongTailManifestUsesProductLanguageAndNonSecretSetup(t *testing.T) {
	catalog, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	items, err := catalog.Search(CatalogFilter{Query: "Slack"})
	if err != nil || len(items) != 1 || items[0].Key != "slack" || items[0].AuthMode != "managed_oauth" {
		t.Fatalf("items=%#v error=%v", items, err)
	}
	serialized, _ := json.Marshal(items[0])
	for _, forbidden := range []string{"nango", "service secret", "provider credential"} {
		if strings.Contains(strings.ToLower(string(serialized)), forbidden) {
			t.Fatalf("manifest leaked %q: %s", forbidden, serialized)
		}
	}
	if err := catalog.ValidateSetup("slack", map[string]string{"workspace_label": "Security operations"}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.ValidateSetup("slack", map[string]string{"workspace_label": ""}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty label error=%v", err)
	}
}

func fixtureScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(fixtureID(t, 1), fixtureID(t, 2), fixtureID(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestConnectorManifestPublicBoundaryAndCatalog(t *testing.T) {
	catalog, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	items, err := catalog.Search(CatalogFilter{Query: "webhook", Category: "notification", Action: "approval_response"})
	if err != nil || len(items) != 1 {
		t.Fatalf("catalog=%+v err=%v", items, err)
	}
	encoded, err := json.Marshal(items[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"adapter", "oss", "nango", "provider_key"} {
		if json.Valid(encoded) && containsFold(string(encoded), forbidden) {
			t.Fatalf("public manifest leaked %q: %s", forbidden, encoded)
		}
	}
	if err := catalog.ValidateSetup("generic-webhook", map[string]string{
		"destination_url":          "https://hooks.customer.invalid/zasp",
		"signing_secret_reference": "secret_ref_1234",
	}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.ValidateSetup("aws", map[string]string{"role_arn": "arn:aws:iam::000000000000:role/zasp-read", "external_id_reference": "ref:aws/external-id-0001", "region": "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.ValidateSetup("github", map[string]string{"authorization_mode": "github_app"}); err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]map[string]string{
		"http":       {"destination_url": "http://customer.invalid/hook", "signing_secret_reference": "secret_ref_1234"},
		"query":      {"destination_url": "https://customer.invalid/hook?next=https://evil.invalid", "signing_secret_reference": "secret_ref_1234"},
		"per-action": {"destination_url": "https://customer.invalid/hook", "approval_url": "https://evil.invalid", "signing_secret_reference": "secret_ref_1234"},
		"loopback":   {"destination_url": "https://127.0.0.1/hook", "signing_secret_reference": "secret_ref_1234"},
	} {
		t.Run(name, func(t *testing.T) {
			if catalog.ValidateSetup("generic-webhook", config) == nil {
				t.Fatal("unsafe webhook config accepted")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := catalog.SearchContext(canceled, CatalogFilter{}); err == nil {
		t.Fatal("canceled catalog search accepted")
	}
}

func TestLaunchCatalogUsesFirstPartyAuthorizationForAWSKubernetesGitHubAndOkta(t *testing.T) {
	catalog, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	items, err := catalog.Search(CatalogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]PublicManifest{}
	for _, item := range items {
		seen[item.Key] = item
	}
	for _, key := range []string{"aws", "github", "kubernetes", "okta"} {
		item, ok := seen[key]
		if !ok || item.AuthMode == "nango_oauth" || item.AuthMode == "" {
			t.Fatalf("launch manifest %q = %#v, %t", key, item, ok)
		}
	}
	setups := map[string]map[string]string{"github": {"authorization_mode": "github_app"}, "kubernetes": {"connection_reference": "ref:kubernetes/connection-0001"}, "okta": {"issuer": "https://acme.okta.com"}}
	for key, setup := range setups {
		if err := catalog.ValidateSetup(key, setup); err != nil {
			t.Fatalf("%s setup rejected: %v", key, err)
		}
	}
}

func TestIntegrationLifecycleAndIdempotentSyncJob(t *testing.T) {
	sequence := 10
	generate := func() (domain.ProductID, error) { sequence++; return fixtureID(t, sequence), nil }
	now := func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
	service, err := NewService(NewMemoryStore(generate, now), mustCatalog(t), now)
	if err != nil {
		t.Fatal(err)
	}
	scope := fixtureScope(t)
	created, err := service.Create(context.Background(), scope, IntegrationInput{
		ConnectorKey: "generic-webhook", Name: "Response notifications",
		Configuration: map[string]string{"destination_url": "https://hooks.customer.invalid/zasp", "signing_secret_reference": "secret_ref_1234"},
	})
	if err != nil || created.Status() != IntegrationPendingAuthorization {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	if _, err := service.Authorize(context.Background(), scope, created.ID()); err != nil {
		t.Fatal(err)
	}
	sync, job, err := service.Sync(context.Background(), scope, created.ID(), "job_1234")
	if err != nil || sync.Status() != SyncQueued || job.JobID != "job_1234" || job.IntegrationID != created.ID() {
		t.Fatalf("sync=%+v job=%+v err=%v", sync, job, err)
	}
	duplicate, duplicateJob, err := service.Sync(context.Background(), scope, created.ID(), "job_1234")
	if err != nil || duplicate.ID() != sync.ID() || duplicateJob != job {
		t.Fatalf("duplicate sync was not idempotent: %+v %+v %v", duplicate, duplicateJob, err)
	}
	for _, transition := range []SyncStatus{SyncRunning, SyncSucceeded} {
		current, err := service.Transition(context.Background(), job, transition)
		if err != nil || current.Status() != transition {
			t.Fatalf("transition=%s current=%+v err=%v", transition, current, err)
		}
	}
	if _, err := service.Transition(context.Background(), job, SyncRunning); err == nil {
		t.Fatal("terminal sync moved backwards")
	}
	second, err := service.Create(context.Background(), scope, IntegrationInput{
		ConnectorKey: "generic-webhook", Name: "Second notifications",
		Configuration: map[string]string{"destination_url": "https://hooks.customer.invalid/second", "signing_secret_reference": "secret_ref_1234"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(context.Background(), scope, second.ID(), IntegrationUpdate{Name: created.Name(), Configuration: second.Configuration()}); err != ErrConflict {
		t.Fatalf("duplicate update error=%v", err)
	}
	listed, err := service.ListSyncs(context.Background(), scope, created.ID())
	if err != nil || len(listed) != 1 || listed[0].ID() != sync.ID() {
		t.Fatalf("listed=%+v err=%v", listed, err)
	}
	foreign, _ := domain.NewScope(fixtureID(t, 20), fixtureID(t, 21), fixtureID(t, 22))
	if _, err := service.Get(context.Background(), foreign, created.ID()); err != ErrForbidden {
		t.Fatalf("foreign error=%v", err)
	}
}

func mustCatalog(t *testing.T) *Catalog {
	t.Helper()
	catalog, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestServiceNilReceiverFailsClosed(t *testing.T) {
	var service *Service
	scope := fixtureScope(t)
	id := fixtureID(t, 30)
	checks := []func() error{
		func() error { _, err := service.Catalog(context.Background(), CatalogFilter{}); return err },
		func() error { _, err := service.List(context.Background(), scope); return err },
		func() error { _, err := service.Get(context.Background(), scope, id); return err },
		func() error {
			_, err := service.Update(context.Background(), scope, id, IntegrationUpdate{})
			return err
		},
		func() error { return service.Delete(context.Background(), scope, id) },
		func() error { _, err := service.Authorize(context.Background(), scope, id); return err },
		func() error { _, err := service.ListSyncs(context.Background(), scope, id); return err },
		func() error { _, err := service.GetSync(context.Background(), scope, id, id); return err },
	}
	for index, check := range checks {
		if err := check(); err == nil {
			t.Fatalf("nil service check %d succeeded", index)
		}
	}
}

func saasSetup(key string) map[string]string {
	if key == "microsoft" {
		return map[string]string{"tenant_id": "0a1b2c3d-1111-2222-3333-444455556666", "client_id": "11111111-2222-3333-4444-555555555555", "client_secret_reference": "ref:microsoft/client-secret/customer-0001"}
	}
	return map[string]string{"instance_url": "https://acme.my.salesforce.com", "organization_id": "00D5e000000abcdEAA", "client_id": "3MVG9abcdefghijklmnopqrstuvwxyz.ABCDEF_0123456789", "client_secret_reference": "ref:salesforce/client-secret/customer-0001"}
}

func TestMicrosoftAndSalesforceManifestsAreFirstPartySaaSEntries(t *testing.T) {
	catalog, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	items, err := catalog.Search(CatalogFilter{Category: "saas"})
	if err != nil || len(items) != 2 || items[0].Key != "microsoft" || items[1].Key != "salesforce" {
		t.Fatalf("saas catalog=%#v err=%v", items, err)
	}
	if items[0].Provider != "Microsoft Entra and Copilot Studio" || items[1].Provider != "Salesforce Agentforce" {
		t.Fatalf("provider names = %q, %q", items[0].Provider, items[1].Provider)
	}
	wantFields := map[string][]SetupField{
		"microsoft":  {{Key: "tenant_id", Type: "string", Required: true}, {Key: "client_id", Type: "string", Required: true}, {Key: "client_secret_reference", Type: "secret_reference", Required: true}, {Key: "dataverse_url", Type: "uri", Required: false}},
		"salesforce": {{Key: "instance_url", Type: "uri", Required: true}, {Key: "organization_id", Type: "string", Required: true}, {Key: "client_id", Type: "string", Required: true}, {Key: "client_secret_reference", Type: "secret_reference", Required: true}},
	}
	for _, item := range items {
		if item.AuthMode != "oauth_client_credentials" || !containsExact(item.Actions, "inventory_read") || !containsExact(item.DataTypes, "agent") {
			t.Fatalf("%s manifest = %#v", item.Key, item)
		}
		want := wantFields[item.Key]
		if len(item.SetupSchema) != len(want) {
			t.Fatalf("%s setup schema = %#v", item.Key, item.SetupSchema)
		}
		for index, field := range item.SetupSchema {
			if field.Key != want[index].Key || field.Type != want[index].Type || field.Required != want[index].Required || field.Label == "" || field.Description == "" {
				t.Fatalf("%s field %d = %#v, want %#v", item.Key, index, field, want[index])
			}
		}
		// The catalog says what the customer must grant, and never carries a
		// secret or an implementation name.
		serialized, _ := json.Marshal(item)
		for _, forbidden := range []string{"adapter", "oss", "nango", "graph-dataverse", "salesforce-rest"} {
			if containsFold(string(serialized), `"`+forbidden) {
				t.Fatalf("%s manifest leaked %q: %s", item.Key, forbidden, serialized)
			}
		}
	}
	for _, permission := range []string{"Application.Read.All", "AgentIdentity.Read.All", "admin consent", "application user", "read access to bot"} {
		if !strings.Contains(items[0].AccessGuidance, permission) {
			t.Fatalf("microsoft access guidance omits %q: %s", permission, items[0].AccessGuidance)
		}
	}
	for _, permission := range []string{"client credentials flow", "scope api", "run-as user", "API Enabled", "View Setup and Configuration"} {
		if !strings.Contains(items[1].AccessGuidance, permission) {
			t.Fatalf("salesforce access guidance omits %q: %s", permission, items[1].AccessGuidance)
		}
	}
}

func TestMicrosoftAndSalesforceSetupValidatesEveryConfigurationField(t *testing.T) {
	catalog, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.ValidateSetup("microsoft", saasSetup("microsoft")); err != nil {
		t.Fatalf("microsoft setup without Dataverse: %v", err)
	}
	withDataverse := saasSetup("microsoft")
	for _, environment := range []string{"https://org1234.crm.dynamics.com", "https://org1234.crm4.dynamics.com", "https://a.crm11.dynamics.com"} {
		withDataverse["dataverse_url"] = environment
		if err := catalog.ValidateSetup("microsoft", withDataverse); err != nil {
			t.Fatalf("microsoft setup with %s: %v", environment, err)
		}
	}
	if err := catalog.ValidateSetup("salesforce", saasSetup("salesforce")); err != nil {
		t.Fatalf("salesforce setup: %v", err)
	}
	for _, instance := range []string{"https://acme--uat.sandbox.my.salesforce.com", "https://a.my.salesforce.com", "https://acme.develop.my.salesforce.com"} {
		setup := saasSetup("salesforce")
		setup["instance_url"] = instance
		if err := catalog.ValidateSetup("salesforce", setup); err != nil {
			t.Fatalf("salesforce setup with %s: %v", instance, err)
		}
	}

	type refusal struct{ connector, field, value string }
	refusals := []refusal{
		// Bad GUIDs.
		{"microsoft", "tenant_id", "contoso.onmicrosoft.com"},
		{"microsoft", "tenant_id", "0A1B2C3D-1111-2222-3333-444455556666"},
		{"microsoft", "tenant_id", "0a1b2c3d111122223333444455556666"},
		{"microsoft", "tenant_id", "{0a1b2c3d-1111-2222-3333-444455556666}"},
		{"microsoft", "client_id", "not-a-guid"},
		{"microsoft", "client_id", "11111111-2222-3333-4444-55555555555"},
		// A reference, of this provider's client-secret class only; never a value.
		{"microsoft", "client_secret_reference", "Abc~1234567890.secret-value_abcdefgh"},
		{"microsoft", "client_secret_reference", "ref:salesforce/client-secret/customer-0001"},
		{"microsoft", "client_secret_reference", "ref:microsoft/client-secret/short"},
		{"microsoft", "client_secret_reference", "ref:microsoft/client-secret/Customer-0001"},
		{"microsoft", "client_secret_reference", "ref:microsoft/client-secret/customer-0001/child"},
		{"microsoft", "client_secret_reference", "ref:microsoft/refresh/customer-0001"},
		{"microsoft", "client_secret_reference", "secret_ref_customer_0001"},
		// Dataverse: HTTPS, the exact host shape, nothing after the host.
		{"microsoft", "dataverse_url", "http://org1234.crm4.dynamics.com"},
		{"microsoft", "dataverse_url", "https://org1234.crm4.dynamics.com/"},
		{"microsoft", "dataverse_url", "https://org1234.crm4.dynamics.com:8443"},
		{"microsoft", "dataverse_url", "https://org1234.crm4.dynamics.com.evil.example"},
		{"microsoft", "dataverse_url", "https://evil.example/org1234.crm4.dynamics.com"},
		{"microsoft", "dataverse_url", "https://user@org1234.crm4.dynamics.com"},
		{"microsoft", "dataverse_url", "https://org1234.api.dynamics.com"},
		{"microsoft", "dataverse_url", "https://org1234.crm123.dynamics.com"},
		{"microsoft", "dataverse_url", "https://ORG1234.crm4.dynamics.com"},
		{"microsoft", "dataverse_url", ""},
		// Salesforce: the My Domain over HTTPS.
		{"salesforce", "instance_url", "http://acme.my.salesforce.com"},
		{"salesforce", "instance_url", "https://login.salesforce.com"},
		{"salesforce", "instance_url", "https://acme.my.salesforce.com/"},
		{"salesforce", "instance_url", "https://acme.my.salesforce.com.evil.example"},
		{"salesforce", "instance_url", "https://evil.example/acme.my.salesforce.com"},
		{"salesforce", "instance_url", "https://acme.my.salesforce.com:8443"},
		{"salesforce", "instance_url", "https://acme.lightning.force.com"},
		{"salesforce", "instance_url", "https://my.salesforce.com"},
		{"salesforce", "organization_id", "00D5e000000abcd"},
		{"salesforce", "organization_id", "0055e000000abcdEAA"},
		{"salesforce", "organization_id", "00D5e000000abcdEA!"},
		{"salesforce", "client_id", "short"},
		{"salesforce", "client_id", "consumer key with spaces 0001"},
		{"salesforce", "client_id", strings.Repeat("a", 257)},
		{"salesforce", "client_secret_reference", "ref:microsoft/client-secret/customer-0001"},
		{"salesforce", "client_secret_reference", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"},
		{"salesforce", "client_secret_reference", "ref:salesforce/client-secret/x"},
	}
	for _, test := range refusals {
		setup := saasSetup(test.connector)
		setup[test.field] = test.value
		if err := catalog.ValidateSetup(test.connector, setup); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s %s=%q error=%v", test.connector, test.field, test.value, err)
		}
	}
	// Every required field is required, and nothing unknown is accepted.
	for _, connector := range []string{"microsoft", "salesforce"} {
		for field := range saasSetup(connector) {
			setup := saasSetup(connector)
			delete(setup, field)
			if err := catalog.ValidateSetup(connector, setup); !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s without %s error=%v", connector, field, err)
			}
		}
		setup := saasSetup(connector)
		setup["client_secret"] = "a-secret-value-in-the-configuration"
		if err := catalog.ValidateSetup(connector, setup); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s with an unknown field error=%v", connector, err)
		}
	}
	// The optional field belongs to Microsoft only.
	salesforce := saasSetup("salesforce")
	salesforce["dataverse_url"] = "https://org1234.crm4.dynamics.com"
	if err := catalog.ValidateSetup("salesforce", salesforce); !errors.Is(err, ErrInvalid) {
		t.Fatalf("salesforce with a Dataverse URL error=%v", err)
	}
	// The connectors with only required fields still need exactly those.
	if err := catalog.ValidateSetup("kubernetes", map[string]string{"connection_reference": "ref:kubernetes/connection/customer-0001", "extra": "value"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("kubernetes with an extra field error=%v", err)
	}
	if err := catalog.ValidateSetup("okta", map[string]string{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("okta without its issuer error=%v", err)
	}
}

func TestManifestSetupSchemaAllowsOptionalFieldsButNotOnlyOptionalOnes(t *testing.T) {
	base := BuiltinManifests()[0]
	optionalOnly := base
	optionalOnly.SetupSchema = []SetupField{{Key: "label", Label: "Label", Type: "string", Required: false, Description: "Optional label."}}
	if _, err := NewCatalog([]ConnectorManifest{optionalOnly}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("manifest with only optional fields error=%v", err)
	}
	duplicate := base
	duplicate.SetupSchema = append(append([]SetupField(nil), base.SetupSchema...), base.SetupSchema[0])
	if _, err := NewCatalog([]ConnectorManifest{duplicate}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("manifest with a duplicate field error=%v", err)
	}
}
