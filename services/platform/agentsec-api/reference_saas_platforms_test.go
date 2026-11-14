package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
)

const (
	saasProbeConnection    = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	saasProbeConfiguration = `{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"databricks","tenant_id":"adb-1234567890123456.7.azuredatabricks.net"}`
)

// saasProbeProxy stands in for the Nango proxy adapter.
type saasProbeProxy struct {
	body  string
	err   error
	calls []string
}

func (proxy *saasProbeProxy) Do(_ context.Context, request nango.Request) (nango.ProxyResponse, error) {
	path := request.Path
	if request.Host != "" {
		path = "//" + request.Host + path
	}
	proxy.calls = append(proxy.calls, request.ConnectorKey+" "+request.ConnectionReference+" "+request.Method+" "+path+"?"+request.Query.Encode())
	if proxy.err != nil || len(request.Body) != 0 {
		return nango.ProxyResponse{}, proxy.err
	}
	return nango.ProxyResponse{StatusCode: http.StatusOK, Body: []byte(proxy.body)}, nil
}

func newSaaSProbe(t *testing.T, proxy *saasProbeProxy) *saasReferenceProbe {
	t.Helper()
	registry, err := platforms.Registry()
	if err != nil {
		t.Fatal(err)
	}
	return &saasReferenceProbe{registry: registry, proxy: proxy, clock: func() time.Time { return time.Now().UTC() }}
}

func saasProbeTarget(configuration string) apiserver.ReferenceAuthorizationTarget {
	return apiserver.ReferenceAuthorizationTarget{Provider: "saas", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: saasProbeConnection, Configuration: json.RawMessage(configuration)}
}

func TestSaaSReferenceProbeBindsTheConnectionToItsTenant(t *testing.T) {
	proxy := &saasProbeProxy{body: `{"metastore_id":"m","workspace_id":1234567890123456}`}
	probe := newSaaSProbe(t, proxy)
	subject, err := probe.ProbeReferenceAuthorization(context.Background(), saasProbeTarget(saasProbeConfiguration))
	if err != nil || subject != (apiserver.ReferenceAuthorizationSubject{Kind: "saas_tenant", ID: "databricks/adb-1234567890123456.7.azuredatabricks.net"}) {
		t.Fatalf("subject = %#v, %v", subject, err)
	}
	// One read, of the platform's tenant lookup, sent to the workspace's own
	// host with the platform's Nango key and the connection reference. No
	// token is involved.
	if len(proxy.calls) != 1 || proxy.calls[0] != "databricks "+saasProbeConnection+" GET //adb-1234567890123456.7.azuredatabricks.net/api/2.1/unity-catalog/current-metastore-assignment?" {
		t.Fatalf("calls = %v", proxy.calls)
	}

	// Slack is the same probe with another platform definition.
	slack := &saasProbeProxy{body: `{"ok":true,"team":{"id":"T024BE7LD","name":"Acme"}}`}
	subject, err = newSaaSProbe(t, slack).ProbeReferenceAuthorization(context.Background(), saasProbeTarget(`{"connection_reference":"`+saasProbeConnection+`","platform":"slack","tenant_id":"T024BE7LD"}`))
	if err != nil || subject.ID != "slack/T024BE7LD" || len(slack.calls) != 1 {
		t.Fatalf("slack subject = %#v, %v, calls %v", subject, err, slack.calls)
	}
}

// A customer-hosted platform is authorized against the host its tenant id
// names: the probe asks that host, the subject it binds the connection to
// carries the host, and so an integration cannot be moved to another host
// without being authorized again as another subject. A host that is not a
// public name is refused before anything is sent.
func TestSaaSReferenceProbePinsACustomerHostedTenantToItsHost(t *testing.T) {
	configuration := func(tenant string) string {
		return `{"connection_reference":"` + saasProbeConnection + `","platform":"gitlab_self_managed","tenant_id":"` + tenant + `"}`
	}
	proxy := &saasProbeProxy{body: `{"id":4242,"name":"Platform","full_path":"acme/platform"}`}
	subject, err := newSaaSProbe(t, proxy).ProbeReferenceAuthorization(context.Background(), saasProbeTarget(configuration("gitlab.acme-corp.com_4242")))
	if err != nil || subject != (apiserver.ReferenceAuthorizationSubject{Kind: "saas_tenant", ID: "gitlab_self_managed/gitlab.acme-corp.com_4242"}) {
		t.Fatalf("subject = %#v, %v", subject, err)
	}
	if len(proxy.calls) != 1 || proxy.calls[0] != "gitlab-pat "+saasProbeConnection+" GET //gitlab.acme-corp.com/api/v4/groups/4242?with_projects=false" {
		t.Fatalf("calls = %v", proxy.calls)
	}
	// The same group id on another host is another subject.
	other := &saasProbeProxy{body: `{"id":4242,"full_path":"acme/platform"}`}
	if moved, err := newSaaSProbe(t, other).ProbeReferenceAuthorization(context.Background(), saasProbeTarget(configuration("git.other-corp.com_4242"))); err != nil || moved.ID == subject.ID || !strings.Contains(other.calls[0], "//git.other-corp.com/") {
		t.Fatalf("another host: %#v, %v, %v", moved, err, other.calls)
	}
	// The host answers for another group than the tenant id names.
	wrong := &saasProbeProxy{body: `{"id":4243,"full_path":"acme/other"}`}
	if _, err := newSaaSProbe(t, wrong).ProbeReferenceAuthorization(context.Background(), saasProbeTarget(configuration("gitlab.acme-corp.com_4242"))); err == nil {
		t.Fatal("a connection of another group was authorized")
	}
	for _, tenant := range []string{"10.0.0.5_4242", "localhost_4242", "gitlab.corp.internal_4242", "nango.zasp.svc.cluster.local_1", "gitlab_4242", "gitlab.acme-corp.com", "4242"} {
		refused := &saasProbeProxy{body: `{"id":4242}`}
		if _, err := newSaaSProbe(t, refused).ProbeReferenceAuthorization(context.Background(), saasProbeTarget(configuration(tenant))); err == nil || len(refused.calls) != 0 {
			t.Errorf("tenant %q: err %v, calls %v", tenant, err, refused.calls)
		}
	}
}

func TestSaaSReferenceProbeRefusesAnotherTenantAndUnknownPlatforms(t *testing.T) {
	for name, test := range map[string]struct {
		configuration, body string
		err                 error
		calls               int
	}{
		"the connection reaches another workspace": {saasProbeConfiguration, `{"workspace_id":9999999999999999}`, nil, 1},
		"the platform names no tenant":             {saasProbeConfiguration, `{"metastore_id":"m"}`, nil, 1},
		"the provider refuses the connection":      {saasProbeConfiguration, "", &nango.StatusError{StatusCode: http.StatusForbidden}, 1},
		"Nango is unreachable":                     {saasProbeConfiguration, "", nango.ErrProxy, 1},
		"an unregistered platform":                 {`{"connection_reference":"` + saasProbeConnection + `","platform":"zendesk","tenant_id":"dev12345"}`, `{}`, nil, 0},
		"a tenant id of another grammar":           {`{"connection_reference":"` + saasProbeConnection + `","platform":"databricks","tenant_id":"T024BE7LD"}`, `{}`, nil, 0},
		"another connection than the target's":     {`{"connection_reference":"ref:nango/connection/22222222-2222-4222-8222-222222222222","platform":"databricks","tenant_id":"adb-1234567890123456.7.azuredatabricks.net"}`, `{}`, nil, 0},
		"a reference that is not a connection":     {`{"connection_reference":"ref:nango/service-key-0001","platform":"databricks","tenant_id":"adb-1234567890123456.7.azuredatabricks.net"}`, `{}`, nil, 0},
		"an unknown member":                        {`{"connection_reference":"` + saasProbeConnection + `","platform":"databricks","tenant_id":"adb-1234567890123456.7.azuredatabricks.net","access_token":"dapi"}`, `{}`, nil, 0},
	} {
		proxy := &saasProbeProxy{body: test.body, err: test.err}
		subject, err := newSaaSProbe(t, proxy).ProbeReferenceAuthorization(context.Background(), saasProbeTarget(test.configuration))
		if !errors.Is(err, errRuntimeUnavailable) || subject != (apiserver.ReferenceAuthorizationSubject{}) || len(proxy.calls) != test.calls {
			t.Fatalf("%s: subject=%#v err=%v calls=%d", name, subject, err, len(proxy.calls))
		}
	}
}

// The API serves the saas provider only where the deployment sets the
// collector version, and never without Nango.
func TestRuntimeConfigServesSaaSOnlyWithNango(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	unset, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || unset.SaaSCollectorVersion != "" {
		t.Fatalf("default config: %q %v", unset.SaaSCollectorVersion, err)
	}
	values["ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION"] = "collector_v1"
	if _, err := loadRuntimeConfig(func(key string) string { return values[key] }); !errors.Is(err, errInvalidRuntimeConfig) {
		t.Fatalf("saas without Nango: %v", err)
	}
	values["ZASP_NANGO_BASE_URL"], values["ZASP_NANGO_SERVICE_SECRET_REFERENCE"], values["ZASP_NANGO_ENVIRONMENT"] = "http://nango.zasp.svc.cluster.local:3003", "ref:nango/service-key-0001", "prod"
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || config.SaaSCollectorVersion != "collector_v1" {
		t.Fatalf("saas with Nango: %q %v", config.SaaSCollectorVersion, err)
	}
	values["ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION"] = "Collector V1"
	if _, err := loadRuntimeConfig(func(key string) string { return values[key] }); !errors.Is(err, errInvalidRuntimeConfig) {
		t.Fatalf("malformed version: %v", err)
	}
	// The production probe is built from the platform registry.
	probe, closer, err := newProductionSaaSReferenceProbe(config, &nangoServiceSecretResolver{path: "/var/run/secrets/zasp-nango/service-key"})
	if err != nil || probe == nil || closer == nil || probe.registry == nil {
		t.Fatalf("production probe: %v", err)
	}
	_ = closer.Close()
	if _, _, err := newProductionSaaSReferenceProbe(unset, &nangoServiceSecretResolver{path: "/var/run/secrets/zasp-nango/service-key"}); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("probe without the saas version: %v", err)
	}
}
