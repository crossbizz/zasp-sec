package kubernetesdiscovery

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type automaticSnapshotArtifacts struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *automaticSnapshotArtifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object.VersionID = fmt.Sprintf("version-%x", object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}
func (store *automaticSnapshotArtifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object, ok := store.objects[locator.Key+"/"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("missing owned artifact")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}
func (store *automaticSnapshotArtifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}
func (*automaticSnapshotArtifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://automatic-discovery-evidence/" + locator.Key, nil
}

func TestAutomaticDiscoveryFullCollectionMeetsTypedSnapshotGrammar(t *testing.T) {
	transport := &kubernetesRoundTripper{}
	for _, phase := range [][2]string{{"v1", "Namespace"}, {"v1", "ServiceAccount"}, {"rbac.authorization.k8s.io/v1", "Role"}, {"rbac.authorization.k8s.io/v1", "ClusterRole"}, {"rbac.authorization.k8s.io/v1", "RoleBinding"}, {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"}, {"apps/v1", "Deployment"}, {"apps/v1", "StatefulSet"}, {"apps/v1", "DaemonSet"}, {"batch/v1", "Job"}, {"batch/v1", "CronJob"}} {
		items := `[]`
		switch phase[1] {
		case "Namespace":
			items = `[{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"ns-zasp","name":"zasp"}}]`
		case "ServiceAccount":
			items = `[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"uid":"sa-support","name":"support","namespace":"zasp"}}]`
		case "Deployment":
			items = `[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"deployment-scheduled-agent","name":"scheduled-agent","namespace":"zasp","labels":{"zasp.ai/entity-kind":"agent"}},"spec":{"template":{"spec":{"serviceAccountName":"support","containers":[{"name":"agent","image":"example/agent:v1"}]}}}}]`
		}
		transport.responses = append(transport.responses, kubernetesHTTPResponse{status: 200, body: fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"continue":""},"items":%s}`, phase[0], phase[1]+"List", items)})
	}
	api, err := newKubernetesCollectionAPI("https://prod.example", transport, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driver := &automaticSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]domain.ProductID, 6)
	for i := range ids {
		ids[i], err = domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", i+1, i+1))
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderKubernetes, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialKubernetesCluster, CredentialReference: "ref:kubernetes/cluster/e2e-a", ExpectedSubject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "prod.example/cluster-a"}, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second}}
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte("local-e2e-credential-material"))
	t.Logf("collection pages=%d artifacts=%d outcome=%T error=%v", len(transport.requests), len(driver.objects), outcome, err)
	// Diagnose every persisted normalized entity against the strict public
	// snapshot constructor, without replacing the collection outcome.
	for _, object := range driver.objects {
		var page struct {
			Entities []json.RawMessage `json:"entities"`
		}
		if json.Unmarshal(object.Body, &page) != nil {
			t.Fatal("invalid artifact")
		}
		for _, entity := range page.Entities {
			_, candidateErr := collection.NewSnapshotCandidate(collection.ProviderKubernetes, "parser_v1", "tool_v1", append(append([]byte{'['}, entity...), ']'), []byte(`[]`), []byte(`[]`))
			if candidateErr != nil {
				t.Logf("artifact entity rejected: %s", entity)
			}
		}
	}
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("valid full inventory rejected: %v", err)
	}
	snapshot := complete.Snapshot()
	if len(transport.requests) != 11 || len(driver.objects) != 12 || !snapshot.TypedObservations() || snapshot.EntityCount() != 4 || snapshot.RelationshipCount() != 4 || snapshot.EvidenceCount() != 4 {
		t.Fatalf("incomplete typed inventory: pages=%d artifacts=%d entities=%d relationships=%d evidence=%d", len(transport.requests), len(driver.objects), snapshot.EntityCount(), snapshot.RelationshipCount(), snapshot.EvidenceCount())
	}
}

func TestKubernetesEntityCanonicalBoundaryPreservesAllValues(t *testing.T) {
	stable := json.RawMessage(`{"z":9007199254740993,"a":{"z":[{"b":true,"a":null},"<unchanged>",1.25],"a":"cluster"}}`)
	attributes := json.RawMessage(`{"z":false,"a":{"z":18,"a":["second","first"]}}`)
	entity, err := marshalKubernetesEntity("pid_00000001-0000-4000-8000-000000000001", "kubernetes_agent", "native-agent", "Agent", stable, attributes)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(entity, &fields) != nil {
		t.Fatal("invalid emitted record")
	}
	for key, original := range map[string]json.RawMessage{"stable_fields": stable, "attributes": attributes} {
		decode := func(raw []byte) any {
			var value any
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		before, after := decode(original), decode(fields[key])
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("%s values changed: before=%v after=%v", key, before, after)
		}
		canonical, err := json.Marshal(before)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fields[key], canonical) {
			t.Fatalf("%s not recursively canonical: %s", key, fields[key])
		}
	}
}

func TestAutomaticDiscoveryAgentPageMeetsSnapshotGrammar(t *testing.T) {
	automaticDiscoveryAgentSnapshotGrammar(t, false)
}

func TestAutomaticDiscoveryAnnotatedAgentPageMeetsSnapshotGrammar(t *testing.T) {
	automaticDiscoveryAgentSnapshotGrammar(t, true)
}

func automaticDiscoveryAgentSnapshotGrammar(t *testing.T, annotated bool) {
	t.Helper()
	// The browser provider returns this same valid Kubernetes deployment. A
	// normalized page must survive the production snapshot contract unchanged.
	transport := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: 200, body: `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"deployment-scheduled-agent","name":"scheduled-agent","namespace":"zasp","labels":{"zasp.ai/entity-kind":"agent"}},"spec":{"template":{"spec":{"serviceAccountName":"support","containers":[{"name":"agent","image":"example/agent:v1"}]}}}}]}`}}}
	if annotated {
		transport.responses[0].body = strings.Replace(transport.responses[0].body, `"labels":`, `"annotations":{"zasp.ai/red-team-enabled":"true","zasp.ai/red-team-endpoint":"https://agent.example.test/v1/evaluate","zasp.ai/red-team-credential-reference":"ref:red-team/fixture_credential","zasp.ai/red-team-target-kinds":"agent_endpoint"},"labels":`, 1)
	}
	api, err := newKubernetesCollectionAPI("https://prod.example", transport, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "prod.example/cluster-a"}
	page, err := api.FetchCollectionPage(context.Background(), []byte("local-e2e-credential-material"), CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "deployments", 7, "start"), Page: 7, RemainingItems: 1000, RemainingRelationships: 2000, RemainingBytes: 64 << 20})
	if err != nil || len(page.Entities) != 1 {
		t.Fatalf("provider page: entities=%d err=%v", len(page.Entities), err)
	}
	var entity struct {
		Attributes json.RawMessage `json:"attributes"`
	}
	if err := json.Unmarshal(page.Entities[0], &entity); err != nil {
		t.Fatal(err)
	}
	var attributes map[string]any
	if err := json.Unmarshal(entity.Attributes, &attributes); err != nil {
		t.Fatal(err)
	}
	if _, present := attributes["red_team"]; present != annotated {
		t.Fatal("annotation fixture was not preserved")
	}
	canonical, err := json.Marshal(attributes)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("provider attributes canonical=%t actual=%s canonical=%s", bytes.Equal(entity.Attributes, canonical), entity.Attributes, canonical)
	entities, _ := json.Marshal(page.Entities)
	// Change only attribute key ordering. This reference isolates the rejected
	// boundary without changing IDs, field values or snapshot validation.
	reference := bytes.Replace(entities, entity.Attributes, canonical, 1)
	if _, err := collection.NewSnapshotCandidate(collection.ProviderKubernetes, "parser_v1", "tool_v1", reference, []byte(`[]`), []byte(`[]`)); err != nil {
		t.Fatal("canonical attribute reference rejected:", err)
	}
	_, err = collection.NewSnapshotCandidate(collection.ProviderKubernetes, "parser_v1", "tool_v1", entities, []byte(`[]`), []byte(`[]`))
	if err != nil {
		t.Fatalf("production page rejected by snapshot grammar: %v", err)
	}
}

type pinnedCollectionDialFunc func(context.Context, string, string) (net.Conn, error)

func (dial pinnedCollectionDialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dial(ctx, network, address)
}

func TestPinnedKubernetesCollectionRetainsTrustAnchorThroughRealTLS(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/version" {
			http.Error(w, "invalid request", 400)
			return
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"gitVersion":"v1.31.0"}`))
	}))
	defer server.Close()
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	build := func(host string, ca []byte) *KubernetesCollectionAPI {
		api, err := NewPinnedKubernetesCollectionAPIWithNetwork(PinnedCollectionAPIConfig{Endpoint: "https://" + host, CABundlePEM: ca, AllowedCIDRs: []string{"203.0.113.0/24"}, Timeout: time.Second}, CollectionNetwork{Resolver: &pinnedCollectionResolverStub{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}}}, Dialer: pinnedCollectionDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "203.0.113.8:443" {
				return nil, errors.New("unexpected pinned destination")
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		})})
		if err != nil {
			t.Fatal(err)
		}
		return api
	}
	// Working reference: identical transport and verifier, with a separately
	// owned parsed trust anchor. No insecure TLS setting or hostname override.
	reference := build("example.com", bundle)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		t.Fatal("fixture root rejected")
	}
	reference.client.Transport.(collection.EffectTransport).Next.(*http.Transport).TLSClientConfig.RootCAs = roots
	if err := reference.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatal("working independently owned root failed:", err)
	}
	if requests.Load() != 1 {
		t.Fatal("reference did not reach HTTPS provider")
	}
	actual := build("example.com", bundle)
	if err := actual.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatal("production pinned path lost parsed trust anchor:", err)
	}
	if requests.Load() != 2 {
		t.Fatal("production TLS did not reach provider")
	}
	for _, api := range []*KubernetesCollectionAPI{build("foreign.example.test", bundle), build("example.com", []byte(testPinnedCertificatePEM))} {
		if err := api.CheckCollectionReadiness(context.Background()); err == nil {
			t.Fatal("foreign hostname or CA trusted")
		}
	}
	if requests.Load() != 2 {
		t.Fatal("rejected TLS reached provider")
	}
}

type pinnedCollectionResolverStub struct {
	addresses []net.IPAddr
	err       error
	calls     int
}

func (stub *pinnedCollectionResolverStub) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	stub.calls++
	return append([]net.IPAddr(nil), stub.addresses...), stub.err
}

type pinnedCollectionDialerStub struct {
	network, address string
	calls            int
	err              error
}

func (stub *pinnedCollectionDialerStub) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	stub.calls++
	stub.network, stub.address = network, address
	return nil, stub.err
}

func TestPinnedKubernetesCollectionDialRequiresAllDNSAnswersAllowedAndPinsIP(t *testing.T) {
	resolver := &pinnedCollectionResolverStub{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}, {IP: net.ParseIP("2001:db8::8")}}}
	dialer := &pinnedCollectionDialerStub{err: errors.New("dial stopped")}
	api, err := newPinnedKubernetesCollectionAPI(PinnedCollectionAPIConfig{Endpoint: "https://cluster.example.test", CABundlePEM: []byte(testPinnedCertificatePEM), AllowedCIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}, Timeout: time.Second}, resolver, dialer)
	if err != nil {
		t.Fatal(err)
	}
	transport := api.client.Transport.(collection.EffectTransport).Next.(*http.Transport)
	_, err = transport.DialContext(context.Background(), "tcp", "cluster.example.test:443")
	if err == nil || dialer.calls != 1 || dialer.address != "203.0.113.8:443" || resolver.calls != 1 || transport.Proxy != nil || transport.TLSClientConfig.ServerName != "cluster.example.test" {
		t.Fatalf("pinning not exact: resolver=%#v dialer=%#v transport=%#v err=%v", resolver, dialer, transport, err)
	}

	resolver.addresses = append(resolver.addresses, net.IPAddr{IP: net.ParseIP("10.0.0.8")})
	dialer.calls = 0
	if _, err := transport.DialContext(context.Background(), "tcp", "cluster.example.test:443"); err == nil || dialer.calls != 0 {
		t.Fatal("mixed allowed/private DNS answer reached dialer")
	}
}

func TestPinnedKubernetesCollectionRejectsAuthorityDrift(t *testing.T) {
	valid := PinnedCollectionAPIConfig{Endpoint: "https://cluster.example.test", CABundlePEM: []byte(testPinnedCertificatePEM), AllowedCIDRs: []string{"203.0.113.0/24"}, Timeout: time.Second}
	tests := []func(*PinnedCollectionAPIConfig){
		func(config *PinnedCollectionAPIConfig) { config.AllowedCIDRs = nil },
		func(config *PinnedCollectionAPIConfig) { config.AllowedCIDRs = []string{"203.0.113.1/24"} },
		func(config *PinnedCollectionAPIConfig) { config.AllowedCIDRs = []string{"0.0.0.0/0"} },
		func(config *PinnedCollectionAPIConfig) {
			config.CABundlePEM = append(config.CABundlePEM, []byte("trailing")...)
		},
		func(config *PinnedCollectionAPIConfig) { config.Endpoint = "https://127.0.0.1" },
	}
	for index, mutate := range tests {
		config := valid
		config.CABundlePEM = append([]byte(nil), valid.CABundlePEM...)
		config.AllowedCIDRs = append([]string(nil), valid.AllowedCIDRs...)
		mutate(&config)
		if _, err := newPinnedKubernetesCollectionAPI(config, &pinnedCollectionResolverStub{}, &pinnedCollectionDialerStub{}); err == nil {
			t.Fatalf("hostile config %d accepted", index)
		}
	}
}

func TestPinnedKubernetesCollectionRejectsWrongDialHostAndUnboundedDNS(t *testing.T) {
	resolver := &pinnedCollectionResolverStub{addresses: make([]net.IPAddr, 17)}
	for index := range resolver.addresses {
		resolver.addresses[index] = net.IPAddr{IP: net.ParseIP("203.0.113." + strconv.Itoa(index+1))}
	}
	dialer := &pinnedCollectionDialerStub{}
	api, err := newPinnedKubernetesCollectionAPI(PinnedCollectionAPIConfig{Endpoint: "https://cluster.example.test", CABundlePEM: []byte(testPinnedCertificatePEM), AllowedCIDRs: []string{"203.0.113.0/24"}, Timeout: time.Second}, resolver, dialer)
	if err != nil {
		t.Fatal(err)
	}
	transport := api.client.Transport.(collection.EffectTransport).Next.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "other.example.test:443"); err == nil || dialer.calls != 0 {
		t.Fatal("foreign host reached dialer")
	}
	_, dialErr := transport.DialContext(context.Background(), "tcp", "cluster.example.test:443")
	if dialErr == nil || dialer.calls != 0 {
		t.Fatal("unbounded DNS set reached dialer")
	}
	if strings.Contains(dialErr.Error(), "cluster.example.test") {
		t.Fatal("stable error exposed endpoint")
	}
}

const testPinnedCertificatePEM = `-----BEGIN CERTIFICATE-----
MIICvjCCAaYCCQCa7cxZ6Y3MiTANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZ6
YXNwLWRpc2NvdmVyeS10ZXN0LWNhMB4XDTI2MDgyMDA5MTQxNloXDTM2MDgxNzA5
MTQxNlowITEfMB0GA1UEAwwWemFzcC1kaXNjb3ZlcnktdGVzdC1jYTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANh6kp693Js5s/ywepHGGfE7RTk1pt1w
PkPnqrnKa4t1WXrvITg1qedB3L3RvvXBPXYGV+8VOba4rmA7utEO0sHcbzfINGYq
wkdpOtuh+RwLmCNV23ON+snR9NbKtqeFB1Res/AkWvynIFotV5dw8Hx2AgMzBjy8
Hcffg28rN0C4GwzevV/kZ/rJFKsaK2NQR13khiTdVsbxoVPyI059T0iJ1/C4HthH
hL30/vtPdCQrAWmUri/+v/mCVbNaObBSQSx+1IlWWyXcngJyIaV5UF7r0gJtmPxq
dy9QJDcg129UYtEI1nrDFOQarinotqi3Piul6KEEWpCfV8XPAejRPlkCAwEAATAN
BgkqhkiG9w0BAQsFAAOCAQEAMH7DRwGWSGQsgYZ60GHATgxtjMgyPdj25gdgAs4l
mpWnq1ZPjbip6qTKsieLLTwnbkTI2wH4TPq70ap9yopJVc0cmytAWzRT2IaECDp7
ZPrYLLzuZ9aco0pdECZZObO036RLWnPGWTr8uUnLiS6SCJKDYSBoltxHwYOxlGlC
MOcVZWwReBWmZPdqvXbWVJbcf1XnCYnaMOh57My+6HO5n/HTRFR6eGTx6gK9IL25
c+ycq4+Zi7euxAKVlGLmEVTLX9y09AQq9YOk8A8SWuYhYV+CcOduXy9k15O0OJIJ
bVTUV5LTcltIKutavvUDzuCeBB13DHmiz84JpOusjUjBQQ==
-----END CERTIFICATE-----
`
