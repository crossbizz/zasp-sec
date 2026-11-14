package kubernetesdiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// kubernetesClusterStub answers a request by its path, however often it is
// asked: the link phase reads the workloads a second time.
type kubernetesClusterStub struct {
	mu       sync.Mutex
	lists    map[string]string
	statuses map[string]int
	requests []string
}

func (stub *kubernetesClusterStub) RoundTrip(request *http.Request) (*http.Response, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.requests = append(stub.requests, request.URL.Path+"?"+request.URL.RawQuery)
	status, body := http.StatusOK, stub.lists[request.URL.Path]
	if refused, set := stub.statuses[request.URL.Path]; set {
		status, body = refused, `{"kind":"Status","status":"Failure"}`
	} else if body == "" {
		status, body = http.StatusNotFound, `{"kind":"Status","status":"Failure","code":404}`
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func kubernetesListBody(apiVersion, kind, items string) string {
	return fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"continue":""},"items":[%s]}`, apiVersion, kind+"List", items)
}

// The cluster of the link tests: two MCP servers behind Services, and agents
// that name them in an environment value, in a ConfigMap and in an argument.
func kubernetesLinkCluster() *kubernetesClusterStub {
	deployment := func(uid, namespace, name, labels, templateLabels, containers, volumes string) string {
		return fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":%q,"name":%q,"namespace":%q%s},"spec":{"selector":{"matchLabels":{"app":%q}},"template":{"metadata":{"labels":%s},"spec":{"serviceAccountName":"default","containers":[%s]%s}}}}`,
			uid, name, namespace, labels, name, templateLabels, containers, volumes)
	}
	agentLabel := `,"labels":{"zasp.ai/entity-kind":"agent"}`
	deployments := strings.Join([]string{
		deployment("d-docs-mcp", "tools", "docs-mcp", "", `{"app":"docs-mcp","tier":"mcp"}`, `{"name":"server","image":"ghcr.io/acme/docs-mcp-server:2"}`, ""),
		deployment("d-tickets-mcp", "shop", "tickets-mcp", "", `{"app":"tickets-mcp"}`, `{"name":"server","image":"registry.example/mcp/tickets:1"}`, ""),
		// Names the docs server by its full Service name, in an environment value.
		deployment("d-support", "shop", "support-agent", agentLabel, `{"app":"support-agent"}`,
			`{"name":"agent","image":"registry.example/shop/support:4","env":[{"name":"DOCS_MCP_URL","value":"http://docs-mcp.tools.svc.cluster.local:8080/mcp"},{"name":"API_TOKEN","value":"tok-do-not-keep-0001"}]}`, ""),
		// Reads the tickets server's address from a ConfigMap, by the bare
		// Service name of its own namespace.
		deployment("d-planner", "shop", "planner", "", `{"app":"planner"}`,
			`{"name":"agent","image":"langchain/langgraph-api:1","envFrom":[{"configMapRef":{"name":"planner-config"}}]}`, ""),
		// Mounts a ConfigMap that names the docs server as <service>.<namespace>.
		deployment("d-mounted", "shop", "mounted-agent", agentLabel, `{"app":"mounted-agent"}`,
			`{"name":"agent","image":"registry.example/shop/mounted:1","args":["--config","/etc/agent/config.yaml"]}`, `,"volumes":[{"name":"config","configMap":{"name":"mounted-config"}}]`),
		// Says "tickets" as a word, not as a host, and names a Service that
		// is not an MCP server.
		deployment("d-unrelated", "shop", "unrelated-agent", agentLabel, `{"app":"unrelated-agent"}`,
			`{"name":"agent","image":"registry.example/shop/unrelated:1","args":["--greeting","tickets are handled by web.shop.svc"]}`, ""),
		// An ordinary workload that names the docs server is not an agent.
		deployment("d-web", "shop", "web", "", `{"app":"web"}`, `{"name":"web","image":"nginx:1.27","env":[{"name":"UPSTREAM","value":"http://docs-mcp.tools.svc:8080"}]}`, ""),
	}, ",")
	configMap := func(data string) string {
		return fmt.Sprintf(`{"apiVersion":"v1","kind":"ConfigMapList","metadata":{},"items":[{"metadata":{"name":"x"},"data":%s}]}`, data)
	}
	return &kubernetesClusterStub{lists: map[string]string{
		"/api/v1/namespaces": kubernetesListBody("v1", "Namespace", `{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"ns-shop","name":"shop"}},{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"ns-tools","name":"tools"}}`),
		"/api/v1/serviceaccounts": kubernetesListBody("v1", "ServiceAccount",
			`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"uid":"sa-shop","name":"default","namespace":"shop"}},{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"uid":"sa-tools","name":"default","namespace":"tools"}}`),
		"/apis/rbac.authorization.k8s.io/v1/roles":               kubernetesListBody("rbac.authorization.k8s.io/v1", "Role", ""),
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":        kubernetesListBody("rbac.authorization.k8s.io/v1", "ClusterRole", ""),
		"/apis/rbac.authorization.k8s.io/v1/rolebindings":        kubernetesListBody("rbac.authorization.k8s.io/v1", "RoleBinding", ""),
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": kubernetesListBody("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", ""),
		"/apis/apps/v1/deployments":                              kubernetesListBody("apps/v1", "Deployment", deployments),
		"/apis/apps/v1/statefulsets":                             kubernetesListBody("apps/v1", "StatefulSet", ""),
		"/apis/apps/v1/daemonsets":                               kubernetesListBody("apps/v1", "DaemonSet", ""),
		"/apis/batch/v1/jobs":                                    kubernetesListBody("batch/v1", "Job", ""),
		"/apis/batch/v1/cronjobs":                                kubernetesListBody("batch/v1", "CronJob", ""),
		"/api/v1/services": kubernetesListBody("v1", "Service", strings.Join([]string{
			`{"metadata":{"name":"docs-mcp","namespace":"tools"},"spec":{"selector":{"app":"docs-mcp"}}}`,
			`{"metadata":{"name":"tickets","namespace":"shop"},"spec":{"selector":{"app":"tickets-mcp"}}}`,
			`{"metadata":{"name":"web","namespace":"shop"},"spec":{"selector":{"app":"web"}}}`,
			// No selector: it names nothing in the cluster.
			`{"metadata":{"name":"external","namespace":"shop"},"spec":{"type":"ExternalName"}}`,
		}, ",")),
		"/api/v1/configmaps":                       `{"apiVersion":"v1","kind":"ConfigMapList","metadata":{},"items":[]}`,
		"/api/v1/namespaces/shop/configmaps":       "",
		"/api/v1/namespaces/shop/configmaps#plan":  configMap(`{"TICKETS_MCP":"http://tickets:9000/sse","NOTE":"cfg-do-not-keep-0002"}`),
		"/api/v1/namespaces/shop/configmaps#mount": configMap(`{"config.yaml":"servers:\n  docs:\n    url: https://docs-mcp.tools/mcp\n"}`),
	}}
}

// The namespaced ConfigMap read names the ConfigMap in a field selector; the
// stub answers by it.
type kubernetesLinkTransport struct{ *kubernetesClusterStub }

func (transport kubernetesLinkTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path == "/api/v1/namespaces/shop/configmaps" {
		key := map[string]string{"metadata.name=planner-config": "#plan", "metadata.name=mounted-config": "#mount"}[request.URL.Query().Get("fieldSelector")]
		transport.mu.Lock()
		transport.requests = append(transport.requests, request.URL.Path+"?"+request.URL.RawQuery)
		body, status := transport.lists[request.URL.Path+key], http.StatusOK
		if refused, set := transport.statuses[request.URL.Path]; set {
			status, body = refused, `{"kind":"Status","status":"Failure"}`
		} else if key == "" {
			body = `{"apiVersion":"v1","kind":"ConfigMapList","metadata":{},"items":[]}`
		}
		transport.mu.Unlock()
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	}
	return transport.kubernetesClusterStub.RoundTrip(request)
}

type kubernetesLinkResult struct {
	complete      collection.CompleteResult
	names         map[string]string // entity id -> kind display name
	links         []string          // "from -> to"
	clusterStatus string
	pages         [][]byte
}

func collectKubernetesLinkCluster(t *testing.T, stub *kubernetesClusterStub) kubernetesLinkResult {
	t.Helper()
	api, err := newKubernetesCollectionAPI("https://prod.example", kubernetesLinkTransport{stub}, time.Second)
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
	for index := range ids {
		if ids[index], err = domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", index+1, index+1)); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderKubernetes, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialKubernetesCluster, CredentialReference: "ref:kubernetes/cluster/e2e-a",
		ExpectedSubject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "prod.example/cluster-a"}, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second}}
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte("local-e2e-credential-material"))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection rejected: %T %v", outcome, err)
	}
	if !complete.Snapshot().TypedObservations() {
		t.Fatal("snapshot is not typed")
	}
	result := kubernetesLinkResult{complete: complete, names: map[string]string{}}
	var relationships []struct{ Kind, From, To, Type string }
	for _, object := range driver.objects {
		var page struct {
			Entities []struct {
				ID          string `json:"id"`
				Kind        string `json:"kind"`
				DisplayName string `json:"display_name"`
				Attributes  struct {
					MCPLinks string `json:"mcp_links"`
				} `json:"attributes"`
			} `json:"entities"`
			Relationships []struct {
				Kind       string `json:"kind"`
				From       string `json:"from_entity_id"`
				To         string `json:"to_entity_id"`
				Attributes struct {
					Type string `json:"type"`
				} `json:"attributes"`
			} `json:"relationships"`
		}
		if json.Unmarshal(object.Body, &page) != nil || page.Entities == nil && page.Relationships == nil {
			continue
		}
		result.pages = append(result.pages, object.Body)
		for _, entity := range page.Entities {
			result.names[entity.ID] = entity.Kind + " " + entity.DisplayName
			if entity.Kind == "kubernetes_cluster" {
				result.clusterStatus = entity.Attributes.MCPLinks
			}
		}
		for _, relationship := range page.Relationships {
			relationships = append(relationships, struct{ Kind, From, To, Type string }{relationship.Kind, relationship.From, relationship.To, relationship.Attributes.Type})
		}
	}
	for _, relationship := range relationships {
		if relationship.Kind == "depends_on" {
			if relationship.Type != "agent_mcp_server" {
				t.Fatalf("link type = %q", relationship.Type)
			}
			result.links = append(result.links, result.names[relationship.From]+" -> "+result.names[relationship.To])
		}
	}
	sort.Strings(result.links)
	return result
}

// A whole collection relates each agent to the MCP servers its pod template
// is configured with, in a typed snapshot, and keeps none of the values it
// compared.
func TestKubernetesCollectionRelatesAgentsToTheMCPServersTheyAreConfiguredWith(t *testing.T) {
	stub := kubernetesLinkCluster()
	result := collectKubernetesLinkCluster(t, stub)
	want := []string{
		"kubernetes_agent shop/mounted-agent -> kubernetes_mcp_server tools/docs-mcp",
		"kubernetes_agent shop/support-agent -> kubernetes_mcp_server tools/docs-mcp",
		"kubernetes_inferred_agent shop/planner -> kubernetes_mcp_server shop/tickets-mcp",
	}
	if strings.Join(result.links, "\n") != strings.Join(want, "\n") {
		t.Fatalf("links =\n%s\nwant\n%s", strings.Join(result.links, "\n"), strings.Join(want, "\n"))
	}
	if result.clusterStatus != "collected" {
		t.Fatalf("cluster mcp_links = %q", result.clusterStatus)
	}
	// 2 namespaces, 2 service accounts, 7 workloads (4 agents), 2 MCP
	// servers and the cluster; the three links are in the snapshot.
	snapshot := result.complete.Snapshot()
	if snapshot.EntityCount() != 14 || snapshot.RelationshipCount() != 2+2+7*2+2+3 {
		t.Fatalf("snapshot entities=%d relationships=%d", snapshot.EntityCount(), snapshot.RelationshipCount())
	}
	// Nothing that was compared is in a stored page: no address, no
	// environment value, no ConfigMap value, no Service name of its own.
	for _, page := range result.pages {
		for _, value := range []string{"svc.cluster.local", "docs-mcp.tools", "tickets:9000", "tok-do-not-keep", "cfg-do-not-keep", "DOCS_MCP_URL", "config.yaml", "planner-config"} {
			if strings.Contains(string(page), value) {
				t.Fatalf("a stored page holds %q", value)
			}
		}
	}
	// Secrets are never asked for, and a ConfigMap is asked for by name.
	for _, request := range stub.requests {
		if strings.Contains(request, "secrets") {
			t.Fatalf("request %s", request)
		}
	}
}

// Without the permission to list Services the collection still completes; it
// relates nothing and says so on the cluster. Without the permission to list
// ConfigMaps it relates what arguments and environment values name.
func TestKubernetesMCPLinksDegradeWithoutThePermissions(t *testing.T) {
	for name, test := range map[string]struct {
		refused       string
		status        int
		clusterStatus string
		links         []string
	}{
		"services forbidden":    {"/api/v1/services", http.StatusForbidden, "services_denied", nil},
		"services unauthorized": {"/api/v1/services", http.StatusUnauthorized, "services_denied", nil},
		"configmaps forbidden": {"/api/v1/configmaps", http.StatusForbidden, "configmaps_denied", []string{
			"kubernetes_agent shop/mounted-agent -> kubernetes_mcp_server tools/docs-mcp",
			"kubernetes_agent shop/support-agent -> kubernetes_mcp_server tools/docs-mcp",
			"kubernetes_inferred_agent shop/planner -> kubernetes_mcp_server shop/tickets-mcp",
		}},
		"namespaced configmaps forbidden": {"/api/v1/namespaces/shop/configmaps", http.StatusForbidden, "collected", []string{"kubernetes_agent shop/support-agent -> kubernetes_mcp_server tools/docs-mcp"}},
	} {
		stub := kubernetesLinkCluster()
		stub.statuses = map[string]int{test.refused: test.status}
		result := collectKubernetesLinkCluster(t, stub)
		if result.clusterStatus != test.clusterStatus || strings.Join(result.links, "\n") != strings.Join(test.links, "\n") {
			t.Errorf("%s: cluster %q, links %v", name, result.clusterStatus, result.links)
		}
	}
}

// A server error of the link phase fails the page, as in every other phase:
// the relations are not silently dropped.
func TestKubernetesMCPLinkPhaseClassifiesTransientFailures(t *testing.T) {
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "prod.example/cluster-a"}
	cursor := nextKubernetesPageCursor(subject, kubernetesPhaseMCPLinks, 12, "start")
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: cursor, Page: 12, RemainingItems: 100, RemainingRelationships: 100, RemainingBytes: 1 << 20}
	for path, status := range map[string]int{"/api/v1/services": http.StatusServiceUnavailable, "/apis/apps/v1/deployments": http.StatusTooManyRequests, "/api/v1/namespaces/shop/configmaps": http.StatusInternalServerError} {
		stub := kubernetesLinkCluster()
		stub.statuses = map[string]int{path: status}
		api, err := newKubernetesCollectionAPI("https://prod.example", kubernetesLinkTransport{stub}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if page, err := api.FetchCollectionPage(context.Background(), []byte("local-e2e-credential-material"), request); err == nil {
			t.Errorf("%s answering %d: the page completed with %d relationships", path, status, len(page.Relationships))
		}
	}
	// With every read answered the same request is the last page.
	api, err := newKubernetesCollectionAPI("https://prod.example", kubernetesLinkTransport{kubernetesLinkCluster()}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if page, err := api.FetchCollectionPage(context.Background(), []byte("local-e2e-credential-material"), request); err != nil || !page.Complete || len(page.Entities) != 0 || len(page.Relationships) != 3 {
		t.Fatalf("link page = %v, complete %t, %d relationships", err, page.Complete, len(page.Relationships))
	}
}

func TestKubernetesServiceNameMatching(t *testing.T) {
	qualified := map[string][]int{"docs.tools": {0}, "tickets.shop": {1}}
	local := map[string][]int{"tools/docs": {0}, "shop/tickets": {1}}
	for text, want := range map[string][]int{
		"http://docs.tools.svc.cluster.local:8080/mcp": {0},
		"DOCS.TOOLS.SVC":                  {0},
		"docs.tools.svc.internal.example": {0},
		"grpc://tickets.shop:9000":        {1},
		"http://tickets/sse":              {1},
		"tickets:9000":                    {1},
		"tickets":                         {1},
		"user@tickets":                    {1},
		"a,http://docs.tools.svc,b http://tickets:1": {0, 1},
		// Words, not hosts.
		"tickets are great":         nil,
		"see docs.tools for more":   nil,
		"my-tickets:9000":           nil,
		"tickets.shop.example.com":  nil,
		"http://docs/":              nil, // another namespace's bare name
		"nottickets.shop.svc":       nil,
		"http://tickets.shopx:9000": nil,
		"":                          nil,
	} {
		matched := map[int]bool{}
		kubernetesMatchServiceNames(text, "shop", qualified, local, matched)
		var got []int
		for server := range matched {
			got = append(got, server)
		}
		sort.Ints(got)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%q matched %v, want %v", text, got, want)
		}
	}
}
