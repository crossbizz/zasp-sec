package kubernetesdiscovery

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// Actual pinned HTTPS application path with controlled provider IO. This does
// not establish customer permissions, PostgreSQL custody or coverage readiness.
func placementID(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }
func placementMeta(name, namespace string, n int) map[string]any {
	m := map[string]any{"name": name, "uid": placementID(n), "resourceVersion": "1"}
	if namespace != "" {
		m["namespace"] = namespace
	}
	return m
}
func placementOwnerFixture(kind, name string, n int) []any {
	return []any{map[string]any{"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": placementID(n), "controller": true}}
}
func placementDeployment(n int) map[string]any {
	m := placementMeta(fmt.Sprintf("agent-%d", n), "default", n)
	m["labels"] = map[string]string{"zasp.ai/entity-kind": "agent"}
	return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": m, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "default", "containers": []any{map[string]string{"name": "agent", "image": "example/agent:v1"}}}}}}
}
func newPlacementPinnedFixture(t *testing.T, mode string) (*KubernetesCollectionAPI, *map[string]int) {
	t.Helper()
	calls := map[string]int{}
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls[r.URL.Path]++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer placement-provider-secret" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var result any
		switch r.URL.Path {
		case "/apis/apps/v1/deployments":
			result = map[string]any{"apiVersion": "apps/v1", "kind": "DeploymentList", "metadata": map[string]string{"continue": "", "resourceVersion": "1"}, "items": []any{placementDeployment(1), placementDeployment(2)}}
		case "/api/v1/namespaces/kube-system":
			result = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": placementMeta("kube-system", "", 99)}
		case "/apis/apps/v1/namespaces/default/replicasets":
			items := []any{}
			for n := 1; n <= 2; n++ {
				m := placementMeta(fmt.Sprintf("rs-%d", n), "default", 10+n)
				m["ownerReferences"] = placementOwnerFixture("Deployment", fmt.Sprintf("agent-%d", n), n)
				if mode == "foreign_owner" && n == 1 {
					m["ownerReferences"] = placementOwnerFixture("Deployment", "foreign-name", 1)
				}
				items = append(items, map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": m})
			}
			result = map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSetList", "metadata": map[string]string{"continue": "", "resourceVersion": "1"}, "items": items}
		case "/api/v1/namespaces/default/pods":
			if mode == "forbidden" {
				http.Error(w, "refused", 403)
				return
			}
			n := 1
			next := "page-two"
			if r.URL.Query().Get("continue") == "page-two" {
				n = 2
				next = ""
			}
			m := placementMeta(fmt.Sprintf("pod-%d", n), "default", 20+n)
			m["ownerReferences"] = placementOwnerFixture("ReplicaSet", fmt.Sprintf("rs-%d", n), 10+n)
			if mode == "zero_pods" {
				next = ""
			}
			result = map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]string{"continue": next, "resourceVersion": "1"}, "items": []any{map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": m, "spec": map[string]string{"nodeName": fmt.Sprintf("node-%d", n)}, "status": map[string]string{"phase": "Running"}}}}
			if mode == "zero_pods" {
				result.(map[string]any)["items"] = []any{}
			}
		case "/api/v1/nodes/node-1", "/api/v1/nodes/node-2":
			n := 1
			if strings.HasSuffix(r.URL.Path, "2") {
				n = 2
			}
			boot := placementID(40 + n)
			if mode == "reboot" && calls[r.URL.Path] > 1 {
				boot = placementID(500 + n)
			}
			result = map[string]any{"apiVersion": "v1", "kind": "Node", "metadata": placementMeta(fmt.Sprintf("node-%d", n), "", 30+n), "status": map[string]any{"nodeInfo": map[string]string{"bootID": boot}}}
		case "/apis/apps/v1/namespaces/default/deployments/agent-1":
			result = placementDeployment(1)
		case "/apis/apps/v1/namespaces/default/deployments/agent-2":
			result = placementDeployment(2)
		default:
			http.Error(w, "unexpected fixed resource", 404)
			return
		}
		if err := json.NewEncoder(w).Encode(result); err != nil {
			t.Error("fixture encode", err)
		}
	}))
	t.Cleanup(server.Close)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	api, err := NewPinnedKubernetesCollectionAPIWithNetwork(PinnedCollectionAPIConfig{Endpoint: "https://example.com", CABundlePEM: bundle, AllowedCIDRs: []string{"203.0.113.0/24"}, Timeout: time.Second, NodePlacement: true}, CollectionNetwork{Resolver: &pinnedCollectionResolverStub{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}}}, Dialer: pinnedCollectionDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "203.0.113.8:443" {
			return nil, errors.New("unexpected pinned destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})})
	if err != nil {
		t.Fatal(err)
	}
	return api, &calls
}
func placementPageRequest() CollectionPageRequest {
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "example.com/prod"}
	c := nextKubernetesPageCursor(subject, "deployments", 7, "start")
	c.Value = strings.Replace(c.Value, "kubernetes:", "kubernetes-placement-v2:", 1)
	return CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: c, Page: 7, RemainingItems: 10, RemainingRelationships: 64, RemainingBytes: 2 << 20}
}
func TestNodePlacementPinnedCollectorWholeOwnerDomain(t *testing.T) {
	api, calls := newPlacementPinnedFixture(t, "")
	before := time.Now().UTC()
	page, err := api.FetchCollectionPage(context.Background(), []byte("placement-provider-secret"), placementPageRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entities) != 2 || !strings.HasPrefix(page.Cursor.Value, "kubernetes-placement-v2:") {
		t.Fatal("V2 recipe or both Agents lost")
	}
	for _, raw := range page.Entities {
		// Decode exact wire keys independently of Go field matching.
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			t.Fatal("entity")
		}
		var attrs map[string]json.RawMessage
		if json.Unmarshal(obj["attributes"], &attrs) != nil {
			t.Fatal("attributes")
		}
		var placement map[string]json.RawMessage
		if json.Unmarshal(attrs["placement"], &placement) != nil {
			t.Fatal("missing authentic placement")
		}
		var schema, cluster, controller string
		var observed time.Time
		var tuples []map[string]string
		_ = json.Unmarshal(placement["schema"], &schema)
		_ = json.Unmarshal(placement["cluster_uid"], &cluster)
		_ = json.Unmarshal(placement["controller_uid"], &controller)
		_ = json.Unmarshal(placement["observed_at"], &observed)
		_ = json.Unmarshal(placement["placements"], &tuples)
		var native string
		_ = json.Unmarshal(obj["source_native_id"], &native)
		n := 1
		if strings.HasSuffix(native, placementID(2)) {
			n = 2
		}
		if schema != "kubernetes-agent-placement-v1" || cluster != placementID(99) || controller != placementID(n) || len(tuples) != 1 || tuples[0]["replicaset_uid"] != placementID(10+n) || tuples[0]["pod_uid"] != placementID(20+n) || tuples[0]["node_uid"] != placementID(30+n) || tuples[0]["boot_id"] != placementID(40+n) || observed.Before(before) || observed.After(time.Now().UTC()) {
			t.Fatal("actual owner/node incarnation or original observation lost")
		}
	}
	if (*calls)["/apis/apps/v1/namespaces/default/replicasets"] != 2 || (*calls)["/api/v1/namespaces/default/pods"] != 4 || (*calls)["/api/v1/namespaces/kube-system"] != 2 {
		t.Fatal("owner domain not complete/double checked or fetched once per Agent instead of shared namespace")
	}
}
func TestNodePlacementPinnedCollectorRefusesUnprovenPlacement(t *testing.T) {
	for _, mode := range []string{"forbidden", "foreign_owner", "reboot"} {
		t.Run(mode, func(t *testing.T) {
			api, _ := newPlacementPinnedFixture(t, mode)
			if _, err := api.FetchCollectionPage(context.Background(), []byte("placement-provider-secret"), placementPageRequest()); err == nil {
				t.Fatal("unproven or changed placement returned as current")
			}
		})
	}
}
func TestNodePlacementRecipeSeparatesLegacyCursor(t *testing.T) {
	api, _ := newPlacementPinnedFixture(t, "")
	req := placementPageRequest()
	req.Cursor.Value = strings.Replace(req.Cursor.Value, "kubernetes-placement-v2:", "kubernetes:", 1)
	if _, err := api.FetchCollectionPage(context.Background(), []byte("placement-provider-secret"), req); err == nil {
		t.Fatal("V2 reinterpreted old continuation")
	}
	api.nodePlacement = false
	req = placementPageRequest()
	if _, err := api.FetchCollectionPage(context.Background(), []byte("placement-provider-secret"), req); err == nil {
		t.Fatal("legacy accepted V2 continuation")
	}
}

// Late successor control: complete scaled-to-zero inventory is retained without
// inventing an empty-set coverage result or blocking unrelated Agent metadata.
func TestNodePlacementZeroPodsPreservesAgentInventory(t *testing.T) {
	api, _ := newPlacementPinnedFixture(t, "zero_pods")
	page, err := api.FetchCollectionPage(context.Background(), []byte("placement-provider-secret"), placementPageRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entities) != 2 {
		t.Fatal("scaled-to-zero erased ordinary Agents")
	}
	for _, raw := range page.Entities {
		var entity struct {
			Attributes map[string]json.RawMessage `json:"attributes"`
		}
		if json.Unmarshal(raw, &entity) != nil {
			t.Fatal("entity")
		}
		if _, ok := entity.Attributes["placement"]; ok {
			t.Fatal("zero Pods fabricated placement coverage")
		}
	}
}

func TestNodePlacementCollectorVersionRequiresExactRecipe(t *testing.T) {
	for _, mode := range []string{"selected", "default_legacy", "missing_selection", "wrong_version"} {
		t.Run(mode, func(t *testing.T) {
			api, _ := newPlacementPinnedFixture(t, "")
			version := NodePlacementCollectorVersion
			if mode == "default_legacy" || mode == "missing_selection" {
				api.nodePlacement = false
			}
			if mode == "default_legacy" || mode == "wrong_version" {
				version = "collector_v1"
			}
			driver := &automaticSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
			artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
			if err != nil {
				t.Fatal(err)
			}
			_, err = NewCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: version, ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
			valid := mode == "selected" || mode == "default_legacy"
			if (err == nil) != valid {
				t.Fatal("collector recipe/version mismatch was not refused", mode, err)
			}
		})
	}
}
