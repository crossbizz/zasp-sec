package kubernetesdiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func egressConfigMapList(t *testing.T, documents ...agentsignals.EgressObservations) string {
	t.Helper()
	items := []map[string]any{}
	for _, document := range documents {
		document.Normalize()
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, map[string]any{"metadata": map[string]any{"name": "zasp-egress-x", "namespace": "zasp-edge"}, "data": map[string]string{agentsignals.EgressObservationsKey: string(body)}})
	}
	// A ConfigMap that carries the label but is not the sensor's document.
	items = append(items, map[string]any{"metadata": map[string]any{"name": "forged"}, "data": map[string]string{agentsignals.EgressObservationsKey: `{"version":"egress-observations-v1","node":"n","generated_at":"2026-11-14T10:00:00Z","workloads":[{"namespace":"shop","kind":"Deployment","name":"plain","destinations":[{"token":"made_up","last_seen":"2026-11-14T10:00:00Z"}]}]}`}})
	list, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMapList", "metadata": map[string]any{"continue": ""}, "items": items})
	if err != nil {
		t.Fatal(err)
	}
	return string(list)
}

// A workload whose pod template says nothing about AI becomes an inferred
// agent when the node sensor saw it call a model API; a full collection with
// that signal ends as a typed snapshot.
func TestRuntimeEgressObservationMakesAnInferredAgentInAFullCollection(t *testing.T) {
	now := time.Now().UTC()
	seen, stale := agentsignals.FormatEgressTime(now.Add(-time.Hour)), agentsignals.FormatEgressTime(now.Add(-agentsignals.EgressObservationRetention-time.Hour))
	observations := egressConfigMapList(t,
		agentsignals.EgressObservations{Version: agentsignals.EgressObservationsVersion, Node: "node-a", GeneratedAt: seen, Workloads: []agentsignals.EgressWorkload{
			{Namespace: "shop", Kind: "Deployment", Name: "support-bot", Destinations: []agentsignals.EgressDestination{{Token: "anthropic", LastSeen: seen}}},
			{Namespace: "shop", Kind: "Deployment", Name: "old-caller", Destinations: []agentsignals.EgressDestination{{Token: "openai", LastSeen: stale}}},
			{Namespace: "shop", Kind: "Deployment", Name: "opted-out", Destinations: []agentsignals.EgressDestination{{Token: "openai", LastSeen: seen}}},
			{Namespace: "shop", Kind: "StatefulSet", Name: "support-bot", Destinations: []agentsignals.EgressDestination{{Token: "openai", LastSeen: seen}}},
		}},
		agentsignals.EgressObservations{Version: agentsignals.EgressObservationsVersion, Node: "node-b", GeneratedAt: seen, Workloads: []agentsignals.EgressWorkload{
			{Namespace: "shop", Kind: "Deployment", Name: "support-bot", Destinations: []agentsignals.EgressDestination{{Token: "mcp_remote", LastSeen: seen}}},
		}},
	)
	transport := &kubernetesRoundTripper{egress: &kubernetesHTTPResponse{status: http.StatusOK, body: observations}}
	deployment := func(uid, name, labels string) string {
		return fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":%q,"name":%q,"namespace":"shop"%s},"spec":{"template":{"spec":{"serviceAccountName":"default","containers":[{"name":"app","image":"registry.example/shop/app:v1"}]}}}}`, uid, name, labels)
	}
	for _, phase := range [][2]string{{"v1", "Namespace"}, {"v1", "ServiceAccount"}, {"rbac.authorization.k8s.io/v1", "Role"}, {"rbac.authorization.k8s.io/v1", "ClusterRole"}, {"rbac.authorization.k8s.io/v1", "RoleBinding"}, {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"}, {"apps/v1", "Deployment"}, {"apps/v1", "StatefulSet"}, {"apps/v1", "DaemonSet"}, {"batch/v1", "Job"}, {"batch/v1", "CronJob"}} {
		items := `[]`
		switch phase[1] {
		case "Namespace":
			items = `[{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"ns-shop","name":"shop"}}]`
		case "ServiceAccount":
			items = `[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"uid":"sa-default","name":"default","namespace":"shop"}}]`
		case "Deployment":
			items = "[" + strings.Join([]string{
				deployment("d-support-bot", "support-bot", ""), deployment("d-plain", "plain", ""), deployment("d-old-caller", "old-caller", ""),
				deployment("d-opted-out", "opted-out", `,"labels":{"zasp.ai/entity-kind":"workload"}`),
			}, ",") + "]"
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
		if ids[i], err = domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", i+1, i+1)); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("local-e2e-credential-material")
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderKubernetes, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialKubernetesCluster, CredentialReference: "ref:kubernetes/cluster/e2e-a", ExpectedSubject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "prod.example/cluster-a"}, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second}}
	outcome, err := client.CollectWithCredential(context.Background(), request, credential)
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection with runtime observations rejected: %T %v", outcome, err)
	}
	if !complete.Snapshot().TypedObservations() {
		t.Fatal("snapshot is not typed")
	}
	// Only the Deployment page has workloads, so only it looked.
	if len(transport.egressRequests) != 1 || transport.egressRequests[0].URL.Query().Get("labelSelector") != "zasp.ai/egress-observations=v1" || transport.egressRequests[0].Header.Get("Authorization") != "Bearer "+string(credential) {
		t.Fatalf("observation requests = %d", len(transport.egressRequests))
	}
	kinds := map[string]string{}
	signals := map[string][]string{}
	for _, object := range driver.objects {
		var page struct {
			Entities []struct {
				Kind        string `json:"kind"`
				DisplayName string `json:"display_name"`
				Attributes  struct {
					Discovery agentsignals.Discovery `json:"discovery"`
				} `json:"attributes"`
			} `json:"entities"`
		}
		if json.Unmarshal(object.Body, &page) != nil {
			continue
		}
		for _, entity := range page.Entities {
			if strings.HasPrefix(entity.DisplayName, "shop/") {
				kinds[entity.DisplayName] = entity.Kind
				signals[entity.DisplayName] = entity.Attributes.Discovery.Signals
			}
		}
	}
	want := map[string]string{"shop/support-bot": "kubernetes_inferred_agent", "shop/plain": "kubernetes_workload", "shop/old-caller": "kubernetes_workload", "shop/opted-out": "kubernetes_workload"}
	for name, kind := range want {
		if kinds[name] != kind {
			t.Errorf("%s is %q, want %q", name, kinds[name], kind)
		}
	}
	if got := signals["shop/support-bot"]; len(got) != 2 || got[0] != "egress:anthropic" || got[1] != "egress:mcp_remote" {
		t.Errorf("support-bot signals = %v (the StatefulSet of the same name must not leak in)", got)
	}
}

// Whatever the observation lookup returns, the workloads still collect.
func TestRuntimeEgressLookupNeverFailsAWorkloadPage(t *testing.T) {
	for name, response := range map[string]*kubernetesHTTPResponse{
		"forbidden":    nil,
		"not json":     {status: http.StatusOK, body: `<html>`},
		"wrong kind":   {status: http.StatusOK, body: `{"apiVersion":"v1","kind":"SecretList","metadata":{},"items":[]}`},
		"server error": {status: http.StatusInternalServerError, body: `{}`},
	} {
		transport := &kubernetesRoundTripper{egress: response, responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"22222222-2222-4222-8222-222222222222","namespace":"default","name":"api"}}]}`}}}
		api, err := newKubernetesCollectionAPI("https://cluster.example", transport, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
		page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "deployments", 7, "start"), Page: 7, RemainingItems: 3, RemainingRelationships: 64, RemainingBytes: 1 << 20})
		if err != nil || len(page.Entities) != 1 || len(transport.egressRequests) != 1 {
			t.Errorf("%s: page = %d entities, %d lookups, err %v", name, len(page.Entities), len(transport.egressRequests), err)
		}
	}
}
