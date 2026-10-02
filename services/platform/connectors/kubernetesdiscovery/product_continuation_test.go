package kubernetesdiscovery

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This isolates canonical cursor/manifest resume from SQL latency. It is not
// the real Temporal/PostgreSQL continuation acceptance test.
func TestProductKubernetesColdResumeAcrossHistoryBoundary(t *testing.T) {
	transport := &kubernetesRoundTripper{}
	for page := 1; page <= 257; page++ {
		next := ""
		if page < 257 {
			next = fmt.Sprintf("page-%d", page+1)
		}
		transport.responses = append(transport.responses, kubernetesHTTPResponse{status: 200, body: fmt.Sprintf(`{"apiVersion":"v1","kind":"NamespaceList","metadata":{"continue":%q},"items":[{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"ns-%03d","name":"ns-%03d"}}]}`, next, page, page)})
	}
	for _, phase := range [][2]string{{"v1", "ServiceAccount"}, {"rbac.authorization.k8s.io/v1", "Role"}, {"rbac.authorization.k8s.io/v1", "ClusterRole"}, {"rbac.authorization.k8s.io/v1", "RoleBinding"}, {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"}, {"apps/v1", "Deployment"}, {"apps/v1", "StatefulSet"}, {"apps/v1", "DaemonSet"}, {"batch/v1", "Job"}, {"batch/v1", "CronJob"}} {
		transport.responses = append(transport.responses, kubernetesHTTPResponse{status: 200, body: fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"continue":""},"items":[]}`, phase[0], phase[1]+"List")})
	}
	api, err := newKubernetesCollectionAPI("https://example.com", transport, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driver := &automaticSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
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
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], EffectID: fmt.Sprintf("%064x", 1), Provider: collection.ProviderKubernetes, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialKubernetesCluster, CredentialReference: "ref:kubernetes/connection/customer-0001", ExpectedSubject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "example.com/customer"}, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 10000, FreshPageLimit: 1, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Minute}}
	current := base
	for page := 1; page <= 267; page++ {
		ctx, cancel, err := collection.WithProductEffect(context.Background(), request.EffectID, time.Now().Add(time.Minute), func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := current.CollectWithCredential(ctx, request, []byte("owned-kubernetes-credential-0001"))
		cancel()
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if page == 267 {
			complete, ok := outcome.(collection.CompleteResult)
			if !ok || complete.Snapshot().EntityCount() != 258 || len(transport.requests) != 267 {
				t.Fatalf("final %T", outcome)
			}
			break
		}
		partial, ok := outcome.(collection.PartialResult)
		if !ok {
			t.Fatalf("page %d: %T", page, outcome)
		}
		d := partial.Manifest().Descriptor()
		checksum := d.Checksum()
		seed := collection.ResumeSeed{EffectID: request.EffectID, CheckpointVersion: int64(page), CheckpointDigest: bytes.Repeat([]byte{7}, 32), Cursor: partial.NextCursor(), ManifestReference: d.ObjectReference(), ManifestKey: d.Key(), ManifestVersionID: d.VersionID(), ManifestChecksum: checksum[:], ManifestSizeBytes: d.Size(), ManifestMediaType: d.MediaType(), ManifestSchema: d.SchemaVersion(), ParserVersion: d.ParserVersion(), ToolVersion: d.ToolVersion()}
		current, err = base.(collection.ResumableProviderClient).WithResumeSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		request.Cursor, request.EffectID = partial.NextCursor(), fmt.Sprintf("%064x", page+1)
	}
}
