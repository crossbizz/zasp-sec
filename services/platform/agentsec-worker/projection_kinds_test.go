package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

// The graph store refuses any kind that names a provider. The collectors name
// their kinds after the provider, so the projector must hand the store the
// neutral kind.
func TestGraphProjectionKindMapsProviderKindsToNeutralKinds(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"aws_account": "account", "aws_role": "role", "aws_policy": "policy", "aws_service": "service", "aws_resource": "resource", "aws_instance": "instance",
		"github_installation": "installation", "github_app": "app", "github_organization": "organization", "github_permission": "permission",
		"github_repository": "repository", "github_workflow": "workflow", "github_environment": "environment",
		// Kubernetes and Okta kinds carry no refused token.
		"kubernetes_service_account": "kubernetes_service_account", "kubernetes_cluster_role_binding": "kubernetes_cluster_role_binding", "okta_user": "okta_user", "okta_service_principal": "okta_service_principal",
		"contains": "contains", "belongs_to": "belongs_to", "trusts": "trusts", "uses_policy": "uses_policy",
	} {
		if got, ok := graphProjectionKind(input); !ok || got != want {
			t.Errorf("graphProjectionKind(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	// A kind that would still name a provider after the prefix is dropped is
	// refused here, before the store sees it.
	for _, input := range []string{"", "aws_", "github_", "aws_aws_role", "aws_github_app", "role_aws", "cartography_node", "neo4j_label", "aws__role"} {
		if got, ok := graphProjectionKind(input); ok {
			t.Errorf("graphProjectionKind(%q) = %q, accepted", input, got)
		}
	}
}

func TestGraphProjectionProjectorHandsTheStoreNeutralKinds(t *testing.T) {
	t.Parallel()
	candidate := projectionCandidateFromPages(t, "graph")
	candidate.Entities = cloneRawMessages(candidate.Entities)
	candidate.Entities[0] = json.RawMessage(`{"id":"` + projectionID(10) + `","kind":"aws_role","source_native_id":"arn:aws:iam::123456789012:role/a","display_name":"a","stable_fields":{"account_id":"123456789012","arn":"arn:aws:iam::123456789012:role/a","name":"a"},"attributes":{}}`)
	candidate.Entities[1] = json.RawMessage(`{"id":"` + projectionID(11) + `","kind":"aws_policy","source_native_id":"arn:aws:iam::123456789012:policy/p","display_name":"p","stable_fields":{"account_id":"123456789012","arn":"arn:aws:iam::123456789012:policy/p","name":"p","policy_type":"managed"},"attributes":{}}`)
	candidate.Relationships = cloneRawMessages(candidate.Relationships)
	candidate.Relationships[0] = json.RawMessage(`{"id":"` + projectionID(12) + `","kind":"uses_policy","source_native_id":"rel-a","from_entity_id":"` + projectionID(10) + `","to_entity_id":"` + projectionID(11) + `","attributes":{}}`)
	store := &graphSnapshotStoreStub{result: graphstore.SnapshotApplyResult{
		SnapshotID: mustProjectionID(t, 4), Source: "aws", Generation: candidate.Generation, InputDigest: candidate.InputDigest, ContentDigest: sha256.Sum256([]byte("graph-content")),
	}}
	projector, err := newGraphProjectionProjector(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Apply(context.Background(), candidate); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(store.inputs) != 1 || store.inputs[0].Source != "aws" {
		t.Fatalf("graph inputs = %#v", store.inputs)
	}
	nodes, edges := store.inputs[0].Projection.Nodes, store.inputs[0].Projection.Edges
	if len(nodes) != 2 || nodes[0].Kind != "role" || nodes[1].Kind != "policy" || len(edges) != 1 || edges[0].Kind != "uses_policy" {
		t.Fatalf("graph projection = %#v", store.inputs[0].Projection)
	}

	hostile := candidate
	hostile.Entities = cloneRawMessages(candidate.Entities)
	hostile.Entities[0] = json.RawMessage(`{"id":"` + projectionID(10) + `","kind":"aws_neo4j_label","source_native_id":"x","display_name":"x","stable_fields":{},"attributes":{}}`)
	if _, err := projector.Apply(context.Background(), hostile); !errors.Is(err, errWorkerExecution) || len(store.inputs) != 1 {
		t.Fatalf("provider-named kind Apply() error=%v calls=%d", err, len(store.inputs))
	}
}
