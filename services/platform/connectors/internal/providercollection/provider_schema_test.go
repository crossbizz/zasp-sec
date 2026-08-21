package providercollection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

func TestProviderSchemaAcceptsRequiredLaunchInventoryKinds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		provider collection.Provider
		subject  collection.SubjectBinding
		kind     string
		stable   string
		attrs    string
	}{
		{"aws policy", collection.ProviderAWS, collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, "aws_policy", `{"account_id":"123456789012","arn":"arn:aws:iam::123456789012:policy/read","name":"read","policy_type":"managed"}`, `{}`},
		{"kubernetes service account", collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, "kubernetes_service_account", `{"api_group":"core","api_version":"v1","cluster":"api.example.com/production","name":"agent","namespace":"default","resource_kind":"ServiceAccount"}`, `{"namespaced":true}`},
		{"kubernetes user", collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, "kubernetes_user", `{"cluster":"api.example.com/production","name":"alice@example.com","scope":"cluster","subject_type":"User"}`, `{}`},
		{"kubernetes group", collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, "kubernetes_group", `{"cluster":"api.example.com/production","name":"developers","scope":"cluster","subject_type":"Group"}`, `{}`},
		{"kubernetes role", collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, "kubernetes_role", `{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/production","name":"reader","namespace":"default","resource_kind":"Role","scope":"namespace"}`, `{"namespaced":true,"rules":[]}`},
		{"kubernetes cluster role", collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, "kubernetes_cluster_role", `{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/production","name":"view","resource_kind":"ClusterRole","scope":"cluster"}`, `{"namespaced":false,"rules":[]}`},
		{"kubernetes role binding", collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, "kubernetes_role_binding", `{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/production","name":"readers","namespace":"default","resource_kind":"RoleBinding","role":"Role/reader","scope":"namespace"}`, `{"namespaced":true}`},
		{"kubernetes cluster role binding", collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, "kubernetes_cluster_role_binding", `{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/production","name":"viewers","resource_kind":"ClusterRoleBinding","role":"ClusterRole/view","scope":"cluster"}`, `{"namespaced":false}`},
		{"github app", collection.ProviderGitHub, collection.SubjectBinding{Kind: "github_installation", ID: "42"}, "github_app", `{"installation_id":42,"name":"zasp","owner":"acme"}`, `{}`},
		{"github workflow", collection.ProviderGitHub, collection.SubjectBinding{Kind: "github_installation", ID: "42"}, "github_workflow", `{"installation_id":42,"name":"build","owner":"acme","repository":"service","workflow":".github/workflows/build.yml"}`, `{}`},
		{"github environment", collection.ProviderGitHub, collection.SubjectBinding{Kind: "github_installation", ID: "42"}, "github_environment", `{"installation_id":42,"name":"production","owner":"acme","repository":"service"}`, `{}`},
		{"github permission", collection.ProviderGitHub, collection.SubjectBinding{Kind: "github_installation", ID: "42"}, "github_permission", `{"installation_id":42,"name":"contents:read","owner":"acme","permission":"read","repository":"service","scope":"contents"}`, `{}`},
		{"okta service principal", collection.ProviderOkta, collection.SubjectBinding{Kind: "okta_tenant", ID: "tenant.example.com"}, "okta_service_principal", `{"name":"automation","object_type":"service_principal","tenant":"tenant.example.com"}`, `{"status":"ACTIVE"}`},
		{"okta role", collection.ProviderOkta, collection.SubjectBinding{Kind: "okta_tenant", ID: "tenant.example.com"}, "okta_role", `{"name":"Application Administrator","object_type":"role","role":"APP_ADMIN","scope":"tenant","tenant":"tenant.example.com"}`, `{}`},
	}
	for index, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			entity := json.RawMessage(fmt.Sprintf(`{"id":"pid_41000000-0000-4000-8000-%012x","kind":%q,"source_native_id":"native-%d","display_name":"Inventory item %d","stable_fields":%s,"attributes":%s}`, index+1, test.kind, index+1, index+1, test.stable, test.attrs))
			cursor := collection.Cursor{Provider: test.provider, Version: "cursor_v1", Value: "complete"}
			if _, err := NewPage(test.provider, test.subject, cursor, true, []json.RawMessage{entity}, nil); err != nil {
				t.Fatalf("required %s entity rejected: %v", test.kind, err)
			}
		})
	}
}

func TestProviderSchemaRejectsMissingAndCrossKindFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		provider collection.Provider
		kind     string
		stable   string
		attrs    string
	}{
		{"aws policy missing arn", collection.ProviderAWS, "aws_policy", `{"account_id":"123456789012","name":"read","policy_type":"managed"}`, `{}`},
		{"kubernetes service account missing namespace", collection.ProviderKubernetes, "kubernetes_service_account", `{"api_group":"core","api_version":"v1","cluster":"api.example.com/production","name":"agent","resource_kind":"ServiceAccount"}`, `{"namespaced":true}`},
		{"github app with workflow field", collection.ProviderGitHub, "github_app", `{"installation_id":42,"name":"zasp","owner":"acme","workflow":"build.yml"}`, `{}`},
		{"okta role missing scope", collection.ProviderOkta, "okta_role", `{"name":"Application Administrator","object_type":"role","role":"APP_ADMIN","tenant":"tenant.example.com"}`, `{}`},
		{"kubernetes role wrong namespaced type", collection.ProviderKubernetes, "kubernetes_role", `{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/production","name":"reader","namespace":"default","resource_kind":"Role","scope":"namespace"}`, `{"namespaced":"true","rules":[]}`},
	}
	for index, test := range tests {
		entity := json.RawMessage(fmt.Sprintf(`{"id":"pid_44000000-0000-4000-8000-%012x","kind":%q,"source_native_id":"native-%d","display_name":"Inventory item %d","stable_fields":%s,"attributes":%s}`, index+1, test.kind, index+1, index+1, test.stable, test.attrs))
		cursor := collection.Cursor{Provider: test.provider, Version: "cursor_v1", Value: "complete"}
		if _, err := NewPage(test.provider, collection.SubjectBinding{Kind: "provider", ID: "subject"}, cursor, true, []json.RawMessage{entity}, nil); !errors.Is(err, collection.ErrContract) {
			t.Fatalf("%s error = %v", test.name, err)
		}
	}
}

func TestProviderSchemaAcceptsRequiredLaunchRelationshipKinds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		provider     collection.Provider
		entities     []json.RawMessage
		relationship json.RawMessage
	}{
		{"belongs_to", collection.ProviderAWS, []json.RawMessage{
			json.RawMessage(`{"id":"pid_42000001-0000-4000-8000-000000000001","kind":"aws_resource","source_native_id":"arn:aws:s3:::evidence","display_name":"evidence","stable_fields":{"account_id":"123456789012","arn":"arn:aws:s3:::evidence","name":"evidence","region":"us-west-2","resource_type":"bucket"},"attributes":{}}`),
			json.RawMessage(`{"id":"pid_42000002-0000-4000-8000-000000000002","kind":"aws_service","source_native_id":"aws:s3","display_name":"S3","stable_fields":{"account_id":"123456789012","name":"S3","service":"s3"},"attributes":{}}`),
		}, json.RawMessage(`{"id":"pid_42000010-0000-4000-8000-000000000001","kind":"belongs_to","source_native_id":"edge-1","from_entity_id":"pid_42000001-0000-4000-8000-000000000001","to_entity_id":"pid_42000002-0000-4000-8000-000000000002","attributes":{}}`)},
		{"uses_policy", collection.ProviderAWS, []json.RawMessage{
			json.RawMessage(`{"id":"pid_42000001-0000-4000-8000-000000000001","kind":"aws_role","source_native_id":"arn:aws:iam::123456789012:role/read","display_name":"read","stable_fields":{"account_id":"123456789012","arn":"arn:aws:iam::123456789012:role/read","name":"read"},"attributes":{}}`),
			json.RawMessage(`{"id":"pid_42000002-0000-4000-8000-000000000002","kind":"aws_policy","source_native_id":"arn:aws:iam::123456789012:policy/read","display_name":"read","stable_fields":{"account_id":"123456789012","arn":"arn:aws:iam::123456789012:policy/read","name":"read","policy_type":"managed"},"attributes":{}}`),
		}, json.RawMessage(`{"id":"pid_42000010-0000-4000-8000-000000000002","kind":"uses_policy","source_native_id":"edge-2","from_entity_id":"pid_42000001-0000-4000-8000-000000000001","to_entity_id":"pid_42000002-0000-4000-8000-000000000002","attributes":{}}`)},
		{"uses_identity", collection.ProviderKubernetes, []json.RawMessage{
			json.RawMessage(`{"id":"pid_42000001-0000-4000-8000-000000000001","kind":"kubernetes_workload","source_native_id":"deployment/api","display_name":"api","stable_fields":{"api_group":"apps","api_version":"v1","cluster":"api.example.com/prod","name":"api","namespace":"default","resource_kind":"Deployment","service_account":"api"},"attributes":{"namespaced":true}}`),
			json.RawMessage(`{"id":"pid_42000002-0000-4000-8000-000000000002","kind":"kubernetes_service_account","source_native_id":"serviceaccount/api","display_name":"api","stable_fields":{"api_group":"core","api_version":"v1","cluster":"api.example.com/prod","name":"api","namespace":"default","resource_kind":"ServiceAccount"},"attributes":{"namespaced":true}}`),
		}, json.RawMessage(`{"id":"pid_42000010-0000-4000-8000-000000000003","kind":"uses_identity","source_native_id":"edge-3","from_entity_id":"pid_42000001-0000-4000-8000-000000000001","to_entity_id":"pid_42000002-0000-4000-8000-000000000002","attributes":{"type":"workload_service_account"}}`)},
		{"binds", collection.ProviderKubernetes, []json.RawMessage{
			json.RawMessage(`{"id":"pid_42000001-0000-4000-8000-000000000001","kind":"kubernetes_role_binding","source_native_id":"rolebinding/readers","display_name":"readers","stable_fields":{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/prod","name":"readers","namespace":"default","resource_kind":"RoleBinding","role":"Role/reader","scope":"namespace"},"attributes":{"namespaced":true}}`),
			json.RawMessage(`{"id":"pid_42000002-0000-4000-8000-000000000002","kind":"kubernetes_role","source_native_id":"role/reader","display_name":"reader","stable_fields":{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/prod","name":"reader","namespace":"default","resource_kind":"Role","scope":"namespace"},"attributes":{"namespaced":true,"rules":[]}}`),
		}, json.RawMessage(`{"id":"pid_42000010-0000-4000-8000-000000000004","kind":"binds","source_native_id":"edge-4","from_entity_id":"pid_42000001-0000-4000-8000-000000000001","to_entity_id":"pid_42000002-0000-4000-8000-000000000002","attributes":{"type":"binding_role"}}`)},
		{"has_permission", collection.ProviderGitHub, []json.RawMessage{
			json.RawMessage(`{"id":"pid_42000001-0000-4000-8000-000000000001","kind":"github_app","source_native_id":"app/7","display_name":"zasp","stable_fields":{"installation_id":42,"name":"zasp","owner":"acme"},"attributes":{}}`),
			json.RawMessage(`{"id":"pid_42000002-0000-4000-8000-000000000002","kind":"github_permission","source_native_id":"permission/contents","display_name":"contents:read","stable_fields":{"installation_id":42,"name":"contents:read","owner":"acme","permission":"read","repository":"service","scope":"contents"},"attributes":{}}`),
		}, json.RawMessage(`{"id":"pid_42000010-0000-4000-8000-000000000005","kind":"has_permission","source_native_id":"edge-5","from_entity_id":"pid_42000001-0000-4000-8000-000000000001","to_entity_id":"pid_42000002-0000-4000-8000-000000000002","attributes":{"type":"app_permission"}}`)},
		{"assigned_to", collection.ProviderOkta, []json.RawMessage{
			json.RawMessage(`{"id":"pid_42000001-0000-4000-8000-000000000001","kind":"okta_user","source_native_id":"user/1","display_name":"Alice","stable_fields":{"name":"Alice","object_type":"user","tenant":"tenant.example.com"},"attributes":{"status":"ACTIVE"}}`),
			json.RawMessage(`{"id":"pid_42000002-0000-4000-8000-000000000002","kind":"okta_role","source_native_id":"role/1","display_name":"Application Administrator","stable_fields":{"name":"Application Administrator","object_type":"role","role":"APP_ADMIN","scope":"tenant","tenant":"tenant.example.com"},"attributes":{}}`),
		}, json.RawMessage(`{"id":"pid_42000010-0000-4000-8000-000000000006","kind":"assigned_to","source_native_id":"edge-6","from_entity_id":"pid_42000001-0000-4000-8000-000000000001","to_entity_id":"pid_42000002-0000-4000-8000-000000000002","attributes":{"type":"principal_role"}}`)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cursor := collection.Cursor{Provider: test.provider, Version: "cursor_v1", Value: "complete"}
			if _, err := NewPage(test.provider, collection.SubjectBinding{Kind: "provider", ID: "subject"}, cursor, true, test.entities, []json.RawMessage{test.relationship}); err != nil {
				t.Fatalf("required %s relationship rejected: %v", test.name, err)
			}
		})
	}
}

func TestProviderSchemaExpansionRemainsClosedAndSecretSafe(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "github_installation", ID: "42"}
	cursor := collection.Cursor{Provider: collection.ProviderGitHub, Version: "cursor_v1", Value: "complete"}
	for name, entity := range map[string]json.RawMessage{
		"unknown kind":  json.RawMessage(`{"id":"pid_43000001-0000-4000-8000-000000000001","kind":"github_secret","source_native_id":"secret-1","display_name":"Secret","stable_fields":{"installation_id":42,"name":"zasp","owner":"acme"},"attributes":{}}`),
		"unknown field": json.RawMessage(`{"id":"pid_43000001-0000-4000-8000-000000000001","kind":"github_app","source_native_id":"app-1","display_name":"App","stable_fields":{"installation_id":42,"name":"zasp","owner":"acme","private_key":"secret"},"attributes":{}}`),
		"secret field":  json.RawMessage(`{"id":"pid_43000001-0000-4000-8000-000000000001","kind":"github_app","source_native_id":"app-1","display_name":"App","stable_fields":{"installation_id":42,"name":"zasp","owner":"acme"},"attributes":{"access_token":"secret"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPage(collection.ProviderGitHub, subject, cursor, true, []json.RawMessage{entity}, nil); !errors.Is(err, collection.ErrContract) {
				t.Fatalf("hostile provider entity error = %v", err)
			}
		})
	}
}

func TestProviderSchemaRejectsRelationshipAuthorityDrift(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}
	cursor := collection.Cursor{Provider: collection.ProviderAWS, Version: "cursor_v1", Value: "complete"}
	entities := []json.RawMessage{
		json.RawMessage(`{"id":"pid_45000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{"account_id":"123456789012"},"attributes":{}}`),
		json.RawMessage(`{"id":"pid_45000002-0000-4000-8000-000000000002","kind":"aws_role","source_native_id":"arn:aws:iam::123456789012:role/read","display_name":"Read role","stable_fields":{"account_id":"123456789012","arn":"arn:aws:iam::123456789012:role/read","name":"read"},"attributes":{}}`),
	}
	for name, relationship := range map[string]json.RawMessage{
		"cross provider kind": json.RawMessage(`{"id":"pid_45000003-0000-4000-8000-000000000003","kind":"member_of","source_native_id":"bad-member","from_entity_id":"pid_45000002-0000-4000-8000-000000000002","to_entity_id":"pid_45000001-0000-4000-8000-000000000001","attributes":{}}`),
		"reversed endpoints":  json.RawMessage(`{"id":"pid_45000004-0000-4000-8000-000000000004","kind":"contains","source_native_id":"bad-direction","from_entity_id":"pid_45000002-0000-4000-8000-000000000002","to_entity_id":"pid_45000001-0000-4000-8000-000000000001","attributes":{}}`),
		"wrong target kind":   json.RawMessage(`{"id":"pid_45000005-0000-4000-8000-000000000005","kind":"uses_policy","source_native_id":"bad-policy","from_entity_id":"pid_45000002-0000-4000-8000-000000000002","to_entity_id":"pid_45000001-0000-4000-8000-000000000001","attributes":{}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPage(collection.ProviderAWS, subject, cursor, true, entities, []json.RawMessage{relationship}); !errors.Is(err, collection.ErrContract) {
				t.Fatalf("relationship drift error = %v", err)
			}
		})
	}
}

func TestKubernetesDanglingRoleReferenceRemainsExplicitWithoutAProductGraphEdge(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/prod"}
	target := deterministicKubernetesReferenceID(subject, "kubernetes_role", "default/deleted-reader")
	binding := json.RawMessage(`{"id":"pid_47000001-0000-4000-8000-000000000001","kind":"kubernetes_role_binding","source_native_id":"rolebinding/readers","display_name":"readers","stable_fields":{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/prod","name":"readers","namespace":"default","resource_kind":"RoleBinding","role":"Role/deleted-reader","scope":"namespace"},"attributes":{"namespaced":true}}`)
	binds := json.RawMessage(fmt.Sprintf(`{"id":"pid_47000002-0000-4000-8000-000000000002","kind":"binds","source_native_id":"rolebinding/readers/role","from_entity_id":"pid_47000001-0000-4000-8000-000000000001","to_entity_id":%q,"attributes":{"type":"binding_role"}}`, target))
	objects := map[string]collection.RawObject{"pid_47000001-0000-4000-8000-000000000001": {}}
	resolved, ok := relationshipsResolve(collection.ProviderKubernetes, subject, []json.RawMessage{binds}, []json.RawMessage{binding}, objects)
	if !ok || len(resolved) != 0 || !bytes.Contains(binding, []byte(`"role":"Role/deleted-reader"`)) {
		t.Fatalf("resolved=%s ok=%t binding=%s", resolved, ok, binding)
	}
	foreign := bytes.Replace(binds, []byte(target), []byte("pid_47000003-0000-4000-8000-000000000003"), 1)
	if _, ok := relationshipsResolve(collection.ProviderKubernetes, subject, []json.RawMessage{foreign}, []json.RawMessage{binding}, objects); ok {
		t.Fatal("arbitrary missing role target was accepted")
	}
}

func TestKubernetesDanglingClusterRoleBindingRequiresExactStableTarget(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/prod"}
	target := deterministicKubernetesReferenceID(subject, "kubernetes_cluster_role", "deleted-auditor")
	binding := json.RawMessage(`{"id":"pid_47000011-0000-4000-8000-000000000011","kind":"kubernetes_cluster_role_binding","source_native_id":"clusterrolebinding/auditors","display_name":"auditors","stable_fields":{"api_group":"rbac.authorization.k8s.io","api_version":"v1","cluster":"api.example.com/prod","name":"auditors","resource_kind":"ClusterRoleBinding","role":"ClusterRole/deleted-auditor","scope":"cluster"},"attributes":{"namespaced":false}}`)
	binds := json.RawMessage(fmt.Sprintf(`{"id":"pid_47000012-0000-4000-8000-000000000012","kind":"binds","source_native_id":"clusterrolebinding/auditors/role","from_entity_id":"pid_47000011-0000-4000-8000-000000000011","to_entity_id":%q,"attributes":{"type":"binding_role"}}`, target))
	objects := map[string]collection.RawObject{"pid_47000011-0000-4000-8000-000000000011": {}}
	resolved, ok := relationshipsResolve(collection.ProviderKubernetes, subject, []json.RawMessage{binds}, []json.RawMessage{binding}, objects)
	if !ok || len(resolved) != 0 {
		t.Fatalf("resolved=%s ok=%t", resolved, ok)
	}
	foreign := bytes.Replace(binds, []byte(target), []byte("pid_47000013-0000-4000-8000-000000000013"), 1)
	if _, ok := relationshipsResolve(collection.ProviderKubernetes, subject, []json.RawMessage{foreign}, []json.RawMessage{binding}, objects); ok {
		t.Fatal("arbitrary missing cluster role target was accepted")
	}
}
