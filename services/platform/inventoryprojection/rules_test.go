package inventoryprojection

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

func TestRuleCatalogBindsExactProviderKindsToProductAuthority(t *testing.T) {
	expected := []Rule{
		{Provider: "aws", SourceKind: "aws_account", Namespace: "aws_account", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_policy", Namespace: "aws_policy", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_resource", Namespace: "aws_resource", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_role", Namespace: "aws_role", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_service", Namespace: "aws_service", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_app", Namespace: "github_app", ProductKind: KindTool, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_environment", Namespace: "github_environment", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_installation", Namespace: "github_installation", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_organization", Namespace: "github_organization", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_permission", Namespace: "github_permission", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_repository", Namespace: "github_repository", ProductKind: KindTool, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_workflow", Namespace: "github_workflow", ProductKind: KindTool, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "kubernetes", SourceKind: "kubernetes_agent", Namespace: "kubernetes_agent", ProductKind: KindAgent, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_cluster", Namespace: "kubernetes_cluster", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_cluster_role", Namespace: "kubernetes_cluster_role", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_cluster_role_binding", Namespace: "kubernetes_cluster_role_binding", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_group", Namespace: "kubernetes_group", ProductKind: KindIdentity, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_namespace", Namespace: "kubernetes_namespace", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_resource", Namespace: "kubernetes_resource", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_role", Namespace: "kubernetes_role", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_role_binding", Namespace: "kubernetes_role_binding", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_service_account", Namespace: "kubernetes_service_account", ProductKind: KindIdentity, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_user", Namespace: "kubernetes_user", ProductKind: KindIdentity, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_workload", Namespace: "kubernetes_workload", ProductKind: KindRuntime, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "okta", SourceKind: "okta_application", Namespace: "okta_application", ProductKind: KindTool, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_group", Namespace: "okta_group", ProductKind: KindIdentity, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_role", Namespace: "okta_role", ProductKind: KindAsset, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_service_principal", Namespace: "okta_service_principal", ProductKind: KindIdentity, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_tenant", Namespace: "okta_tenant", ProductKind: KindAsset, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_user", Namespace: "okta_user", ProductKind: KindIdentity, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
	}

	actual := RuleCatalog()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("catalog = %#v, want %#v", actual, expected)
	}
	digest := RuleCatalogDigest()
	if got := hex.EncodeToString(digest[:]); got != "44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30" {
		t.Fatalf("catalog digest = %s", got)
	}

	actual[0].Namespace = "mutated"
	if replay := RuleCatalog(); !reflect.DeepEqual(replay, expected) {
		t.Fatalf("catalog shared mutable state: %#v", replay)
	}
}

func TestRuleCatalogLookupRejectsUnknownOrNoncanonicalAuthority(t *testing.T) {
	rule, ok := LookupRule("kubernetes", "kubernetes_agent")
	if !ok || rule.ProductKind != KindAgent || rule.Freshness != 15*time.Minute {
		t.Fatalf("agent rule = %#v, ok=%t", rule, ok)
	}
	for _, query := range [][2]string{
		{"AWS", "aws_account"},
		{"aws", "AWS_ACCOUNT"},
		{"aws", "unknown"},
		{"", "aws_account"},
		{"kubernetes", "kubernetes/agent"},
	} {
		if value, exists := LookupRule(query[0], query[1]); exists || value != (Rule{}) {
			t.Fatalf("LookupRule(%q,%q) = %#v, %t", query[0], query[1], value, exists)
		}
	}
}
