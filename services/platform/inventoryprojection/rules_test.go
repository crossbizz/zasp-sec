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
		{Provider: "aws", SourceKind: "aws_agentcore_gateway", Namespace: "aws_agentcore_gateway", ProductKind: KindTool, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_agentcore_runtime", Namespace: "aws_agentcore_runtime", ProductKind: KindAgent, Version: 1, Priority: 100, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_bedrock_agent", Namespace: "aws_bedrock_agent", ProductKind: KindAgent, Version: 1, Priority: 100, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_data_store", Namespace: "aws_data_store", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_inferred_agent", Namespace: "aws_inferred_agent", ProductKind: KindAgent, Version: 1, Priority: 100, ConfidenceBasisPoints: 6000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_mcp_server", Namespace: "aws_mcp_server", ProductKind: KindTool, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_mcp_tool", Namespace: "aws_mcp_tool", ProductKind: KindTool, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_policy", Namespace: "aws_policy", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_resource", Namespace: "aws_resource", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_role", Namespace: "aws_role", ProductKind: KindIdentity, Version: 2, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "aws", SourceKind: "aws_service", Namespace: "aws_service", ProductKind: KindAsset, Version: 1, Priority: 100, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_agent_project", Namespace: "github_agent_project", ProductKind: KindAgent, Version: 1, Priority: 120, ConfidenceBasisPoints: 6000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_agent_skill", Namespace: "github_agent_skill", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_app", Namespace: "github_app", ProductKind: KindTool, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_environment", Namespace: "github_environment", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_installation", Namespace: "github_installation", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_mcp_server", Namespace: "github_mcp_server", ProductKind: KindTool, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_mcp_tool", Namespace: "github_mcp_tool", ProductKind: KindTool, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_organization", Namespace: "github_organization", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_permission", Namespace: "github_permission", ProductKind: KindAsset, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_repository", Namespace: "github_repository", ProductKind: KindTool, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "github", SourceKind: "github_workflow", Namespace: "github_workflow", ProductKind: KindTool, Version: 1, Priority: 120, ConfidenceBasisPoints: 9000, Freshness: 24 * time.Hour},
		{Provider: "kubernetes", SourceKind: "kubernetes_agent", Namespace: "kubernetes_agent", ProductKind: KindAgent, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_cluster", Namespace: "kubernetes_cluster", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_cluster_role", Namespace: "kubernetes_cluster_role", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_cluster_role_binding", Namespace: "kubernetes_cluster_role_binding", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_group", Namespace: "kubernetes_group", ProductKind: KindIdentity, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_inferred_agent", Namespace: "kubernetes_inferred_agent", ProductKind: KindAgent, Version: 1, Priority: 80, ConfidenceBasisPoints: 6000, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_mcp_server", Namespace: "kubernetes_mcp_server", ProductKind: KindTool, Version: 1, Priority: 80, ConfidenceBasisPoints: 6000, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_namespace", Namespace: "kubernetes_namespace", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_resource", Namespace: "kubernetes_resource", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_role", Namespace: "kubernetes_role", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_role_binding", Namespace: "kubernetes_role_binding", ProductKind: KindAsset, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_service_account", Namespace: "kubernetes_service_account", ProductKind: KindIdentity, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_user", Namespace: "kubernetes_user", ProductKind: KindIdentity, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "kubernetes", SourceKind: "kubernetes_workload", Namespace: "kubernetes_workload", ProductKind: KindRuntime, Version: 1, Priority: 80, ConfidenceBasisPoints: 9500, Freshness: 15 * time.Minute},
		{Provider: "microsoft", SourceKind: "microsoft_agent_identity", Namespace: "microsoft_agent_identity", ProductKind: KindAgent, Version: 1, Priority: 130, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "microsoft", SourceKind: "microsoft_ai_application", Namespace: "microsoft_ai_application", ProductKind: KindAgent, Version: 1, Priority: 130, ConfidenceBasisPoints: 7000, Freshness: 24 * time.Hour},
		{Provider: "microsoft", SourceKind: "microsoft_ai_deployment", Namespace: "microsoft_ai_deployment", ProductKind: KindAsset, Version: 1, Priority: 130, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "microsoft", SourceKind: "microsoft_ai_resource", Namespace: "microsoft_ai_resource", ProductKind: KindAsset, Version: 1, Priority: 130, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "microsoft", SourceKind: "microsoft_copilot_agent", Namespace: "microsoft_copilot_agent", ProductKind: KindAgent, Version: 1, Priority: 130, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "microsoft", SourceKind: "microsoft_tenant", Namespace: "microsoft_tenant", ProductKind: KindAsset, Version: 1, Priority: 130, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_ai_application", Namespace: "okta_ai_application", ProductKind: KindAgent, Version: 1, Priority: 110, ConfidenceBasisPoints: 7000, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_application", Namespace: "okta_application", ProductKind: KindTool, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_group", Namespace: "okta_group", ProductKind: KindIdentity, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_role", Namespace: "okta_role", ProductKind: KindAsset, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_service_principal", Namespace: "okta_service_principal", ProductKind: KindIdentity, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_tenant", Namespace: "okta_tenant", ProductKind: KindAsset, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "okta", SourceKind: "okta_user", Namespace: "okta_user", ProductKind: KindIdentity, Version: 1, Priority: 110, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "salesforce", SourceKind: "salesforce_agent", Namespace: "salesforce_agent", ProductKind: KindAgent, Version: 1, Priority: 140, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "salesforce", SourceKind: "salesforce_org", Namespace: "salesforce_org", ProductKind: KindAsset, Version: 1, Priority: 140, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "saas", SourceKind: "saas_agent", Namespace: "saas_agent", ProductKind: KindAgent, Version: 1, Priority: 150, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "saas", SourceKind: "saas_ai_application", Namespace: "saas_ai_application", ProductKind: KindAgent, Version: 1, Priority: 150, ConfidenceBasisPoints: 7000, Freshness: 24 * time.Hour},
		{Provider: "saas", SourceKind: "saas_mcp_server", Namespace: "saas_mcp_server", ProductKind: KindTool, Version: 1, Priority: 150, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
		{Provider: "saas", SourceKind: "saas_tenant", Namespace: "saas_tenant", ProductKind: KindAsset, Version: 1, Priority: 150, ConfidenceBasisPoints: 9500, Freshness: 24 * time.Hour},
	}

	actual := RuleCatalog()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("catalog = %#v, want %#v", actual, expected)
	}
	digest := RuleCatalogDigest()
	if got := hex.EncodeToString(digest[:]); got != "cb8d8d45c753ad53654b44bbc1a6c4ed70fba671049b03047b26d1c12bad8169" {
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
