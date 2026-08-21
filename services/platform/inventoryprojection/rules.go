package inventoryprojection

import (
	"crypto/sha256"
	"encoding/json"
	"time"
)

type Rule struct {
	Provider              string
	SourceKind            string
	Namespace             string
	ProductKind           Kind
	Version               int
	Priority              int
	ConfidenceBasisPoints int
	Freshness             time.Duration
}

var ruleCatalog = []Rule{
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

func RuleCatalog() []Rule {
	return append([]Rule(nil), ruleCatalog...)
}

func LookupRule(provider, sourceKind string) (Rule, bool) {
	for _, rule := range ruleCatalog {
		if rule.Provider == provider && rule.SourceKind == sourceKind {
			return rule, true
		}
	}
	return Rule{}, false
}

func RuleCatalogDigest() [sha256.Size]byte {
	type canonicalRule struct {
		Provider              string `json:"provider"`
		SourceKind            string `json:"source_kind"`
		Namespace             string `json:"namespace"`
		ProductKind           Kind   `json:"product_kind"`
		Version               int    `json:"version"`
		Priority              int    `json:"priority"`
		ConfidenceBasisPoints int    `json:"confidence_basis_points"`
		FreshnessSeconds      int64  `json:"freshness_seconds"`
	}
	values := make([]canonicalRule, 0, len(ruleCatalog))
	for _, rule := range ruleCatalog {
		values = append(values, canonicalRule{
			Provider: rule.Provider, SourceKind: rule.SourceKind, Namespace: rule.Namespace, ProductKind: rule.ProductKind,
			Version: rule.Version, Priority: rule.Priority, ConfidenceBasisPoints: rule.ConfidenceBasisPoints, FreshnessSeconds: int64(rule.Freshness / time.Second),
		})
	}
	encoded, _ := json.Marshal(values)
	return sha256.Sum256(encoded)
}
