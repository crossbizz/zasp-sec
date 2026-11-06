package preflight

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	ostypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/cloudreadiness"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
	inventoryos "github.com/zasp-ai/zasp-sec/services/platform/inventorysearch/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	runtimeos "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

type OpenSearchSummary struct {
	DomainObserved                      bool     `json:"domain_observed"`
	SchemaReadsObserved                 []string `json:"schema_reads_observed"`
	GlobalDeploymentPhaseObserved       bool     `json:"global_deployment_phase_observed"`
	RequiredMutationPermissionsObserved bool     `json:"required_mutation_permissions_observed"`
	WorkloadNetworkOriginObserved       bool     `json:"workload_network_origin_observed"`
}
type openSearchDomainEvidence struct {
	targetDigest string
	observedAt   time.Time
}

func (r *Runner) observeOpenSearchDomain(ctx context.Context, report *Report) *openSearchDomainEvidence {
	if r == nil || ctx == nil || ctx.Err() != nil || r.config.OpenSearch == nil || !validOpenSearchConfig(r.config) {
		return nil
	}
	report.OpenSearch = &OpenSearchSummary{SchemaReadsObserved: []string{}}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	inspector := *r
	inspector.config = r.config
	inspector.config.Credentials = r.config.AWSAuthority.Inspection
	credentials, e := inspector.credentials(bounded)
	if e != nil {
		// Loading local authority is a prerequisite, not an attempted STS read.
		// Preserve earlier attempted evidence instead of replacing it with unknown.
		for i := range report.Checks {
			for j := range report.Checks[i].Observations {
				o := &report.Checks[i].Observations[j]
				if o.Name == "opensearch_reachable" && o.Status == "unobserved" && o.Kind == "unobserved" && o.ObservedAt == nil && len(o.Failures) == 0 {
					o.Code = "inspection_credentials_unavailable"
				}
			}
		}
		return nil
	}
	defer func() { credentials = aws.Credentials{} }()
	sdk := aws.Config{Region: r.config.Deployment.Region, HTTPClient: r.http, Credentials: aws.CredentialsProviderFunc(func(c context.Context) (aws.Credentials, error) {
		if c.Err() != nil || credentials.CanExpire && !credentials.Expires.After(time.Now().Add(time.Minute)) {
			return aws.Credentials{}, ErrRejected
		}
		return credentials, nil
	}), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	identity, e := sts.NewFromConfig(sdk).GetCallerIdentity(bounded, &sts.GetCallerIdentityInput{})
	if e == nil && (identity == nil || aws.ToString(identity.Account) == "" || aws.ToString(identity.Arn) == "") {
		e = errMalformedProviderObservation
	}
	if e != nil || bounded.Err() != nil || !cloudreadiness.Role(identity, r.config.Deployment.Partition, r.config.Deployment.AccountID, r.config.AWSAuthority.Inspection.ExpectedRoleARN) {
		r.openSearchFailure(report, "sts:GetCallerIdentity", failureOutcome(probeError(bounded, e)))
		return nil
	}
	out, e := opensearch.NewFromConfig(sdk).DescribeDomain(bounded, &opensearch.DescribeDomainInput{DomainName: aws.String(r.config.OpenSearch.DomainName)})
	if e != nil || bounded.Err() != nil {
		r.openSearchFailure(report, "opensearch:DescribeDomain", failureOutcome(probeError(bounded, e)))
		return nil
	}
	if out == nil || !matchesOpenSearchDomain(r.config, out.DomainStatus) {
		r.openSearchFailure(report, "opensearch:DescribeDomain", "binding_mismatch")
		return nil
	}
	report.OpenSearch.DomainObserved = true
	return &openSearchDomainEvidence{targetDigest: singleTargetDigest(r.config.OpenSearch), observedAt: time.Now().UTC()}
}
func (r *Runner) observeOpenSearchSchemas(ctx context.Context, report *Report, sdk aws.Config, authority *awsAuthorityEvidence, proof *awsWebIdentityProof, reader KubernetesIdentityReader, domain *openSearchDomainEvidence) {
	if r == nil || ctx == nil || ctx.Err() != nil || report == nil || r.config.OpenSearch == nil || r.config.AWSAuthority == nil || r.config.AWSAuthority.Selected == nil || report.OpenSearch == nil {
		return
	}
	dependencyCode(report, "opensearch_index_access", "required_mutations_and_global_phase_unobserved")
	now := time.Now().UTC()
	if authority == nil || !authority.clusterVerified || !authority.selectedExchangeVerified || !authority.selectedSpecVerified || proof == nil || !proof.expires.After(now.Add(time.Minute)) || r.config.Credentials.Kind != "workload_web_identity" || !r.freshOpenSearchDomain(domain, now) {
		return
	}
	selected := *r.config.AWSAuthority.Selected
	namespace, sa := openSearchSubject(selected.Purpose)
	roles, ok := authorityRoles(r.config.AWSAuthority, requiredAWSRoleInventory(r.config.Features.AttackLab == "enabled"), r.config.Deployment)
	if !ok || roles[selected.Purpose] == "" || r.config.Credentials.ExpectedRoleARN != roles[selected.Purpose] || proof.requestedRoleARN != roles[selected.Purpose] || proof.subject != "system:serviceaccount:"+namespace+":"+sa || proof.audience != "sts.amazonaws.com" || proof.provider != r.config.AWSAuthority.Cluster.Issuer {
		return
	}
	actual, ok := reader.(openSearchWorkloadReader)
	if !ok {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	current, e := sts.NewFromConfig(sdk).GetCallerIdentity(bounded, &sts.GetCallerIdentityInput{})
	if e == nil && (current == nil || aws.ToString(current.Account) == "" || aws.ToString(current.Arn) == "") {
		e = errMalformedProviderObservation
	}
	if e != nil || bounded.Err() != nil || !cloudreadiness.Role(current, r.config.Deployment.Partition, r.config.Deployment.AccountID, roles[selected.Purpose]) {
		r.openSearchFailure(report, "sts:GetCallerIdentity", failureOutcome(probeError(bounded, e)), "workload")
		return
	}
	workload, e := actual.OpenSearchWorkload(bounded, selected, r.config.OpenSearch.Container)
	if e != nil {
		r.openSearchFailure(report, "kubernetes:GetSelectedOpenSearchPod", openSearchOutcome(e), "workload")
		return
	}
	footprint, e := deriveOpenSearchFootprint(*r.config.OpenSearch, selected, workload)
	if e != nil {
		r.openSearchFailure(report, "kubernetes:GetSelectedOpenSearchPod", "binding_mismatch", "workload")
		return
	}
	for _, index := range footprint {
		if bounded.Err() != nil || !proof.expires.After(time.Now().Add(time.Minute)) || !r.freshOpenSearchDomain(domain, time.Now().UTC()) {
			return
		}
		capture := &openSearchReadCapture{client: r.http}
		var observer interface{ Ready(context.Context) error }
		clock := func() time.Time { return time.Now().UTC() }
		if index == "zasp-inventory-v1" {
			observer, e = inventoryos.NewSchemaObserver(inventoryos.Config{Endpoint: r.config.OpenSearch.Endpoint, Region: r.config.Deployment.Region, RequestTimeout: 5 * time.Second, MaximumRequestBytes: 65536, MaximumResponseBytes: 65536}, sdk.Credentials, v4.NewSigner(), capture, clock)
		} else {
			observer, e = runtimeos.NewSchemaObserver(index, runtimeos.Config{Endpoint: r.config.OpenSearch.Endpoint, Region: r.config.Deployment.Region, RequestTimeout: 5 * time.Second, MaximumRequestBytes: 65536, MaximumResponseBytes: 65536}, sdk.Credentials, v4.NewSigner(), capture, clock)
		}
		if e == nil {
			e = observer.Ready(bounded)
		}
		if e != nil {
			operation := "opensearch:GetMapping"
			if strings.Contains(capture.path, "/_doc/") {
				operation = "opensearch:GetSchemaMarker"
			}
			outcome := "unreachable"
			if capture.status == http.StatusUnauthorized || capture.status == http.StatusForbidden {
				outcome = "denied"
			} else if capture.status == http.StatusNotFound || errors.Is(e, runtimeindex.ErrDrift) || errors.Is(e, inventorysearch.ErrDrift) {
				outcome = "binding_mismatch"
			}
			r.openSearchFailure(report, operation, outcome, "workload")
			return
		}
		report.OpenSearch.SchemaReadsObserved = append(report.OpenSearch.SchemaReadsObserved, index)
	}
	if bounded.Err() != nil || !proof.expires.After(time.Now().Add(time.Minute)) || !r.freshOpenSearchDomain(domain, time.Now().UTC()) {
		return
	}
	// These are signed reads from this process. They do not attest workload-plane
	// origin, global release phase or any unexercised mutation permission.
	r.record(report, "opensearch_reachable", true, "", "workload", r.config.OpenSearch, true)
}
func (r *Runner) freshOpenSearchDomain(domain *openSearchDomainEvidence, now time.Time) bool {
	return domain != nil && !domain.observedAt.IsZero() && !domain.observedAt.Before(now.Add(-30*time.Second)) && !domain.observedAt.After(now.Add(5*time.Second)) && domain.targetDigest == singleTargetDigest(r.config.OpenSearch)
}

func validOpenSearchConfig(c Config) bool {
	t := c.OpenSearch
	if t == nil {
		return true
	}
	if c.AWSAuthority == nil || !regexp.MustCompile(`^[a-z][a-z0-9-]{2,27}$`).MatchString(t.DomainName) || t.DomainARN != "arn:"+c.Deployment.Partition+":es:"+c.Deployment.Region+":"+c.Deployment.AccountID+":domain/"+t.DomainName || t.VPCID != c.AWSAuthority.Cluster.VPCID || !regexp.MustCompile(`^vpc-([0-9a-f]{8}|[0-9a-f]{17})$`).MatchString(t.VPCID) || !validOpenSearchEndpointTarget(t.Endpoint, c.Deployment.Region) || !validKey(c, t.KMSKeyARN) || !dnsPattern.MatchString(t.Container) || len(t.Image) > 512 || !regexp.MustCompile(`^[A-Za-z0-9._/:+-]+@sha256:[0-9a-f]{64}$`).MatchString(t.Image) {
		return false
	}
	if !validOpenSearchIDs(t.SubnetIDs, "subnet") || !validOpenSearchIDs(t.SecurityGroupIDs, "sg") {
		return false
	}
	switch t.SessionSearchPhase {
	case "compatibility", "backfill", "query", "precision-consumers", "precision-intake":
		return true
	}
	return false
}
func validOpenSearchIDs(values []string, prefix string) bool {
	if len(values) < 1 || len(values) > 16 {
		return false
	}
	seen := map[string]bool{}
	p := regexp.MustCompile(`^` + prefix + `-([0-9a-f]{8}|[0-9a-f]{17})$`)
	for _, v := range values {
		if seen[v] || !p.MatchString(v) {
			return false
		}
		seen[v] = true
	}
	return true
}
func sameOpenSearchIDs(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	a := append([]string(nil), actual...)
	b := append([]string(nil), expected...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func matchesOpenSearchDomain(c Config, d *ostypes.DomainStatus) bool {
	t := c.OpenSearch
	if t == nil || d == nil || aws.ToString(d.ARN) != t.DomainARN || aws.ToString(d.DomainName) != t.DomainName || aws.ToString(d.DomainId) != c.Deployment.AccountID+"/"+t.DomainName || d.Created == nil || !aws.ToBool(d.Created) || d.Deleted == nil || aws.ToBool(d.Deleted) || d.Processing == nil || aws.ToBool(d.Processing) || d.UpgradeProcessing == nil || aws.ToBool(d.UpgradeProcessing) || aws.ToString(d.EngineVersion) != "OpenSearch_2.19" || aws.ToString(d.Endpoint) != "" || aws.ToString(d.EndpointV2) != "" || len(d.Endpoints) != 1 || "https://"+d.Endpoints["vpc"] != t.Endpoint || d.VPCOptions == nil || aws.ToString(d.VPCOptions.VPCId) != t.VPCID || !sameOpenSearchIDs(d.VPCOptions.SubnetIds, t.SubnetIDs) || !sameOpenSearchIDs(d.VPCOptions.SecurityGroupIds, t.SecurityGroupIDs) || d.EncryptionAtRestOptions == nil || !aws.ToBool(d.EncryptionAtRestOptions.Enabled) || d.NodeToNodeEncryptionOptions == nil || !aws.ToBool(d.NodeToNodeEncryptionOptions.Enabled) || d.DomainEndpointOptions == nil || !aws.ToBool(d.DomainEndpointOptions.EnforceHTTPS) || string(d.DomainEndpointOptions.TLSSecurityPolicy) != "Policy-Min-TLS-1-2-2019-07" || aws.ToBool(d.DomainEndpointOptions.CustomEndpointEnabled) {
		return false
	}
	key := aws.ToString(d.EncryptionAtRestOptions.KmsKeyId)
	// DescribeDomain documents a UUID key ID. Both it and the full ARN are bound
	// to the exact configured key; no alias or cross-target lookup is accepted.
	expectedID := strings.TrimPrefix(t.KMSKeyARN, "arn:"+c.Deployment.Partition+":kms:"+c.Deployment.Region+":"+c.Deployment.AccountID+":key/")
	return key == t.KMSKeyARN || key == expectedID
}
func (r *Runner) openSearchFailure(report *Report, operation, outcome string, selectedIdentity ...string) {
	identity := "operator"
	if len(selectedIdentity) == 1 {
		identity = selectedIdentity[0]
	}
	hint := "verify es:DescribeDomain on the exact configured domain, account, VPC, KMS and HTTPS settings; inspect only with the explicit operator identity"
	if operation == "sts:GetCallerIdentity" {
		hint = "verify the exact selected identity and reachable STS; GetCallerIdentity needs no IAM allow"
	} else if operation == "kubernetes:GetSelectedOpenSearchPod" {
		hint = "verify the exact selected Pod UID, service account, container image and literal endpoint/index/stage; do not resolve secret references"
	} else if operation == "opensearch:GetMapping" || operation == "opensearch:GetSchemaMarker" {
		hint = "verify es:ESHttpGet on the selected fixed mapping/schema-marker path; missing, malformed or drifted compiled schema shares binding_mismatch; initialize only through the separately authorized installer"
	}
	for i := range report.Checks {
		for j := range report.Checks[i].Observations {
			o := &report.Checks[i].Observations[j]
			if o.Name == "opensearch_reachable" {
				o.Status = "fail"
				o.Kind = "provider-read"
				o.Code = "opensearch_authority_unavailable"
				if (operation == "opensearch:GetMapping" || operation == "opensearch:GetSchemaMarker") && outcome == "binding_mismatch" {
					o.Code = "schema_missing_invalid_or_drifted"
				}
				o.IdentityKind = identity
				o.TargetDigest = singleTargetDigest(r.config.OpenSearch)
				now := time.Now().UTC()
				o.ObservedAt = &now
				if len(o.Failures) < 32 {
					o.Failures = append(o.Failures, Failure{Operation: operation, Hint: hint, TargetDigest: o.TargetDigest, Outcome: outcome})
				}
			}
		}
	}
}

// Keep HTTP status metadata only, never a provider body or Authorization field.
type openSearchReadCapture struct {
	client *http.Client
	status int
	path   string
}

func (c *openSearchReadCapture) Do(r *http.Request) (*http.Response, error) {
	c.status, c.path = 0, r.URL.Path
	out, e := c.client.Do(r)
	if out != nil {
		c.status = out.StatusCode
	}
	return out, e
}

func openSearchOutcome(e error) string {
	var typed *awsKubernetesOutcomeError
	if errors.As(e, &typed) {
		return typed.outcome
	}
	return failureOutcome(e)
}
