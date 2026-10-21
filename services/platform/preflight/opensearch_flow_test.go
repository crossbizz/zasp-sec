package preflight

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type openSearchDomainFlowTransport struct {
	delegate               *awsAuthorityFixtureTransport
	domain                 *OpenSearchConfig
	mode                   string
	domainCalls, dataCalls int
}

func (tr *openSearchDomainFlowTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "/opensearch/domain/") {
		tr.domainCalls++
		if r.Method != http.MethodGet || r.URL.Host != "es.us-west-2.amazonaws.com" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || r.URL.Path != "/2021-01-01/opensearch/domain/product-events" || r.URL.RawQuery != "" {
			return nil, ErrRejected
		}
		if tr.mode == "denied" {
			return &http.Response{StatusCode: 403, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"message":"provider-secret-not-for-report"}`))}, nil
		}
		target := tr.domain
		d := map[string]any{"ARN": target.DomainARN, "DomainName": target.DomainName, "DomainId": "123456789012/" + target.DomainName, "Created": true, "Deleted": false, "Processing": false, "UpgradeProcessing": false, "EngineVersion": "OpenSearch_2.19", "Endpoints": map[string]string{"vpc": strings.TrimPrefix(target.Endpoint, "https://")}, "VPCOptions": map[string]any{"VPCId": target.VPCID, "SubnetIds": target.SubnetIDs, "SecurityGroupIds": target.SecurityGroupIDs}, "EncryptionAtRestOptions": map[string]any{"Enabled": true, "KmsKeyId": target.KMSKeyARN}, "NodeToNodeEncryptionOptions": map[string]bool{"Enabled": true}, "DomainEndpointOptions": map[string]any{"EnforceHTTPS": true, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"}, "ClusterConfig": map[string]any{"InstanceCount": 2, "ZoneAwarenessEnabled": true}}
		switch tr.mode {
		case "wrong account":
			d["ARN"] = "arn:aws:es:us-west-2:999999999999:domain/product-events"
		case "wrong engine":
			d["EngineVersion"] = "OpenSearch_2.11"
		case "public endpoint":
			delete(d, "Endpoints")
			d["Endpoint"] = strings.TrimPrefix(target.Endpoint, "https://")
		case "wrong VPC":
			d["VPCOptions"] = map[string]any{"VPCId": "vpc-foreign", "SubnetIds": target.SubnetIDs, "SecurityGroupIds": target.SecurityGroupIDs}
		case "missing presence":
			delete(d, "Created")
		}
		b, _ := json.Marshal(map[string]any{"DomainStatus": d})
		if tr.mode == "malformed" {
			b = []byte("{")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
	}
	if strings.HasSuffix(r.URL.Host, ".es.amazonaws.com") {
		tr.dataCalls++
		return nil, ErrRejected
	}
	return tr.delegate.RoundTrip(r)
}
func openSearchDomainFlowConfig(t *testing.T) (Config, *openSearchDomainFlowTransport) {
	c := sdkContractConfig(t)
	authority, _, delegate := awsAuthorityFixtureConfig(t)
	c.AWSAuthority = authority
	c.Credentials = authority.Inspection
	c.Features.SensorMode = "disabled"
	c.OpenSearch = &OpenSearchConfig{DomainName: "product-events", DomainARN: "arn:aws:es:us-west-2:123456789012:domain/product-events", Endpoint: "https://vpc-product-events.us-west-2.es.amazonaws.com", VPCID: authority.Cluster.VPCID, SubnetIDs: []string{"subnet-11111111111111111", "subnet-22222222222222222"}, SecurityGroupIDs: []string{"sg-11111111111111111"}, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", SessionSearchPhase: "compatibility", Container: "runtime-index", Image: "example/worker@sha256:" + strings.Repeat("a", 64)}
	return c, &openSearchDomainFlowTransport{delegate: delegate, domain: c.OpenSearch}
}
func TestOpenSearchActualDescribeDomainIsMountedAndNeverProvesWorkloadWrites(t *testing.T) {
	for _, mode := range []string{"exact operator metadata", "denied", "wrong account", "wrong engine", "public endpoint", "wrong VPC", "missing presence", "malformed", "missing local inspector credentials"} {
		t.Run(mode, func(t *testing.T) {
			c, tr := openSearchDomainFlowConfig(t)
			tr.mode = mode
			if mode == "missing local inspector credentials" {
				c.AWSAuthority.Inspection.Kind = "operator_file"
				c.AWSAuthority.Inspection.File = filepath.Join(t.TempDir(), "missing-inspector-credentials")
				c.Credentials = c.AWSAuthority.Inspection
			}
			r, e := NewRunner(c)
			if e != nil {
				t.Fatal("explicit exact target config refused")
			}
			defer r.Close()
			r.http = &http.Client{Transport: tr}
			report, e := r.Run(context.Background(), "installed")
			if mode == "missing local inspector credentials" {
				if tr.domainCalls != 0 || tr.dataCalls != 0 || len(tr.delegate.calls) != 0 {
					t.Fatal("missing local prerequisite attempted provider operation")
				}
				found := false
				for _, check := range report.Checks {
					for _, o := range check.Observations {
						if o.Name == "opensearch_reachable" {
							found = true
							if o.Kind != "unobserved" || o.Status != "unobserved" || o.ObservedAt != nil || o.Code != "inspection_credentials_unavailable" || len(o.Failures) != 0 {
								t.Fatal("missing local credentials fabricated an observed provider attempt")
							}
						}
					}
				}
				if !found {
					t.Fatal("original OpenSearch observation missing")
				}
				// A prior attempted failure is immutable diagnostic evidence even when a
				// later prerequisite read fails before another provider call is possible.
				prior := initialReport(c, "installed")
				r.openSearchFailure(&prior, "opensearch:DescribeDomain", "denied")
				before := prior.Checks[3].Observations[0]
				r.observeOpenSearchDomain(context.Background(), &prior)
				if !reflect.DeepEqual(before, prior.Checks[3].Observations[0]) {
					t.Fatal("local prerequisite replaced earlier attempted failure")
				}
			} else if tr.domainCalls != 1 || tr.dataCalls != 0 {
				t.Fatal("actual mounted domain SDK read missing or operator used workload data plane")
			}
			if report.OpenSearch == nil {
				t.Fatal("OpenSearch read results not attached to report")
			}
			if mode == "exact operator metadata" {
				if !report.OpenSearch.DomainObserved {
					t.Fatal("actual exact domain not observed")
				}
			} else if report.OpenSearch.DomainObserved {
				t.Fatal("unobserved domain identity became trusted")
			}
			if e == nil || report.Ready || report.ProductionEndToEndVerified || report.OpenSearch.RequiredMutationPermissionsObserved || report.OpenSearch.GlobalDeploymentPhaseObserved || report.OpenSearch.WorkloadNetworkOriginObserved {
				t.Fatal("read-only subset promoted deployment/write authority")
			}
			for _, check := range report.Checks {
				for _, o := range check.Observations {
					if o.Name == "opensearch_index_access" && o.Status == "pass" {
						t.Fatal("operator metadata proved required index operations")
					}
				}
			}
			b, _ := json.Marshal(report)
			if strings.Contains(string(b), "provider-secret") || strings.Contains(string(b), c.OpenSearch.Endpoint) {
				t.Fatal("raw provider or endpoint reflected")
			}
		})
	}
}
