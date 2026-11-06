package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type openSearchSelectedReader struct {
	*awsAuthorityFixtureReader
	workload openSearchWorkload
	err      error
}

func (r *openSearchSelectedReader) OpenSearchWorkload(context.Context, AWSSelectedWorkload, string) (openSearchWorkload, error) {
	return r.workload, r.err
}

type openSearchDataFlowTransport struct {
	base                             *openSearchDomainFlowTransport
	role, mode                       string
	schemas                          map[string]string
	dataCalls, selectedIdentityCalls int
}

func (tr *openSearchDataFlowTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.URL.Host, "sts.") && strings.Contains(r.Header.Get("Authorization"), "fixture-workload-key") {
		tr.selectedIdentityCalls++
		role := strings.TrimPrefix(tr.role, "arn:aws:iam::123456789012:role/")
		if tr.mode == "wrong current identity" {
			role = "foreign"
		}
		body := `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/` + role + `/actual-read</Arn><UserId>fixture</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/xml"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	}
	if r.URL.Host == strings.TrimPrefix(tr.base.domain.Endpoint, "https://") {
		tr.dataCalls++
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || !strings.Contains(r.Header.Get("Authorization"), "fixture-workload-key") {
			return nil, ErrRejected
		}
		if tr.mode == "denied schema" {
			return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"message":"private-provider-data"}`))}, nil
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(parts) < 2 {
			return nil, ErrRejected
		}
		index := parts[0]
		schema := tr.schemas[index]
		if schema == "" {
			return nil, ErrRejected
		}
		body := ""
		if parts[1] == "_mapping" {
			body = `{"` + index + `":` + schema + `}`
		} else {
			markerID := "_zasp_schema_v1"
			if index == "zasp-runtime-sessions-v1" {
				markerID = "_zasp_session_schema_v1"
			}
			if len(parts) != 3 || parts[1] != "_doc" || parts[2] != markerID {
				return nil, ErrRejected
			}
			hash := sha256.Sum256([]byte(schema))
			version := 1
			if tr.mode == "marker drift" {
				version = 99
			}
			b, _ := json.Marshal(map[string]any{"_index": index, "_id": markerID, "_version": 1, "_seq_no": 0, "_primary_term": 1, "found": true, "_source": map[string]any{"record_type": "schema_marker", "schema_version": version, "mapping_digest": "sha256:" + hex.EncodeToString(hash[:])}})
			body = string(b)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	}
	return tr.base.RoundTrip(r)
}
func openSearchCompiledSchemaFixture(t *testing.T, path, name string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("existing schema source fixture unavailable")
	}
	pattern := regexp.MustCompile(name + "\\s*=\\s*`([^`]+)`")
	m := pattern.FindSubmatch(b)
	if len(m) != 2 {
		t.Fatal("existing schema source fixture changed")
	}
	return string(m[1])
}
func TestOpenSearchSameInvocationIdentityAndActualSchemasStayNarrow(t *testing.T) {
	for _, mode := range []string{"exact selected reads", "missing exchange", "expired exchange", "unverified cluster", "unverified Pod", "expired domain", "wrong current identity", "wrong actual PodUID", "wrong actual stage", "denied schema", "marker drift", "typed Pod denied", "typed Pod malformed"} {
		t.Run(mode, func(t *testing.T) {
			c, base := openSearchDomainFlowConfig(t)
			authority, k, _ := awsAuthorityFixtureConfig(t)
			selected := AWSSelectedWorkload{Purpose: `aws_iam_role.runtime["index"]`, PodName: "preflight-pod", PodUID: "33333333-3333-4333-8333-333333333333"}
			authority.Selected = &selected
			c.AWSAuthority = authority
			c.Credentials = CredentialConfig{Kind: "workload_web_identity", ExpectedRoleARN: k.bindings[selected.Purpose], Namespace: "agentsec", ServiceAccount: "zasp-runtime-index", TokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"}
			base.delegate.roles = map[string]string{}
			base.delegate.subjects = k.subjects
			for _, role := range authority.Roles {
				base.delegate.roles[role.RoleARN[strings.LastIndex(role.RoleARN, "/")+1:]] = role.Purpose
			}
			tr := &openSearchDataFlowTransport{base: base, role: c.Credentials.ExpectedRoleARN, mode: mode, schemas: map[string]string{"zasp-runtime-events-v1": openSearchCompiledSchemaFixture(t, "../runtimeindex/opensearchdriver/schema.go", "indexSchemaJSON"), "zasp-runtime-sessions-v1": openSearchCompiledSchemaFixture(t, "../runtimeindex/opensearchdriver/session_index.go", "sessionIndexSchemaJSON")}}
			r := &Runner{config: c, http: &http.Client{Transport: tr}}
			report := initialReport(c, "installed")
			evidence := r.inspectAWSAuthority(context.Background(), &report, authority, k)
			credentials, proof, e := r.exchangeAWSWebIdentity(context.Background(), c.Credentials.ExpectedRoleARN, []byte(strings.Repeat("opaque_fixture_token_", 8)))
			if e != nil {
				t.Fatal("actual fixture STS exchange failed")
			}
			r.observeSelectedAWSBinding(context.Background(), &report, authority, evidence, proof, k)
			if !evidence.clusterVerified || !evidence.selectedExchangeVerified || !evidence.selectedSpecVerified {
				t.Fatal("original actual B2 invocation prerequisites missing")
			}
			domain := r.observeOpenSearchDomain(context.Background(), &report)
			if domain == nil {
				t.Fatal("actual domain prerequisite absent")
			}
			reader := &openSearchSelectedReader{awsAuthorityFixtureReader: k, workload: openSearchWorkload{Namespace: "agentsec", PodName: selected.PodName, PodUID: selected.PodUID, ServiceAccount: "zasp-runtime-index", Purpose: selected.Purpose, Container: c.OpenSearch.Container, Image: c.OpenSearch.Image, Env: map[string]string{"ZASP_WORKER_MODE": "runtime-index", "ZASP_RUNTIME_STAGE_VERSION": "runtime-index-v1", "ZASP_OPENSEARCH_ENDPOINT": c.OpenSearch.Endpoint, "ZASP_OPENSEARCH_INDEX": "zasp-runtime-events-v1", "ZASP_RUNTIME_SESSION_INDEX": "zasp-runtime-sessions-v1"}}}
			switch mode {
			case "missing exchange":
				proof = nil
			case "expired exchange":
				proof.expires = time.Now().Add(-time.Second)
			case "unverified cluster":
				evidence.clusterVerified = false
			case "unverified Pod":
				evidence.selectedSpecVerified = false
			case "expired domain":
				domain.observedAt = time.Now().Add(-31 * time.Second)
			case "wrong actual PodUID":
				reader.workload.PodUID = "44444444-4444-4444-8444-444444444444"
			case "typed Pod denied":
				reader.err = &awsKubernetesOutcomeError{outcome: "denied"}
			case "typed Pod malformed":
				reader.err = &awsKubernetesOutcomeError{outcome: "malformed"}
			case "wrong actual stage":
				reader.workload.Env["ZASP_RUNTIME_STAGE_VERSION"] = "runtime-index-unknown"
			}
			sdk := aws.Config{Region: c.Deployment.Region, HTTPClient: r.http, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return credentials, nil }), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
			r.observeOpenSearchSchemas(context.Background(), &report, sdk, evidence, proof, reader, domain)
			if mode == "exact selected reads" {
				if tr.dataCalls != 4 || tr.selectedIdentityCalls != 1 || len(report.OpenSearch.SchemaReadsObserved) != 2 {
					t.Fatal("same-invocation selected read flow not mounted through existing validators")
				}
			} else if mode != "denied schema" && mode != "marker drift" && tr.dataCalls != 0 {
				t.Fatal("missing authority reached data plane")
			}
			if (mode == "denied schema" || mode == "marker drift") && tr.dataCalls == 0 {
				t.Fatal("actual failed schema read not observed")
			}
			if report.OpenSearch.RequiredMutationPermissionsObserved || report.OpenSearch.GlobalDeploymentPhaseObserved || report.OpenSearch.WorkloadNetworkOriginObserved || report.Ready || report.ProductionEndToEndVerified {
				t.Fatal("narrow reads became write/global/deployed proof")
			}
			for _, check := range report.Checks {
				for _, o := range check.Observations {
					if o.Name == "opensearch_index_access" && o.Status == "pass" {
						t.Fatal("required unexercised operations passed")
					}
				}
			}
			if mode == "typed Pod denied" || mode == "typed Pod malformed" {
				expected := "denied"
				if mode == "typed Pod malformed" {
					expected = "malformed"
				}
				found := false
				for _, check := range report.Checks {
					for _, o := range check.Observations {
						for _, f := range o.Failures {
							if f.Operation == "kubernetes:GetSelectedOpenSearchPod" && f.Outcome == expected {
								found = true
							}
						}
					}
				}
				if !found {
					t.Fatal("typed actual selectedPod outcome lost before report")
				}
			}
			b, _ := json.Marshal(report)
			if strings.Contains(string(b), "private-provider") || strings.Contains(string(b), c.OpenSearch.Endpoint) {
				t.Fatal("raw provider/endpoint escaped")
			}
		})
	}
}
