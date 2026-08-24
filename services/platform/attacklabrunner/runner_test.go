package attacklabrunner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/attacklabproxy"
)

func TestRunnerCallsExactProxyAndReturnsTenantBoundCanaryOutcome(t *testing.T) {
	digest := sha256.Sum256([]byte("attack-lab-input"))
	config := Config{
		OrganizationID: "pid_7d100010-0000-4000-8000-000000000010", WorkspaceID: "pid_7d100011-0000-4000-8000-000000000011", EnvironmentID: "pid_7d100012-0000-4000-8000-000000000012",
		RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example", SuccessCriterion: "Observe exact canary touch", ExpectedSideEffects: []string{"one bounded canary mutation"}, InputDigest: hex.EncodeToString(digest[:]),
		ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", EgressToken: "signed.capability.production", Timeout: 30 * time.Second,
	}
	canary := `{"schema_version":"attack-lab-canary-v1","organization_id":"` + config.OrganizationID + `","workspace_id":"` + config.WorkspaceID + `","environment_id":"` + config.EnvironmentID + `","run_id":"` + config.RunID + `","input_digest":"` + config.InputDigest + `","criterion_observed":true,"canary_touched":true,"evidence":"cloud canary changed once"}`
	proxyBody := `{"status_code":200,"content_type":"application/json","body_base64":"` + base64.RawURLEncoding.EncodeToString([]byte(canary)) + `"}`
	client := &recordingRunnerClient{response: &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(proxyBody))}}
	runner, err := New(config, client)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.CriterionObserved || !outcome.CanaryTouched || outcome.GatewayEvidence != "proxy authorized the exact run and destination" || outcome.EgressEvidence != "one HTTPS POST reached adapter.customer.example" || outcome.CloudEvidence != "cloud canary changed once" || len(client.requests) != 1 {
		t.Fatalf("outcome=%#v requests=%d", outcome, len(client.requests))
	}
	request := client.requests[0]
	if request.URL.String() != config.ProxyEndpoint || request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer "+config.EgressToken || request.Header.Get("Content-Type") != "application/json" {
		t.Fatal("proxy request authority drifted")
	}
	var envelope attacklabproxy.Request
	if !decodeExactRunnerJSON(client.bodies[0], &envelope) || envelope.Path != "/v1/attack-lab/canary" || envelope.ContentType != "application/json" {
		t.Fatal("proxy envelope drifted")
	}
	body, err := base64.RawURLEncoding.DecodeString(envelope.BodyBase64)
	if err != nil {
		t.Fatal(err)
	}
	var forwarded canaryRequest
	if !decodeExactRunnerJSON(body, &forwarded) || forwarded.RunID != config.RunID || forwarded.InputDigest != config.InputDigest || forwarded.Destination != config.Destination {
		t.Fatal("canary request drifted")
	}
}

type recordingRunnerClient struct {
	response *http.Response
	requests []*http.Request
	bodies   [][]byte
}

func (client *recordingRunnerClient) Do(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	client.requests = append(client.requests, request)
	client.bodies = append(client.bodies, body)
	client.response.Request = request
	return client.response, nil
}
