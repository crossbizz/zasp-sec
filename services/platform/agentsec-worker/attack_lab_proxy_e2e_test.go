package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklabproxy"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklabrunner"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type combinedAttackLabProxyResolver struct {
	repository *apiserver.AttackLabExecutionRepository
	calls      atomic.Int32
}

func (r *combinedAttackLabProxyResolver) Ready(ctx context.Context) error {
	return r.repository.Ready(ctx)
}
func (r *combinedAttackLabProxyResolver) ResolveAttackLabEgress(ctx context.Context, scope domain.Scope, run, destination string) (apiserver.AttackLabEgressAuthority, error) {
	r.calls.Add(1)
	return r.repository.ResolveAttackLabEgress(ctx, scope, run, destination)
}

// Only the downstream transport is a fixture. The production handler, signed
// worker grant, runner envelope and PostgreSQL principal/authority are real.
type combinedAttackLabTLSForwarder struct {
	server             *httptest.Server
	destination, runID string
	calls              atomic.Int32
}

func (f *combinedAttackLabTLSForwarder) Forward(ctx context.Context, input attacklabproxy.ForwardRequest) (attacklabproxy.ForwardResult, error) {
	if input.Destination != f.destination || input.RunID != f.runID || input.Method != "POST" || input.Path != "/v1/attack-lab/canary" || input.CredentialReference != "ref:red-team/target_e2e_0001" {
		return attacklabproxy.ForwardResult{}, errors.New("fixture downstream authority mismatch")
	}
	f.calls.Add(1)
	request, err := http.NewRequestWithContext(ctx, input.Method, f.server.URL+input.Path, bytes.NewReader(input.Body))
	if err != nil {
		return attacklabproxy.ForwardResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := f.server.Client().Do(request)
	if err != nil {
		return attacklabproxy.ForwardResult{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32<<10+1))
	if err != nil {
		return attacklabproxy.ForwardResult{}, err
	}
	return attacklabproxy.ForwardResult{StatusCode: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body}, nil
}

func proveCombinedAttackLabEgress(ctx context.Context, request attackLabSandboxRequest, repository *apiserver.AttackLabExecutionRepository) error {
	key := []byte("test-only-attack-lab-signing-key-32")
	defer clear(key)
	provider, err := newProductionAttackLabKubernetesProvider(productionAttackLabKubernetesProviderConfig{
		Cluster: &recordingAttackLabCluster{uid: "123e4567-e89b-12d3-a456-426614174000"}, Namespace: "zasp-attack-lab", ServiceAccount: "agentsec-attack-lab-runner", RunnerTestRoleARN: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test",
		RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", SigningKey: key, OperationTimeout: 10 * time.Second, Now: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return err
	}
	job, err := provider.jobForRequest(request)
	if err != nil {
		return err
	}
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		var input struct {
			Schema       string   `json:"schema_version"`
			Organization string   `json:"organization_id"`
			Workspace    string   `json:"workspace_id"`
			Environment  string   `json:"environment_id"`
			Run          string   `json:"run_id"`
			Destination  string   `json:"destination"`
			Digest       string   `json:"input_digest"`
			Criterion    string   `json:"success_criterion"`
			SideEffects  []string `json:"expected_side_effects"`
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10+1))
		decoder.DisallowUnknownFields()
		if r.Method != "POST" || r.URL.Path != "/v1/attack-lab/canary" || decoder.Decode(&input) != nil || input.Schema != "attack-lab-canary-request-v1" || input.Organization != job.OrganizationID || input.Workspace != job.WorkspaceID || input.Environment != job.EnvironmentID || input.Run != job.RunID || input.Destination != job.Destination || input.Digest != job.InputDigest || input.Criterion != job.SuccessCriterion {
			http.Error(w, "exact canary request required", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "attack-lab-canary-v1", "organization_id": job.OrganizationID, "workspace_id": job.WorkspaceID, "environment_id": job.EnvironmentID, "run_id": job.RunID, "input_digest": job.InputDigest, "criterion_observed": true, "canary_touched": true, "evidence": "controlled TLS canary observed exact run"})
	}))
	defer target.Close()
	forwarder := &combinedAttackLabTLSForwarder{server: target, destination: job.Destination, runID: job.RunID}
	resolver := &combinedAttackLabProxyResolver{repository: repository}
	handler, err := attacklabproxy.NewHandler(attacklabproxy.Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return time.Now().UTC() }}, resolver, forwarder)
	if err != nil {
		return err
	}
	defer handler.Close()
	proxy := httptest.NewTLSServer(handler)
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		return err
	}
	client := proxy.Client()
	client.Timeout = 5 * time.Second
	client.Transport = combinedE2EOpenRouterTransport{target: proxyURL, inner: client.Transport}
	base := attacklabrunner.Config{OrganizationID: job.OrganizationID, WorkspaceID: job.WorkspaceID, EnvironmentID: job.EnvironmentID, RunID: job.RunID, Destination: job.Destination, SuccessCriterion: job.SuccessCriterion, ExpectedSideEffects: job.ExpectedSideEffects, InputDigest: job.InputDigest, ProxyEndpoint: job.ProxyEndpoint, EgressToken: job.EgressToken, Timeout: 5 * time.Second}
	runner, err := attacklabrunner.New(base, client)
	if err != nil {
		return err
	}
	outcome, err := runner.Run(ctx)
	if err != nil || !outcome.CriterionObserved || !outcome.CanaryTouched || targetCalls.Load() != 1 || forwarder.calls.Load() != 1 {
		return errors.New("worker-issued capability failed durable TLS acceptance")
	}
	for _, mutation := range []string{"undeclared-host", "expired-token", "foreign-run"} {
		changed := request
		switch mutation {
		case "undeclared-host":
			changed.Run.Destination = "undeclared.customer.example"
		case "foreign-run":
			changed.Run.ID = "pid_7e300099-0000-4000-8000-000000000099"
		case "expired-token":
			started := time.Now().UTC().Add(-6 * time.Minute)
			changed.Run.AttemptStartedAt = &started
		}
		invalidJob, err := provider.jobForRequest(changed)
		if err != nil {
			return err
		}
		invalid := base
		invalid.EgressToken = invalidJob.EgressToken
		invalid.RunID = invalidJob.RunID
		invalid.Destination = invalidJob.Destination
		before := resolver.calls.Load()
		rejected, err := attacklabrunner.New(invalid, client)
		if err != nil {
			return err
		}
		if _, err := rejected.Run(ctx); err == nil || targetCalls.Load() != 1 || forwarder.calls.Load() != 1 {
			return errors.New("undeclared or expired capability reached downstream")
		}
		if mutation == "expired-token" && resolver.calls.Load() != before {
			return errors.New("expired token reached durable resolution")
		}
	}
	if base.InputDigest != hex.EncodeToString(request.InputDigest[:]) {
		return errors.New("worker capability input digest changed")
	}
	return nil
}
