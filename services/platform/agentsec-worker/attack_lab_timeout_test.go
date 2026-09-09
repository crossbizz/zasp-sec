package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const attackLabTimeoutEvidence = "kubernetes:approved attempt deadline elapsed; sandbox cleanup required"

func TestAttackLabTimeoutEvidenceRequiresAuthoritativeJobDeadline(t *testing.T) {
	const name = "zasp-attack-lab-7e300001000040008000000000000001"
	const uid = "123e4567-e89b-12d3-a456-426614174000"
	for _, tc := range []struct {
		name, owner, conditions string
		timedOut                bool
	}{
		{"deadline", uid, `{"type":"Failed","status":"True","reason":"DeadlineExceeded","message":"private-provider-detail"}`, true},
		{"other failure", uid, `{"type":"Failed","status":"True","reason":"BackoffLimitExceeded","message":"private-provider-detail"}`, false},
		{"foreign job", "123e4567-e89b-12d3-a456-426614174001", `{"type":"Failed","status":"True","reason":"DeadlineExceeded"}`, false},
		{"contradictory completion", uid, `{"type":"Failed","status":"True","reason":"DeadlineExceeded"},{"type":"Complete","status":"True"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"apiVersion":"batch/v1","kind":"Job","metadata":{"namespace":"zasp-attack-lab","name":"` + name + `","uid":"` + tc.owner + `"},"status":{"failed":1,"conditions":[` + tc.conditions + `]}}`
			api := timeoutTestKubernetesAPI(t, &recordingAttackLabKubernetesTransport{responses: []*http.Response{attackLabKubernetesTestResponse(http.StatusOK, body)}})
			_, err := api.Collect(context.Background(), "zasp-attack-lab", name, uid, time.Second)
			assertAttackLabTimeoutEvidence(t, err, tc.timedOut)
		})
	}
}

func TestAttackLabTimeoutSeparatesAttemptBudgetFromTransportAndCallerDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		callerDeadline, transportTimeout bool
		timedOut                         bool
	}{
		{"attempt budget", false, false, true}, {"caller deadline", true, false, false}, {"HTTP timeout", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			budget := 30 * time.Millisecond
			if tc.callerDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
				budget = time.Second
			}
			api := timeoutTestKubernetesAPI(t, attackLabTimeoutTransport(func(request *http.Request) (*http.Response, error) {
				if tc.transportTimeout {
					return nil, context.DeadlineExceeded
				}
				<-request.Context().Done()
				return nil, request.Context().Err()
			}))
			started := time.Now()
			_, err := api.Collect(ctx, "zasp-attack-lab", "zasp-attack-lab-7e300001000040008000000000000001", "123e4567-e89b-12d3-a456-426614174000", budget)
			assertAttackLabTimeoutEvidence(t, err, tc.timedOut)
			if time.Since(started) > time.Second {
				t.Fatal("attempt collection was unbounded")
			}
		})
	}
}

func TestAttackLabCompletedJobEvidenceReadKeepsDeadlineClassification(t *testing.T) {
	const name = "zasp-attack-lab-7e300001000040008000000000000001"
	const uid = "123e4567-e89b-12d3-a456-426614174000"
	for _, tc := range []struct {
		name                                       string
		callerDeadline, transportTimeout, timedOut bool
	}{
		{"evidence exceeds attempt budget", false, false, true}, {"evidence caller deadline", true, false, false}, {"evidence HTTP timeout", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			budget := 30 * time.Millisecond
			if tc.callerDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
				budget = time.Second
			}
			calls := 0
			api := timeoutTestKubernetesAPI(t, attackLabTimeoutTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"namespace":"zasp-attack-lab","name":"`+name+`","uid":"`+uid+`"},"status":{"succeeded":1,"conditions":[{"type":"Complete","status":"True"}]}}`), nil
				}
				if request.URL.Path != "/api/v1/namespaces/zasp-attack-lab/pods" {
					t.Fatal("evidence request scope drifted")
				}
				if tc.transportTimeout {
					return nil, context.DeadlineExceeded
				}
				<-request.Context().Done()
				return nil, request.Context().Err()
			}))
			_, err := api.Collect(ctx, "zasp-attack-lab", name, uid, budget)
			assertAttackLabTimeoutEvidence(t, err, tc.timedOut)
			if calls != 2 {
				t.Fatal("completed Job never reached dependent evidence")
			}
		})
	}
}

func TestAttackLabResumedAttemptKeepsAbsoluteDeadline(t *testing.T) {
	now := time.Date(2026, 9, 9, 1, 0, 0, 0, time.UTC)
	request := productionAttackLabSandboxFixture(t, now)
	started := now.Add(-299500 * time.Millisecond)
	request.Run.StartedAt, request.Run.AttemptStartedAt = &started, &started
	cluster := &attackLabDeadlineCluster{recordingAttackLabCluster: &recordingAttackLabCluster{outcome: attackLabClusterOutcome{GatewayEvidence: "no result", EgressEvidence: "bounded", KubernetesEvidence: "completed", CloudEvidence: "unchanged"}}}
	provider, err := newProductionAttackLabKubernetesProvider(productionAttackLabKubernetesProviderConfig{Cluster: cluster, Namespace: "zasp-attack-lab", ServiceAccount: "agentsec-attack-lab-runner", RunnerTestRoleARN: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test", RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", SigningKey: []byte("test-only-attack-lab-signing-key-32"), OperationTimeout: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	name, _ := attackLabJobName(request.Scope, request.Run.ID)
	sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/" + name + "@123e4567-e89b-12d3-a456-426614174000"}
	if _, err := provider.Run(context.Background(), request, sandbox); err != nil || cluster.timeout != 500*time.Millisecond || cluster.calls != 1 {
		t.Fatalf("resumed deadline reset: timeout=%s calls=%d err=%v", cluster.timeout, cluster.calls, err)
	}
	cluster.afterCollect = func() { now = now.Add(time.Second) }
	_, err = provider.Run(context.Background(), request, sandbox)
	assertAttackLabTimeoutEvidence(t, err, true)
	if cluster.calls != 2 {
		t.Fatal("late success fixture did not execute")
	}
	_, err = provider.Run(context.Background(), request, sandbox)
	assertAttackLabTimeoutEvidence(t, err, true)
	if cluster.calls != 2 {
		t.Fatal("expired attempt invoked collection")
	}
}

func TestAttackLabTimeoutCheckpointsBoundedEvidenceBeforeCleanupAndResumes(t *testing.T) {
	now := time.Now().UTC()
	request := productionAttackLabSandboxFixture(t, now)
	request.Run.Status = "running"
	name, _ := attackLabJobName(request.Scope, request.Run.ID)
	const uid = "123e4567-e89b-12d3-a456-426614174000"
	sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/" + name + "@" + uid}
	job := `{"apiVersion":"batch/v1","kind":"Job","metadata":{"namespace":"zasp-attack-lab","name":"` + name + `","uid":"` + uid + `"}`
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
		attackLabKubernetesTestResponse(http.StatusOK, job+`,"status":{"failed":1,"conditions":[{"type":"Failed","status":"True","reason":"DeadlineExceeded","message":"private-provider-detail"}]}}`),
		attackLabKubernetesTestResponse(http.StatusOK, job+`}`),
		attackLabKubernetesTestResponse(http.StatusServiceUnavailable, `{"kind":"Status","reason":"Unavailable"}`),
	}}
	cluster := timeoutTestKubernetesAPI(t, transport)
	provider, err := newProductionAttackLabKubernetesProvider(productionAttackLabKubernetesProviderConfig{Cluster: cluster, Namespace: "zasp-attack-lab", ServiceAccount: "agentsec-attack-lab-runner", RunnerTestRoleARN: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test", RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", SigningKey: []byte("test-only-attack-lab-signing-key-32"), OperationTimeout: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, claim: apiserver.AttackLabRunClaim{Disposition: "running", Run: request.Run, Preflight: request.Preflight, InputDigest: request.InputDigest, SandboxReference: sandbox.Reference, LeaseExpiresAt: now.Add(time.Minute)}}
	runID := mustProductID(t, request.Run.ID)
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: request.Scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: request.InputDigest, Payload: attackLabQueuePayload(t, request.Scope, request.Run, request.InputDigest)}}}}
	key := mustAttackLabRuntimeEvidenceKey(t, request.Scope, request.Run.ID, 1)
	evidence := &recordingAttackLabEvidenceWriter{steps: &steps, artifact: attackLabEvidenceArtifact{Reference: "s3://zasp-attack-lab-evidence/" + key, Key: key, VersionID: "timeout-evidence-1", Checksum: bytes.Repeat([]byte{0xcc}, sha256.Size), SizeBytes: 512}}
	config := attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: &timeoutReadyProvider{productionAttackLabKubernetesProvider: provider, steps: &steps}, Evidence: evidence, WorkerID: "attack-lab-timeout-01", LeaseSeconds: 60, BatchSize: 1, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 32), nil }}
	processor, err := newAttackLabProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if processor.RunOnce(context.Background()) == nil || fmt.Sprint(steps) != "[consume claim run evidence begin-cleanup destroy]" {
		t.Fatalf("uncertain timeout cleanup finished early: %v", steps)
	}
	if authority.cleanup.ErrorCode != "outcome_unknown" || authority.cleanup.Verdict != "inconclusive" || len(authority.cleanup.Evidence) != 5 || authority.cleanup.Evidence[3] != attackLabTimeoutEvidence || evidence.result.Evidence[3] != attackLabTimeoutEvidence {
		t.Fatal("bounded deadline reason was not retained before cleanup")
	}
	steps = nil
	authority.claim.Disposition, authority.claim.Run.Status = "cleanup", "cleanup"
	authority.claim.Checkpoint = apiserver.AttackLabCleanupCheckpoint{Attempt: 1, SandboxReference: sandbox.Reference, ErrorCode: authority.cleanup.ErrorCode, Verdict: authority.cleanup.Verdict}
	transport.responses = []*http.Response{attackLabKubernetesTestResponse(http.StatusNotFound, `{"kind":"Status","reason":"NotFound"}`), attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"PodList","items":[]}`)}
	resumed, err := newAttackLabProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.RunOnce(context.Background()); err != nil || fmt.Sprint(steps) != "[consume claim destroy finish-cleanup ack]" {
		t.Fatalf("timeout restart re-executed or lost cleanup: err=%v steps=%v", err, steps)
	}
}

// Only cluster readiness is replaced here. Run and cleanup use the production
// Kubernetes HTTP implementation with bounded responses from the fixture.
type timeoutReadyProvider struct {
	*productionAttackLabKubernetesProvider
	steps *[]string
}

func (*timeoutReadyProvider) Ready(context.Context) error { return nil }
func (provider *timeoutReadyProvider) Run(ctx context.Context, request attackLabSandboxRequest, sandbox attackLabSandbox) (attackLabSandboxResult, error) {
	*provider.steps = append(*provider.steps, "run")
	return provider.productionAttackLabKubernetesProvider.Run(ctx, request, sandbox)
}
func (provider *timeoutReadyProvider) Destroy(ctx context.Context, sandbox attackLabSandbox) error {
	*provider.steps = append(*provider.steps, "destroy")
	return provider.productionAttackLabKubernetesProvider.Destroy(ctx, sandbox)
}

func assertAttackLabTimeoutEvidence(t *testing.T, err error, expected bool) {
	t.Helper()
	if err == nil {
		t.Fatal("missing evaluation failure")
	}
	result := failedAttackLabResult(err)
	if !validAttackLabSandboxResult(result) || result.Verdict != "inconclusive" || result.ErrorCode != "outcome_unknown" || (result.Evidence[3] == attackLabTimeoutEvidence) != expected || strings.Contains(strings.Join(result.Evidence, " "), "private-provider-detail") {
		t.Fatalf("deadline classification mismatch: expected=%v result=%#v", expected, result)
	}
}

func timeoutTestKubernetesAPI(t *testing.T, transport http.RoundTripper) *productionAttackLabKubernetesAPI {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
}

type attackLabTimeoutTransport func(*http.Request) (*http.Response, error)

func (transport attackLabTimeoutTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type attackLabDeadlineCluster struct {
	*recordingAttackLabCluster
	timeout      time.Duration
	calls        int
	afterCollect func()
}

func (cluster *attackLabDeadlineCluster) Collect(ctx context.Context, _, _, _ string, timeout time.Duration) (attackLabClusterOutcome, error) {
	if ctx.Err() != nil {
		return attackLabClusterOutcome{}, errors.New("caller unavailable")
	}
	cluster.timeout = timeout
	cluster.calls++
	if cluster.afterCollect != nil {
		cluster.afterCollect()
	}
	return cluster.outcome, nil
}
