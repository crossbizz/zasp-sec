package main

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func TestProductionAttackLabProviderCreatesCollectsAndDestroysExactOwnedJob(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	request := productionAttackLabSandboxFixture(t, now)
	cluster := &recordingAttackLabCluster{uid: "123e4567-e89b-12d3-a456-426614174000", outcome: attackLabClusterOutcome{
		CriterionObserved: true, CanaryTouched: true, GatewayEvidence: "allowed", EgressEvidence: "adapter.customer.example", KubernetesEvidence: "fargate job complete", CloudEvidence: "canary touched",
	}}
	provider, err := newProductionAttackLabKubernetesProvider(productionAttackLabKubernetesProviderConfig{
		Cluster: cluster, Namespace: "zasp-attack-lab", ServiceAccount: "agentsec-attack-lab-runner",
		RunnerImage:   "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64),
		ProxyEndpoint: "https://agentsec-attack-lab-proxy.zasp.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt",
		SigningKey: []byte("test-only-attack-lab-signing-key-32"), OperationTimeout: 10 * time.Second, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := provider.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if sandbox.Reference != "k8s://attack-lab/jobs/zasp-attack-lab-7e300001000040008000000000000001@123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("sandbox=%#v", sandbox)
	}
	job := cluster.created
	if job.Namespace != "zasp-attack-lab" || job.Name != "zasp-attack-lab-7e300001000040008000000000000001" || job.ServiceAccount != "agentsec-attack-lab-runner" || job.Image != provider.config.RunnerImage || job.ActiveDeadlineSeconds != 300 || job.Limits != request.Run.Limits || job.Labels["zasp.io/execution"] != "attack-lab" || job.Labels["zasp.io/run-id"] != request.Run.ID || job.AllowsDirectEgress {
		t.Fatal("sandbox job authority drifted")
	}
	if err := verifyAttackLabEgressToken(provider.config.SigningKey, job.EgressToken, request.Scope, request.Run.ID, request.Run.Destination, "POST", now.Add(time.Minute)); err != nil {
		t.Fatalf("token verification=%v", err)
	}
	result, err := provider.Collect(context.Background(), request, sandbox)
	if err != nil || result.Verdict != "verified" || !result.CriterionObserved || !result.CanaryTouched || len(result.Evidence) != 5 || result.Evidence[3] != "kubernetes:fargate job complete" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if err := provider.Destroy(context.Background(), sandbox); err != nil {
		t.Fatal(err)
	}
	if cluster.destroyedName != job.Name || cluster.destroyedUID != cluster.uid {
		t.Fatalf("destroyed=%s@%s", cluster.destroyedName, cluster.destroyedUID)
	}
}

func TestProductionAttackLabProviderRejectsProductionDriftBeforeClusterIO(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	request := productionAttackLabSandboxFixture(t, now)
	request.Run.Environment = "production"
	request.Preflight.Environment = "production"
	cluster := &recordingAttackLabCluster{}
	provider, err := newProductionAttackLabKubernetesProvider(productionAttackLabKubernetesProviderConfig{
		Cluster: cluster, Namespace: "zasp-attack-lab", ServiceAccount: "agentsec-attack-lab-runner",
		RunnerImage:   "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64),
		ProxyEndpoint: "https://agentsec-attack-lab-proxy.zasp.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt",
		SigningKey: []byte("test-only-attack-lab-signing-key-32"), OperationTimeout: 10 * time.Second, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Create(context.Background(), request); err == nil {
		t.Fatal("production target accepted")
	}
	if cluster.createCalls != 0 {
		t.Fatalf("cluster calls=%d", cluster.createCalls)
	}
}

func productionAttackLabSandboxFixture(t *testing.T, now time.Time) attackLabSandboxRequest {
	t.Helper()
	scope := fixtureAttackLabOutboxScope(t)
	digest := sha256.Sum256([]byte("attack-lab-kubernetes-provider"))
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{
		ID: "pid_7e300001-0000-4000-8000-000000000001", Version: 3, SourceRunID: "pid_7e300002-0000-4000-8000-000000000002", DefinitionID: "pid_7e300003-0000-4000-8000-000000000003", DefinitionVersion: 2,
		TargetID: "pid_7e300004-0000-4000-8000-000000000004", TargetKind: "agent_endpoint", Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", Status: "leased", Attempt: 1, CleanupState: "pending",
		Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-time.Minute), StartedAt: &started,
	}
	preflight := apiserver.AttackLabPreflightSnapshot{Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", AllowedDestinations: []string{"adapter.customer.example"}, SuccessCriterion: "Observe the exact isolated canary touch", ExpectedSideEffects: []string{"one bounded test canary mutation"}}
	return attackLabSandboxRequest{Scope: scope, Run: run, Preflight: preflight, InputDigest: digest}
}

type recordingAttackLabCluster struct {
	uid                         string
	outcome                     attackLabClusterOutcome
	created                     attackLabKubernetesJob
	createCalls                 int
	destroyedName, destroyedUID string
}

func (*recordingAttackLabCluster) Ready(context.Context) error { return nil }

func (cluster *recordingAttackLabCluster) Create(_ context.Context, job attackLabKubernetesJob) (string, error) {
	cluster.createCalls++
	cluster.created = job
	return cluster.uid, nil
}

func (cluster *recordingAttackLabCluster) Collect(context.Context, string, string, string, time.Duration) (attackLabClusterOutcome, error) {
	return cluster.outcome, nil
}

func (cluster *recordingAttackLabCluster) Destroy(_ context.Context, _ string, name, uid string) error {
	cluster.destroyedName, cluster.destroyedUID = name, uid
	return nil
}
