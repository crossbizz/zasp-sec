package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func validMainEnvironment() map[string]string {
	return map[string]string{
		"AWS_M019_ISOLATED_TEST": "I_UNDERSTAND_THIS_APPLIES_A_DISPOSABLE_EKS_EGRESS_POLICY",
		"AWS_M019_KUBECONFIG":    "/owned/kubeconfig", "AWS_M019_KUBE_CONTEXT": "proof-context",
		"AWS_M019_CLUSTER_NAME": "proof-cluster", "AWS_M019_REGION": "us-west-2",
		"AWS_M019_FARGATE_PROFILE": "proof-profile", "AWS_M019_PROFILE_NAMESPACE_PREFIX": NamespacePrefix,
		"AWS_M019_PROFILE_LABEL_KEY": ProfileSelectorLabelKey, "AWS_M019_PROFILE_LABEL_VALUE": ProfileSelectorLabelValue,
		"AWS_M019_PROXY_URL": "https://proxy.example.test/canary", "AWS_M019_DIRECT_URL": "https://undeclared.example.test/canary",
		"AWS_M019_CANARY_TOKEN": "synthetic-token", "AWS_M019_POD_SECURITY_GROUP_ID": "sg-0123456789abcdef0",
		"AWS_M019_CLUSTER_SECURITY_GROUP_ID": "sg-11111111111111111", "AWS_M019_PROXY_SECURITY_GROUP_ID": "sg-22222222222222222",
		"AWS_M019_VPC_ID": "vpc-0123456789abcdef0", "AWS_M019_DNS_CIDR": "10.0.0.2/32",
		"AWS_M019_ACCESS_KEY_ID": "ABCDEFGHIJKLMNOPQRST", "AWS_M019_SECRET_ACCESS_KEY": "synthetic-secret-value",
		"ZASP_M019_KUBECTL_EXECUTABLE": "/owned/kubectl",
	}
}

func lookupMain(values map[string]string) environmentLookup {
	return func(name string) (string, bool) { value, ok := values[name]; return value, ok }
}

func TestExecuteMainGatesEveryAuthorityBeforeConstruction(t *testing.T) {
	environment := validMainEnvironment()
	calls := 0
	factory := func(KubectlBoundaryOptions, RealEC2Options) (ClusterBoundary, EC2Boundary, error) {
		calls++
		cluster, ec2, _ := happyProof()
		return cluster, ec2, nil
	}
	for _, name := range requiredMainEnvironment {
		copy := cloneMap(environment)
		delete(copy, name)
		code, line := executeMain([]string{"proof"}, lookupMain(copy), strings.NewReader(strings.Repeat("\x00", 16)), factory)
		if code != 1 || line != "EKS Fargate egress proof failed: configuration rejected." {
			t.Fatalf("missing %s=(%d,%q)", name, code, line)
		}
	}
	if calls != 0 {
		t.Fatalf("factory calls=%d", calls)
	}
}

func TestExecuteMainRunsExactProofAndReturnsFixedLine(t *testing.T) {
	var capturedCluster *fakeCluster
	code, line := executeMain([]string{"proof"}, lookupMain(validMainEnvironment()), strings.NewReader(strings.Repeat("\x00", 16)),
		func(KubectlBoundaryOptions, RealEC2Options) (ClusterBoundary, EC2Boundary, error) {
			cluster, ec2, _ := happyProof()
			capturedCluster = cluster
			return cluster, ec2, nil
		})
	if code != 0 || line != proofSuccessLine {
		t.Fatalf("result=(%d,%q) created=%v deleted=%v objects=%v", code, line, capturedCluster.created, capturedCluster.deleted, capturedCluster.objects)
	}
}

func TestExecuteMainContainsFailuresAndTimeoutsFitContract(t *testing.T) {
	code, line := executeMain([]string{"proof"}, lookupMain(validMainEnvironment()), failingReader{}, defaultBoundaryFactory)
	if code != 1 || line != "EKS Fargate egress proof failed: configuration rejected." {
		t.Fatalf("result=(%d,%q)", code, line)
	}
	if proofMainTimeout != 10*time.Minute || proofCleanupTimeout != 5*time.Minute || proofOverallTimeout != 15*time.Minute {
		t.Fatal("timeout contract")
	}
	for err, category := range map[error]string{ErrConfiguration: "configuration", ErrProvider: "provider", ErrScheduling: "scheduling", ErrCanary: "canary", ErrOwnership: "ownership", ErrCleanup: "cleanup", ErrDeadline: "deadline", ErrPanic: "panic"} {
		if fixedCategory(err) != category {
			t.Fatalf("category %v", err)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("random unavailable") }

var _ io.Reader = failingReader{}
