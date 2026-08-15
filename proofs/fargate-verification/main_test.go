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
		"AWS_M018_ISOLATED_TEST":            "I_UNDERSTAND_THIS_MUTATES_A_DISPOSABLE_EKS_PROFILE",
		"AWS_M018_KUBECONFIG":               "/owned/kubeconfig",
		"AWS_M018_KUBE_CONTEXT":             "proof-context",
		"AWS_M018_CLUSTER_NAME":             "proof-cluster",
		"AWS_M018_REGION":                   "us-west-2",
		"AWS_M018_FARGATE_PROFILE":          "proof-profile",
		"AWS_M018_PROFILE_NAMESPACE_PREFIX": NamespacePrefix,
		"AWS_M018_PROFILE_LABEL_KEY":        ProfileSelectorLabelKey,
		"AWS_M018_PROFILE_LABEL_VALUE":      ProfileSelectorLabelValue,
		"AWS_M018_PROXY_URL":                "https://proxy.example.test/canary",
		"AWS_M018_CANARY_TOKEN":             "synthetic-token",
		"ZASP_M018_KUBECTL_EXECUTABLE":      "/owned/kubectl",
	}
}

func lookupMain(values map[string]string) environmentLookup {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestExecuteMainCapabilityGatePrecedesBoundaryConstruction(t *testing.T) {
	environment := validMainEnvironment()
	factoryCalls := 0
	factory := func(KubectlBoundaryOptions) (ClusterBoundary, error) {
		factoryCalls++
		return newHappyCluster(), nil
	}
	for _, name := range requiredMainEnvironment {
		copy := make(map[string]string, len(environment))
		for key, value := range environment {
			copy[key] = value
		}
		delete(copy, name)
		code, line := executeMain([]string{"proof"}, lookupMain(copy), strings.NewReader(strings.Repeat("\x00", 16)), factory)
		if code != 1 || line != "EKS Fargate proof failed: configuration rejected." {
			t.Fatalf("missing %s => (%d,%q)", name, code, line)
		}
	}
	if factoryCalls != 0 {
		t.Fatalf("factory calls before complete gate=%d", factoryCalls)
	}
	bad := validMainEnvironment()
	bad["AWS_M018_ISOLATED_TEST"] = "true"
	code, line := executeMain([]string{"proof"}, lookupMain(bad), strings.NewReader(strings.Repeat("\x00", 16)), factory)
	if code != 1 || line != "EKS Fargate proof failed: configuration rejected." || factoryCalls != 0 {
		t.Fatalf("attestation => (%d,%q,calls=%d)", code, line, factoryCalls)
	}
}

func TestExecuteMainRunsExactProofAndReturnsFixedLine(t *testing.T) {
	var captured KubectlBoundaryOptions
	code, line := executeMain(
		[]string{"proof"}, lookupMain(validMainEnvironment()), strings.NewReader(strings.Repeat("\x00", 16)),
		func(options KubectlBoundaryOptions) (ClusterBoundary, error) {
			captured = options
			return newHappyCluster(), nil
		},
	)
	if code != 0 || line != proofSuccessLine {
		t.Fatalf("executeMain=(%d,%q)", code, line)
	}
	if captured.Executable != "/owned/kubectl" || captured.KubeconfigPath != "/owned/kubeconfig" || captured.Context != "proof-context" || captured.ClusterName != "proof-cluster" {
		t.Fatalf("captured boundary=%#v", captured)
	}
}

func TestExecuteMainContainsFailuresAndMapsOnlyFixedCategories(t *testing.T) {
	tests := []struct {
		name    string
		random  io.Reader
		factory boundaryFactory
		want    string
	}{
		{name: "random", random: failingReader{}, factory: defaultBoundaryFactory, want: "configuration"},
		{name: "factory", random: strings.NewReader(strings.Repeat("\x00", 16)), factory: func(KubectlBoundaryOptions) (ClusterBoundary, error) { return nil, errors.New("sensitive") }, want: "configuration"},
		{name: "panic", random: strings.NewReader(strings.Repeat("\x00", 16)), factory: func(KubectlBoundaryOptions) (ClusterBoundary, error) { panic("sensitive") }, want: "panic"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, line := executeMain([]string{"proof"}, lookupMain(validMainEnvironment()), test.random, test.factory)
			if code != 1 || line != "EKS Fargate proof failed: "+test.want+" rejected." || strings.Contains(line, "sensitive") {
				t.Fatalf("executeMain=(%d,%q)", code, line)
			}
		})
	}
	for err, category := range map[error]string{
		ErrConfiguration: "configuration", ErrProvider: "provider", ErrScheduling: "scheduling", ErrCanary: "canary",
		ErrOwnership: "ownership", ErrCleanup: "cleanup", ErrDeadline: "deadline", ErrPanic: "panic",
	} {
		if got := fixedCategory(err); got != category {
			t.Fatalf("fixedCategory(%v)=%q want=%q", err, got, category)
		}
	}
}

func TestProofTimeoutsFitFifteenMinuteContract(t *testing.T) {
	if proofMainTimeout != 10*time.Minute || proofCleanupTimeout != 5*time.Minute || proofOverallTimeout != 15*time.Minute {
		t.Fatalf("timeouts main=%s cleanup=%s overall=%s", proofMainTimeout, proofCleanupTimeout, proofOverallTimeout)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("random unavailable") }
