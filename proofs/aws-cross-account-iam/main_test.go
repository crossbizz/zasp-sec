package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestExecuteMainUsesFixedOutputAndRequiresCompleteCapability(t *testing.T) {
	marker := "0000000000000000"
	environment := validMainEnvironment()
	factoryCalls := 0
	factory := func(sdkBoundaryConfig) (closeableIAMBoundary, error) {
		factoryCalls++
		return &closeableFakeBoundary{fakeIAMBoundary: newFakeIAMBoundary(marker)}, nil
	}
	for name := range environment {
		copy := cloneEnvironment(environment)
		delete(copy, name)
		code, line := executeMain([]string{"proof"}, lookupMap(copy), strings.NewReader(strings.Repeat("\x00", 8)), factory)
		if code != 1 || line != "Real AWS IAM proof failed: configuration rejected." {
			t.Fatalf("missing input produced (%d, %q)", code, line)
		}
	}
	if factoryCalls != 0 {
		t.Fatal("SDK boundary constructed before complete capability gate")
	}
	badAttestation := cloneEnvironment(environment)
	badAttestation["AWS_M009_ISOLATED_TEST"] = "true"
	code, line := executeMain([]string{"proof"}, lookupMap(badAttestation), strings.NewReader(strings.Repeat("\x00", 8)), factory)
	if code != 1 || line != "Real AWS IAM proof failed: capability rejected." || factoryCalls != 0 {
		t.Fatalf("attestation gate = (%d, %q, calls=%d)", code, line, factoryCalls)
	}
}

func TestProofTimeoutBudgetLeavesSupervisorCleanupMargin(t *testing.T) {
	if proofMainTimeout != 90*time.Second || proofCleanupTimeout != 30*time.Second {
		t.Fatal("Go proof lifetime changed without supervisor contract review")
	}
}

func TestExecuteMainContainsRandomFactoryAndPanicFailures(t *testing.T) {
	environment := validMainEnvironment()
	tests := []struct {
		name    string
		random  io.Reader
		factory sdkBoundaryFactory
		line    string
	}{
		{name: "random", random: errReader{}, factory: defaultSDKBoundaryFactory, line: "Real AWS IAM proof failed: configuration rejected."},
		{name: "factory", random: strings.NewReader(strings.Repeat("\x00", 8)), factory: func(sdkBoundaryConfig) (closeableIAMBoundary, error) { return nil, errors.New("provider detail") }, line: "Real AWS IAM proof failed: configuration rejected."},
		{name: "panic", random: strings.NewReader(strings.Repeat("\x00", 8)), factory: func(sdkBoundaryConfig) (closeableIAMBoundary, error) { panic("provider detail") }, line: "Real AWS IAM proof failed: operation rejected."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, line := executeMain([]string{"proof"}, lookupMap(environment), test.random, test.factory)
			if code != 1 || line != test.line || strings.Contains(line, "provider detail") {
				t.Fatalf("executeMain = (%d, %q)", code, line)
			}
		})
	}
}

func TestExecuteMainReturnsOnlyFixedSuccessForExactProof(t *testing.T) {
	marker := "0000000000000000"
	fake := &closeableFakeBoundary{fakeIAMBoundary: newFakeIAMBoundary(marker)}
	code, line := executeMain(
		[]string{"proof"}, lookupMap(validMainEnvironment()), strings.NewReader(strings.Repeat("\x00", 8)),
		func(sdkBoundaryConfig) (closeableIAMBoundary, error) { return fake, nil },
	)
	if code != 0 || line != proofSuccessLine || !fake.closed {
		t.Fatalf("executeMain = (%d, %q, closed=%t)", code, line, fake.closed)
	}
}

func TestFixedCategoryDoesNotExposeProviderErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{errConfiguration, "configuration"}, {errCapability, "capability"}, {errAuthentication, "authentication"},
		{errAuthorization, "authorization"}, {errOwnership, "ownership"}, {errCleanup, "cleanup"},
		{errors.New("sensitive provider detail"), "operation"},
	} {
		if got := fixedCategory(test.err); got != test.want {
			t.Fatalf("fixedCategory(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("random unavailable") }

type closeableFakeBoundary struct {
	*fakeIAMBoundary
	closed bool
}

func (f *closeableFakeBoundary) Close() { f.closed = true }

func validMainEnvironment() map[string]string {
	return map[string]string{
		"AWS_M009_ISOLATED_TEST":                  isolatedTestAttestation,
		"AWS_M009_REGION":                         "us-west-2",
		"AWS_M009_SOURCE_ACCOUNT_ID":              "111111111111",
		"AWS_M009_TARGET_ACCOUNT_ID":              "222222222222",
		"AWS_M009_SOURCE_PRINCIPAL_ARN":           "arn:aws:iam::111111111111:role/zasp-proof-source",
		"AWS_M009_SOURCE_ACCESS_KEY_ID":           "source-access",
		"AWS_M009_SOURCE_SECRET_ACCESS_KEY":       "source-secret",
		"AWS_M009_TARGET_ADMIN_ACCESS_KEY_ID":     "target-access",
		"AWS_M009_TARGET_ADMIN_SECRET_ACCESS_KEY": "target-secret",
	}
}

func lookupMap(values map[string]string) environmentLookup {
	return func(name string) (string, bool) {
		value, exists := values[name]
		return value, exists
	}
}

func cloneEnvironment(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
