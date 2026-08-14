package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	isolatedTestAttestation = "isolated-disposable-aws-test-accounts-only"
	proofSuccessLine        = "Real AWS IAM proof passed: cross_account=true assumed=true allowed_read=true denied_call=true cleanup=true audit=true."
)

type environmentLookup func(string) (string, bool)
type closeableIAMBoundary interface {
	IAMProofBoundary
	Close()
}
type sdkBoundaryFactory func(sdkBoundaryConfig) (closeableIAMBoundary, error)

func main() {
	code, line := executeMain(os.Args, os.LookupEnv, rand.Reader, defaultSDKBoundaryFactory)
	if code == 0 {
		fmt.Fprintln(os.Stdout, line)
	} else {
		fmt.Fprintln(os.Stderr, line)
	}
	os.Exit(code)
}

func executeMain(arguments []string, lookup environmentLookup, random io.Reader, factory sdkBoundaryFactory) (code int, line string) {
	code, line = failureLine("operation")
	defer func() {
		if recover() != nil {
			code, line = failureLine("operation")
		}
	}()
	if len(arguments) != 1 || lookup == nil || random == nil || factory == nil {
		return failureLine("configuration")
	}
	values := map[string]string{}
	for _, name := range []string{
		"AWS_M009_ISOLATED_TEST", "AWS_M009_REGION", "AWS_M009_SOURCE_ACCOUNT_ID", "AWS_M009_TARGET_ACCOUNT_ID",
		"AWS_M009_SOURCE_PRINCIPAL_ARN", "AWS_M009_SOURCE_ACCESS_KEY_ID", "AWS_M009_SOURCE_SECRET_ACCESS_KEY",
		"AWS_M009_TARGET_ADMIN_ACCESS_KEY_ID", "AWS_M009_TARGET_ADMIN_SECRET_ACCESS_KEY",
	} {
		value, exists := lookup(name)
		if !exists || value == "" {
			return failureLine("configuration")
		}
		values[name] = value
	}
	for _, name := range []string{"AWS_M009_SOURCE_SESSION_TOKEN", "AWS_M009_TARGET_ADMIN_SESSION_TOKEN"} {
		if value, exists := lookup(name); exists {
			values[name] = value
		}
	}
	if values["AWS_M009_ISOLATED_TEST"] != isolatedTestAttestation {
		return failureLine("capability")
	}
	markerBytes := make([]byte, 8)
	if _, err := io.ReadFull(random, markerBytes); err != nil {
		return failureLine("configuration")
	}
	marker := hex.EncodeToString(markerBytes)
	boundary, err := factory(sdkBoundaryConfig{
		region: values["AWS_M009_REGION"],
		source: explicitCredentialSet{
			accessKeyID: values["AWS_M009_SOURCE_ACCESS_KEY_ID"], secretAccessKey: values["AWS_M009_SOURCE_SECRET_ACCESS_KEY"],
			sessionToken: values["AWS_M009_SOURCE_SESSION_TOKEN"],
		},
		targetAdmin: explicitCredentialSet{
			accessKeyID: values["AWS_M009_TARGET_ADMIN_ACCESS_KEY_ID"], secretAccessKey: values["AWS_M009_TARGET_ADMIN_SECRET_ACCESS_KEY"],
			sessionToken: values["AWS_M009_TARGET_ADMIN_SESSION_TOKEN"],
		},
	})
	if err != nil || boundary == nil {
		return failureLine("configuration")
	}
	defer boundary.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := RunProof(ctx, ProofOptions{
		Marker: marker, Region: values["AWS_M009_REGION"],
		SourceAccountID: values["AWS_M009_SOURCE_ACCOUNT_ID"], TargetAccountID: values["AWS_M009_TARGET_ACCOUNT_ID"],
		SourcePrincipalARN: values["AWS_M009_SOURCE_PRINCIPAL_ARN"], Boundary: boundary,
		CleanupTimeout: 30 * time.Second, PollInterval: 250 * time.Millisecond,
	})
	if err != nil {
		return failureLine(fixedCategory(err))
	}
	want := ProofResult{CrossAccount: true, Assumed: true, AllowedRead: true, DeniedCall: true, Cleanup: true, Audit: true}
	if result != want {
		return failureLine("operation")
	}
	return 0, proofSuccessLine
}

func fixedCategory(err error) string {
	switch {
	case errors.Is(err, errConfiguration):
		return "configuration"
	case errors.Is(err, errCapability):
		return "capability"
	case errors.Is(err, errAuthentication):
		return "authentication"
	case errors.Is(err, errAuthorization):
		return "authorization"
	case errors.Is(err, errOwnership):
		return "ownership"
	case errors.Is(err, errCleanup):
		return "cleanup"
	default:
		return "operation"
	}
}

func defaultSDKBoundaryFactory(config sdkBoundaryConfig) (closeableIAMBoundary, error) {
	return newSDKIAMBoundary(config)
}

func failureLine(category string) (int, string) {
	return 1, fmt.Sprintf("Real AWS IAM proof failed: %s rejected.", category)
}
