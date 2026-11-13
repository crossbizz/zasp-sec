package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/localcloud"
)

// These tests pin the two worker behaviours that differ for a local cloud
// emulator, and show that without the emulator (production) nothing changes.

func localCloudSettings(t *testing.T, environment, endpoint string) localcloud.Settings {
	t.Helper()
	settings, _ := localcloud.Load(func(name string) string {
		switch name {
		case localcloud.EnvironmentVariable:
			return environment
		case localcloud.EndpointVariable:
			return endpoint
		}
		return ""
	})
	return settings
}

func TestHealthListenerMovesOnlyForLocalEmulator(t *testing.T) {
	t.Parallel()
	var opened string
	listen := func(_, address string) (net.Listener, error) {
		opened = address
		return nil, errors.New("not opened")
	}
	port := func(value string) func(string) string {
		return func(name string) string {
			if name == localHealthPortVariable {
				return value
			}
			return ""
		}
	}
	for _, test := range []struct {
		name, environment, endpoint, port, want string
	}{
		{"production without emulator ignores the port", "production", "", "18082", healthListenAddress},
		{"production with a refused emulator ignores the port", "production", "http://127.0.0.1:4566", "18082", healthListenAddress},
		{"unset environment ignores the port", "", "http://127.0.0.1:4566", "18082", healthListenAddress},
		{"development without emulator ignores the port", "development", "", "18082", healthListenAddress},
		{"emulator without a port keeps the fixed address", "development", "http://127.0.0.1:4566", "", healthListenAddress},
		{"emulator refuses a malformed port", "development", "http://127.0.0.1:4566", "0.0.0.0:18082", healthListenAddress},
		{"emulator refuses a privileged port", "test", "http://127.0.0.1:4566", "80", healthListenAddress},
		{"development emulator moves to loopback", "development", "http://127.0.0.1:4566", "18082", "127.0.0.1:18082"},
		{"test emulator moves to loopback", "test", "http://127.0.0.1:4566", "18083", "127.0.0.1:18083"},
	} {
		opened = ""
		_, _ = healthListener(localCloudSettings(t, test.environment, test.endpoint), port(test.port), listen)("tcp", healthListenAddress)
		if opened != test.want {
			t.Fatalf("%s: listened on %q, want %q", test.name, opened, test.want)
		}
	}
	if healthListener(localCloudSettings(t, "development", "http://127.0.0.1:4566"), nil, listen) == nil {
		t.Fatal("a missing environment reader removed the listener")
	}
}

type regionListEC2Stub struct {
	regions   []ec2types.Region
	described *[]string
	region    string
}

func (stub *regionListEC2Stub) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	return &ec2.DescribeRegionsOutput{Regions: stub.regions}, nil
}

func (stub *regionListEC2Stub) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	*stub.described = append(*stub.described, stub.region)
	return &ec2.DescribeInstancesOutput{}, nil
}

func TestAWSInstanceCollectionSkipsUnavailableRegionsOnlyForLocalEmulator(t *testing.T) {
	t.Parallel()
	region := func(name, status string) ec2types.Region {
		return ec2types.Region{RegionName: aws.String(name), OptInStatus: aws.String(status)}
	}
	credentials := aws.Credentials{AccessKeyID: "ASIAABCDEFGHIJKLMNOP", SecretAccessKey: "secret", SessionToken: "token", CanExpire: true, Expires: time.Now().Add(time.Hour)}
	collect := func(regions []ec2types.Region, localEmulator bool) ([]string, error) {
		var described []string
		factory := func(name string, _ aws.Credentials) (discoveryAWSEC2API, error) {
			return &regionListEC2Stub{regions: regions, described: &described, region: name}, nil
		}
		primary, _ := factory("us-east-1", credentials)
		_, err := collectDiscoveryAWSInstances(context.Background(), factory, primary, credentials, "123456789012", localEmulator)
		return described, err
	}
	mixed := []ec2types.Region{region("us-east-1", "opt-in-not-required"), region("ap-east-1", "not-opted-in"), region("eu-west-1", "opted-in")}
	partitions := []ec2types.Region{region("us-east-1", "opt-in-not-required"), region("cn-north-1", "opt-in-not-required"), region("us-gov-east-1", "opt-in-not-required")}

	// Production reads every region AWS lists as enabled, whatever its name.
	if described, err := collect(partitions, false); err != nil || len(described) != 3 {
		t.Fatalf("production partition collection = %v, %v", described, err)
	}
	// Emulator: regions of other partitions are skipped and never read.
	if described, err := collect(partitions, true); err != nil || len(described) != 1 || described[0] != "us-east-1" {
		t.Fatalf("emulator partition collection = %v, %v", described, err)
	}

	// Production: AWS never lists a region that is not enabled when asked for
	// enabled regions only, so one in the answer refuses the whole collection.
	if described, err := collect(mixed, false); !errors.Is(err, awsdiscovery.ErrDenied) || len(described) != 0 {
		t.Fatalf("production collection = %v, %v; want refusal before any instance read", described, err)
	}
	// Emulator: the region is skipped and never read.
	described, err := collect(mixed, true)
	if err != nil || len(described) != 2 || described[0] != "eu-west-1" || described[1] != "us-east-1" {
		t.Fatalf("emulator collection = %v, %v", described, err)
	}
	// Every other malformed answer is refused for the emulator too.
	for name, regions := range map[string][]ec2types.Region{
		"unknown status":        {region("us-east-1", "opt-in-not-required"), region("eu-west-1", "disabled")},
		"malformed region name": {region("us-east-1", "opt-in-not-required"), region("not a region", "not-opted-in")},
		"no usable region":      {region("ap-east-1", "not-opted-in")},
		"missing opt-in status": {region("us-east-1", "")},
		"empty region list":     {},
	} {
		if described, err := collect(regions, true); !errors.Is(err, awsdiscovery.ErrDenied) || len(described) != 0 {
			t.Fatalf("%s: emulator collection = %v, %v; want refusal", name, described, err)
		}
	}
}

func TestUnclassifiedDiscoveryPageOutcome(t *testing.T) {
	t.Parallel()
	// A collector that was never built made no provider request.
	if outcome := unclassifiedDiscoveryPageOutcome(errWorkerExecution); outcome != "terminal" {
		t.Fatalf("unbuilt collector outcome = %q", outcome)
	}
	// After a collector exists the provider may have been reached.
	if outcome := unclassifiedDiscoveryPageOutcome(nil); outcome != "outcome_unknown" {
		t.Fatalf("built collector outcome = %q", outcome)
	}
}

func TestProviderDiscoveryCredentialExpiryIsWholeSecondsAndNeverLater(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	whole := now.Add(15 * time.Minute)
	if got := providerDiscoveryCredentialExpiry(now, whole); !got.Equal(whole.Add(-30 * time.Second)) {
		t.Fatalf("whole-second expiry = %s", got)
	}
	fractional := whole.Add(855 * time.Millisecond)
	got := providerDiscoveryCredentialExpiry(now, fractional)
	if got.Nanosecond() != 0 || !got.Equal(whole.Add(-30*time.Second)) || got.After(fractional.Add(-30*time.Second)) {
		t.Fatalf("fractional expiry = %s", got)
	}
	if got := providerDiscoveryCredentialExpiry(now, now.Add(30*time.Second+500*time.Millisecond)); !got.IsZero() {
		t.Fatalf("expiry inside the safety margin = %s", got)
	}
}

func TestAWSInventoryPageTimeoutIsWithinCollectorAndActivityBounds(t *testing.T) {
	t.Parallel()
	if discoveryAWSInventoryPageTimeout > awsdiscovery.MaximumInventoryPageTimeout || discoveryAWSInventoryPageTimeout >= 5*time.Minute || discoveryAWSInventoryPageTimeout < 30*time.Second {
		t.Fatalf("AWS inventory page timeout = %s", discoveryAWSInventoryPageTimeout)
	}
}

func TestRetryDiscoveryAuthorizationRepeatsOnlyWhileProjectionMoves(t *testing.T) {
	t.Parallel()
	sequence := func(results ...error) (func() (json.RawMessage, error), *int) {
		calls := 0
		return func() (json.RawMessage, error) {
			index := calls
			calls++
			if index >= len(results) {
				index = len(results) - 1
			}
			if results[index] != nil {
				return nil, results[index]
			}
			return json.RawMessage(`true`), nil
		}, &calls
	}
	// A moving projection is decided again until it settles.
	call, calls := sequence(authorization.ErrConflict, authorization.ErrPending, nil)
	if raw, err := retryDiscoveryAuthorization(context.Background(), time.Second, time.Millisecond, call); err != nil || string(raw) != "true" || *calls != 3 {
		t.Fatalf("settled projection = %s, %v after %d calls", raw, err, *calls)
	}
	// A denial and any other error are final on the first attempt.
	for _, final := range []error{authorization.ErrDenied, authorization.ErrInvalid, errWorkerExecution} {
		call, calls = sequence(final, nil)
		if _, err := retryDiscoveryAuthorization(context.Background(), time.Second, time.Millisecond, call); !errors.Is(err, final) || *calls != 1 {
			t.Fatalf("%v: result %v after %d calls", final, err, *calls)
		}
	}
	// A projection that never settles fails within the budget.
	call, calls = sequence(authorization.ErrConflict)
	started := time.Now()
	if _, err := retryDiscoveryAuthorization(context.Background(), 50*time.Millisecond, 5*time.Millisecond, call); !errors.Is(err, authorization.ErrConflict) || *calls < 2 || time.Since(started) > time.Second {
		t.Fatalf("unsettled projection = %v after %d calls in %s", err, *calls, time.Since(started))
	}
	// Cancellation stops the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	call, calls = sequence(authorization.ErrPending)
	if _, err := retryDiscoveryAuthorization(ctx, time.Minute, time.Second, call); !errors.Is(err, authorization.ErrPending) || *calls != 1 {
		t.Fatalf("cancelled wait = %v after %d calls", err, *calls)
	}
	if _, err := retryDiscoveryAuthorization(context.Background(), 0, time.Millisecond, call); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("zero budget = %v", err)
	}
}
