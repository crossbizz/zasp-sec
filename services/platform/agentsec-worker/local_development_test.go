package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
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
