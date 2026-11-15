package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	smithy "github.com/aws/smithy-go"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

// creationEvent is a CloudTrail create event as LookupEvents returns it: the
// record is a JSON string. The request parameters stand for everything the
// collector must not keep.
func creationEvent(at time.Time, identity map[string]any, response map[string]any, errorCode string) cloudtrailtypes.Event {
	record := map[string]any{"userIdentity": identity, "responseElements": response, "requestParameters": map[string]any{"instruction": "never-recorded-instruction", "environment": map[string]any{"variables": map[string]any{"TOKEN": "never-recorded-value"}}}}
	if errorCode != "" {
		record["errorCode"] = errorCode
	}
	body, _ := json.Marshal(record)
	return cloudtrailtypes.Event{CloudTrailEvent: aws.String(string(body)), EventTime: aws.Time(at)}
}

func TestCloudTrailCreatorsNameTheCallerOfTheCreateEvent(t *testing.T) {
	now := discoveryAgentTestClock()
	const (
		agentARN    = "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"
		runtimeARN  = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1"
		functionARN = "arn:aws:lambda:us-east-1:123456789012:function:bot"
	)
	sso := map[string]any{"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Developer_0123456789abcdef/dana.reyes@example.com"}
	pipeline := map[string]any{"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/ci-deployer/release-481"}
	user := map[string]any{"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/eli", "userName": "eli"}
	stub := &cloudTrailStub{events: map[string][]cloudtrailtypes.Event{
		"CreateAgent": {
			creationEvent(now.Add(-48*time.Hour), sso, map[string]any{"agent": map[string]any{"agentArn": agentARN}}, ""),
			// A failed call created nothing.
			creationEvent(now.Add(-24*time.Hour), user, map[string]any{"agent": map[string]any{"agentArn": agentARN}}, "AccessDenied"),
			// Another account's agent, the root user and an AWS service attribute nothing.
			creationEvent(now.Add(-24*time.Hour), user, map[string]any{"agent": map[string]any{"agentArn": "arn:aws:bedrock:us-east-1:999999999999:agent/OTHER"}}, ""),
			creationEvent(now.Add(-24*time.Hour), map[string]any{"type": "Root", "arn": "arn:aws:iam::123456789012:root"}, map[string]any{"agent": map[string]any{"agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/ROOTMADE"}}, ""),
			creationEvent(now.Add(-24*time.Hour), map[string]any{"type": "AWSService", "invokedBy": "cloudformation.amazonaws.com"}, map[string]any{"agent": map[string]any{"agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/SERVICEMADE"}}, ""),
			{CloudTrailEvent: aws.String("not json"), EventTime: aws.Time(now.Add(-time.Hour))},
			// An event outside the window, or without a time, is not read.
			creationEvent(now.Add(-100*24*time.Hour), user, map[string]any{"agent": map[string]any{"agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/TOOOLD"}}, ""),
		},
		"CreateAgentRuntime": {creationEvent(now.Add(-72*time.Hour), pipeline, map[string]any{"agentRuntimeArn": runtimeARN}, "")},
		"CreateFunction20150331": {
			// The function was deleted and created again: the newest wins.
			creationEvent(now.Add(-10*time.Hour), user, map[string]any{"functionArn": functionARN}, ""),
			creationEvent(now.Add(-30*24*time.Hour), pipeline, map[string]any{"functionArn": functionARN}, ""),
		},
	}}
	creators, err := collectDiscoveryAWSCreators(context.Background(), stub, "123456789012", now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]awsdiscovery.AgentInventoryCreator{
		agentARN:    {ARN: agentARN, CreatedAt: now.Add(-48 * time.Hour).UTC().Format(time.RFC3339), CreatedBy: "dana.reyes@example.com"},
		runtimeARN:  {ARN: runtimeARN, CreatedAt: now.Add(-72 * time.Hour).UTC().Format(time.RFC3339), CreatedBy: "ci-deployer/release-481"},
		functionARN: {ARN: functionARN, CreatedAt: now.Add(-10 * time.Hour).UTC().Format(time.RFC3339), CreatedBy: "eli"},
	}
	if len(creators) != len(want) {
		t.Fatalf("creators = %+v", creators)
	}
	for arn, expected := range want {
		if creators[arn] != expected {
			t.Fatalf("%s = %+v, want %+v", arn, creators[arn], expected)
		}
	}
	if len(stub.calls) != len(discoveryAWSCreationEvents) {
		t.Fatalf("asked for %v", stub.calls)
	}
	encoded, _ := json.Marshal(creators)
	if strings.Contains(string(encoded), "never-recorded") {
		t.Fatalf("a request parameter was kept: %s", encoded)
	}
	// A refusal or throttling yields nothing and is not an error; only a
	// cancelled read is.
	for name, failure := range map[string]error{"refused": &smithy.GenericAPIError{Code: "AccessDeniedException"}, "throttled": &smithy.GenericAPIError{Code: "ThrottlingException"}} {
		got, err := collectDiscoveryAWSCreators(context.Background(), &cloudTrailStub{err: failure}, "123456789012", now)
		if err != nil || len(got) != 0 {
			t.Fatalf("%s: creators %v, err %v", name, got, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := collectDiscoveryAWSCreators(cancelled, &cloudTrailStub{err: context.Canceled}, "123456789012", now); err == nil {
		t.Fatal("a cancelled read was not an error")
	}
}

// The whole agents read: the creator of a listed agent reaches the canonical
// source, and a create event of something the inventory does not list is
// dropped.
func TestAWSInventoryRecordsTheCreatorOfListedAgentsOnly(t *testing.T) {
	read := func(trail *cloudTrailStub) awsdiscovery.AgentInventorySource {
		t.Helper()
		factory := discoveryAgentFactory(discoveryAgentMixedAccount())
		factory.CloudTrail = func(region string, _ aws.Credentials) (discoveryAWSCloudTrailAPI, error) {
			if region == "us-east-1" {
				return trail, nil
			}
			return &cloudTrailStub{}, nil
		}
		factory.Clock = discoveryAgentTestClock
		caller, err := newDiscoveryAWSCollectionInventoryCaller(factory, discoveryAgentTestClock)
		if err != nil {
			t.Fatal(err)
		}
		credential := mustDiscoveryAWSCredentialEnvelope(t, discoveryAgentTestClock().Add(15*time.Minute))
		inventory, err := caller.GetCollectionInventory(context.Background(), credential)
		clear(credential)
		if err != nil {
			t.Fatalf("inventory: %v", err)
		}
		var source awsdiscovery.AgentInventorySource
		if err := json.Unmarshal(inventory.AgentSource, &source); err != nil {
			t.Fatal(err)
		}
		return source
	}
	listed := read(&cloudTrailStub{})
	if len(listed.Creators) != 0 || len(listed.BedrockAgents) == 0 {
		t.Fatalf("without create events: creators %+v, agents %d", listed.Creators, len(listed.BedrockAgents))
	}
	agentARN := listed.BedrockAgents[0].ARN
	at := discoveryAgentTestClock().Add(-36 * time.Hour)
	caller := map[string]any{"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Developer_0123456789abcdef/dana.reyes@example.com"}
	source := read(&cloudTrailStub{events: map[string][]cloudtrailtypes.Event{"CreateAgent": {
		creationEvent(at, caller, map[string]any{"agent": map[string]any{"agentArn": agentARN}}, ""),
		creationEvent(at, caller, map[string]any{"agent": map[string]any{"agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/DELETED999"}}, ""),
	}}})
	want := awsdiscovery.AgentInventoryCreator{ARN: agentARN, CreatedAt: at.UTC().Format(time.RFC3339), CreatedBy: "dana.reyes@example.com"}
	if len(source.Creators) != 1 || source.Creators[0] != want {
		t.Fatalf("creators = %+v, want %+v", source.Creators, want)
	}
}
