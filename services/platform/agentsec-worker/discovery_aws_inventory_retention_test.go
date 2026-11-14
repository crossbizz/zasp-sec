package main

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func discoveryAWSInventoryTestBinding(t *testing.T, job string) awsdiscovery.InventoryBinding {
	t.Helper()
	parse := func(value string) domain.ProductID {
		id, err := domain.ParseProductID(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	scope, err := domain.NewScope(parse("pid_61000001-0000-4000-8000-000000000001"), parse("pid_61000002-0000-4000-8000-000000000002"), parse("pid_61000003-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	return awsdiscovery.InventoryBinding{Scope: scope, IntegrationID: parse("pid_61000004-0000-4000-8000-000000000004"), ConnectionID: parse("pid_61000005-0000-4000-8000-000000000005"), JobID: parse(job),
		Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, Digest: [16]byte{1, 2, 3}}
}

// A later page of the run that read the account gets the held inventory after
// its own credential is verified with the provider; roles, policies, regions
// and instances are not read again. Any other run reads the account itself.
func TestAWSInventoryCallerResumesOnlyTheSameRunAndStillVerifiesTheCredential(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	var identityCalls, iamBuilds, ec2Builds, agentBuilds atomic.Int64
	account := "123456789012"
	caller, err := newDiscoveryAWSCollectionInventoryCaller(discoveryAWSInventoryFactory{
		BedrockAgent: func(region string, credentials aws.Credentials) (discoveryAWSBedrockAgentAPI, error) {
			agentBuilds.Add(1)
			return emptyDiscoveryBedrockAgents(region, credentials)
		},
		AgentCore: emptyDiscoveryAgentCore, Lambda: emptyDiscoveryLambda,
		Identity: func(string, aws.Credentials) (discoveryCallerIdentityAPI, error) {
			identityCalls.Add(1)
			return &discoveryCallerIdentityStub{output: &sts.GetCallerIdentityOutput{Account: aws.String(account), Arn: aws.String("arn:aws:sts::" + account + ":assumed-role/zasp/session")}}, nil
		},
		IAM: func(string, aws.Credentials) (discoveryAWSIAMAPI, error) {
			iamBuilds.Add(1)
			return &discoveryInventoryIAMStub{}, nil
		},
		EC2: func(region string, _ aws.Credentials) (discoveryAWSEC2API, error) {
			ec2Builds.Add(1)
			return &discoveryInventoryEC2Stub{region: region}, nil
		},
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	first := mustDiscoveryAWSCredentialEnvelope(t, now.Add(15*time.Minute))
	inventory, err := caller.GetCollectionInventory(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	binding := discoveryAWSInventoryTestBinding(t, "pid_61000006-0000-4000-8000-000000000006")

	// Nothing is held before the first page keeps it, and nothing is asked
	// of the provider for a binding that is not held.
	identityCalls.Store(0)
	iamBuilds.Store(0)
	ec2Builds.Store(0)
	agentBuilds.Store(0)
	if _, found, err := caller.ResumeCollectionInventory(context.Background(), first, binding); err != nil || found || identityCalls.Load() != 0 {
		t.Fatalf("resume before keep: found=%v err=%v identity calls=%d", found, err, identityCalls.Load())
	}
	caller.RetainCollectionInventory(binding, inventory)

	later := mustDiscoveryAWSCredentialEnvelope(t, now.Add(40*time.Minute))
	resumed, found, err := caller.ResumeCollectionInventory(context.Background(), later, binding)
	if err != nil || !found || identityCalls.Load() != 1 || iamBuilds.Load() != 0 || ec2Builds.Load() != 0 || agentBuilds.Load() != 0 {
		t.Fatalf("resume: found=%v err=%v identity=%d iam=%d ec2=%d", found, err, identityCalls.Load(), iamBuilds.Load(), ec2Builds.Load())
	}
	if !bytes.Equal(resumed.CartographySource, inventory.CartographySource) || !bytes.Equal(resumed.ProwlerSource, inventory.ProwlerSource) || resumed.CartographyDigest != inventory.CartographyDigest || resumed.ProwlerDigest != inventory.ProwlerDigest ||
		len(inventory.AgentSource) == 0 || !bytes.Equal(resumed.AgentSource, inventory.AgentSource) || resumed.AgentDigest != inventory.AgentDigest ||
		resumed.Identity != inventory.Identity || resumed.CredentialExpiresAt != now.Add(40*time.Minute) {
		t.Fatalf("resumed inventory = %#v", resumed)
	}
	// The held bytes are not shared with what a page is handed.
	resumed.ProwlerSource[0] ^= 0xff
	resumed.AgentSource[0] ^= 0xff
	again, found, err := caller.ResumeCollectionInventory(context.Background(), later, binding)
	if err != nil || !found || !bytes.Equal(again.ProwlerSource, inventory.ProwlerSource) || !bytes.Equal(again.AgentSource, inventory.AgentSource) {
		t.Fatalf("held inventory was mutated through a page: found=%v err=%v", found, err)
	}

	// Another run, another integration and another digest hold nothing.
	other := discoveryAWSInventoryTestBinding(t, "pid_61000007-0000-4000-8000-000000000007")
	digest := binding
	digest.Digest = [16]byte{9}
	integration := binding
	integration.IntegrationID = binding.ConnectionID
	for name, candidate := range map[string]awsdiscovery.InventoryBinding{"run": other, "digest": digest, "integration": integration} {
		if _, found, err := caller.ResumeCollectionInventory(context.Background(), later, candidate); err != nil || found {
			t.Fatalf("%s: found=%v err=%v", name, found, err)
		}
	}

	// An expired credential and a credential of another account are refused
	// although the inventory is held.
	expired := mustDiscoveryAWSCredentialEnvelope(t, now)
	if _, found, err := caller.ResumeCollectionInventory(context.Background(), expired, binding); err == nil || found {
		t.Fatalf("expired credential: found=%v err=%v", found, err)
	}
	account = "210987654321"
	if _, found, err := caller.ResumeCollectionInventory(context.Background(), later, binding); !errors.Is(err, awsdiscovery.ErrDenied) || found {
		t.Fatalf("other account: found=%v err=%v", found, err)
	}
	account = "123456789012"

	// The entry ends with its retention time.
	now = now.Add(discoveryAWSInventoryRetentionTime)
	fresh := mustDiscoveryAWSCredentialEnvelope(t, now.Add(15*time.Minute))
	if _, found, err := caller.ResumeCollectionInventory(context.Background(), fresh, binding); err != nil || found {
		t.Fatalf("after retention: found=%v err=%v", found, err)
	}
}

func TestAWSInventoryRetentionIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	retention := newDiscoveryAWSInventoryRetention(func() time.Time { return now })
	inventory := awsdiscovery.CollectionInventory{Identity: awsdiscovery.Identity{AccountID: "123456789012"}, CartographySource: []byte(`{}`), ProwlerSource: []byte(`{}`), AgentSource: []byte(`{}`)}
	base := discoveryAWSInventoryTestBinding(t, "pid_61000006-0000-4000-8000-000000000006")
	for index := 0; index < discoveryAWSInventoryRetentionEntries+4; index++ {
		binding := base
		binding.Digest = [16]byte{byte(index + 1)}
		retention.keep(binding, inventory)
		now = now.Add(time.Second)
	}
	if len(retention.entries) != discoveryAWSInventoryRetentionEntries {
		t.Fatalf("entries = %d", len(retention.entries))
	}
	oldest, newest := base, base
	oldest.Digest, newest.Digest = [16]byte{1}, [16]byte{byte(discoveryAWSInventoryRetentionEntries + 4)}
	if _, found := retention.find(oldest); found {
		t.Fatal("the oldest entry was not evicted")
	}
	if _, found := retention.find(newest); !found {
		t.Fatal("the newest entry is missing")
	}
	// Not kept: over the size limit, another account, an invalid binding.
	large := inventory
	large.CartographySource = make([]byte, discoveryAWSInventoryRetentionBytes)
	wrongAccount := inventory
	wrongAccount.Identity.AccountID = "210987654321"
	unbound := base
	unbound.Digest = [16]byte{}
	candidate := base
	candidate.Digest = [16]byte{200}
	retention.keep(candidate, large)
	retention.keep(candidate, wrongAccount)
	retention.keep(unbound, inventory)
	if _, found := retention.find(candidate); found || len(retention.entries) != discoveryAWSInventoryRetentionEntries {
		t.Fatalf("an inventory that must not be kept was kept (%d entries)", len(retention.entries))
	}
}

func TestAWSInventoryEachRunsEveryIndexBoundedAndStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	seen := make(map[int]int)
	inflight, peak := 0, 0
	err := discoveryAWSEach(context.Background(), 23, func(_ context.Context, index int) error {
		mu.Lock()
		seen[index]++
		inflight++
		if inflight > peak {
			peak = inflight
		}
		mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		mu.Lock()
		inflight--
		mu.Unlock()
		return nil
	})
	if err != nil || len(seen) != 23 || peak < 2 || peak > discoveryAWSInventoryReadConcurrency {
		t.Fatalf("err=%v indexes=%d peak=%d", err, len(seen), peak)
	}
	for index, count := range seen {
		if count != 1 {
			t.Fatalf("index %d ran %d times", index, count)
		}
	}

	// The first failure is returned, the rest is cancelled, and a panic is a
	// refusal, not a crash.
	started := 0
	err = discoveryAWSEach(context.Background(), 1000, func(bounded context.Context, index int) error {
		mu.Lock()
		started++
		mu.Unlock()
		if index == 3 {
			return awsdiscovery.ErrDenied
		}
		<-bounded.Done()
		return bounded.Err()
	})
	if !errors.Is(err, awsdiscovery.ErrDenied) || started > 2*discoveryAWSInventoryReadConcurrency {
		t.Fatalf("err=%v started=%d", err, started)
	}
	if err := discoveryAWSEach(context.Background(), 2, func(context.Context, int) error { panic("provider client") }); !errors.Is(err, awsdiscovery.ErrDenied) {
		t.Fatalf("panic err=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := discoveryAWSEach(cancelled, 5, func(context.Context, int) error { return nil }); !errors.Is(err, awsdiscovery.ErrDenied) {
		t.Fatalf("cancelled err=%v", err)
	}
	if err := discoveryAWSEach(context.Background(), 0, nil); err == nil {
		t.Fatal("nil work accepted")
	}
}
