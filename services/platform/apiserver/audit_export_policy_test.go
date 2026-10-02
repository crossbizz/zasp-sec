package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type auditExportPolicyNoIO struct{ calls int }

func (transport *auditExportPolicyNoIO) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("policy construction must not access provider")
}

func auditExportPolicyFixture(t *testing.T) (migrations.AuditExportConfiguration, auditExportStoragePolicy) {
	t.Helper()
	config := migrations.AuditExportConfiguration{PolicyID: "pid_74000001-0000-4000-8000-000000000001", Bucket: "owned-export-fixture", ExpectedBucketOwner: "123456789012", KMSKeyARN: auditExportSDKKMS, MaximumExportBytes: 1 << 30, MaximumRetainedBytes: 10 << 30, MaximumInflight: 2, CaptureTimeoutSeconds: 120}
	digest, err := migrations.AuditExportPolicyDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	return config, auditExportStoragePolicy{Schema: "audit-export-policy-v1", PolicyID: config.PolicyID, PolicyDigest: digest, Bucket: config.Bucket, ExpectedBucketOwner: config.ExpectedBucketOwner, KMSKeyARN: config.KMSKeyARN, MaximumExportBytes: config.MaximumExportBytes, MaximumRetainedBytes: config.MaximumRetainedBytes, MaximumInflight: config.MaximumInflight, CaptureTimeoutSeconds: config.CaptureTimeoutSeconds}
}

func TestAuditExportPolicySelectsOnlyTrustedRevision(t *testing.T) {
	config, policy := auditExportPolicyFixture(t)
	transport := &auditExportPolicyNoIO{}
	client := s3.New(s3.Options{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
	entries := []auditExportStorageEntry{{Configuration: config, Client: client}}
	registry, err := newAuditExportStorageRegistry(entries, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	entries[0].Configuration.Bucket = "changed-after-construction"
	reader, err := registry.Resolve(policy)
	if err != nil || reader == nil {
		t.Fatal("trusted revision refused", err)
	}
	fixture, _, _ := auditExportArtifactFixtureForTest(t)
	ref, err := reader.ObjectReference(fixture.object.Locator)
	if err != nil || ref != fixture.reference {
		t.Fatal("configured reference not preserved", ref, err)
	}
	for _, kind := range []string{"unknown revision", "bucket", "owner", "kms", "quota", "digest"} {
		candidate := policy
		switch kind {
		case "unknown revision":
			candidate.PolicyID = "pid_74000002-0000-4000-8000-000000000002"
		case "bucket":
			candidate.Bucket = "untrusted-bucket"
		case "owner":
			candidate.ExpectedBucketOwner = "999999999999"
		case "kms":
			candidate.KMSKeyARN = "untrusted-key"
		case "quota":
			candidate.MaximumInflight++
		case "digest":
			candidate.PolicyDigest = strings.Repeat("a", 64)
		}
		if _, err := registry.Resolve(candidate); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatal("untrusted policy selected a client", kind, err)
		}
	}
	if transport.calls != 0 {
		t.Fatal("policy resolution accessed provider")
	}
}

func TestAuditExportPolicyRejectsInvalidRegistry(t *testing.T) {
	config, _ := auditExportPolicyFixture(t)
	transport := &auditExportPolicyNoIO{}
	client := s3.New(s3.Options{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
	for _, kind := range []string{"empty", "nil client", "typed nil client", "duplicate", "invalid policy", "zero timeout", "long timeout"} {
		entries := []auditExportStorageEntry{{Configuration: config, Client: client}}
		timeout := time.Second
		switch kind {
		case "empty":
			entries = nil
		case "nil client":
			entries[0].Client = nil
		case "typed nil client":
			entries[0].Client = (*s3.Client)(nil)
		case "duplicate":
			entries = append(entries, entries[0])
		case "invalid policy":
			entries[0].Configuration.MaximumInflight = 0
		case "zero timeout":
			timeout = 0
		case "long timeout":
			timeout = 31 * time.Second
		}
		if _, err := newAuditExportStorageRegistry(entries, timeout); !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatal("bad registry accepted", kind, err)
		}
	}
	if transport.calls != 0 {
		t.Fatal("invalid config accessed provider")
	}
}

func TestAuditExportPolicyRetainsOldAndNewConfiguredRevisions(t *testing.T) {
	old, oldPolicy := auditExportPolicyFixture(t)
	next := old
	next.PolicyID = "pid_74000003-0000-4000-8000-000000000003"
	next.ExpectedCurrentPolicyID = old.PolicyID
	next.Bucket = "new-owned-export-fixture"
	next.MaximumRetainedBytes = 5 << 30
	digest, err := migrations.AuditExportPolicyDigest(next)
	if err != nil {
		t.Fatal(err)
	}
	nextPolicy := oldPolicy
	nextPolicy.PolicyID = next.PolicyID
	nextPolicy.PolicyDigest = digest
	nextPolicy.Bucket = next.Bucket
	nextPolicy.MaximumRetainedBytes = next.MaximumRetainedBytes
	transport := &auditExportPolicyNoIO{}
	client := s3.New(s3.Options{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
	registry, err := newAuditExportStorageRegistry([]auditExportStorageEntry{{Configuration: next, Client: client}, {Configuration: old, Client: client}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fixture, _, _ := auditExportArtifactFixtureForTest(t)
	for _, policy := range []auditExportStoragePolicy{oldPolicy, nextPolicy} {
		reader, err := registry.Resolve(policy)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := reader.ObjectReference(fixture.object.Locator)
		if err != nil || !strings.HasPrefix(ref, "s3://"+policy.Bucket+"/") {
			t.Fatal("retained revision rebound", ref, err)
		}
	}
	if transport.calls != 0 {
		t.Fatal("revision selection used provider")
	}
}

func TestAuditExportPolicyDecodesClosedImmutableWire(t *testing.T) {
	_, policy := auditExportPolicyFixture(t)
	body, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeAuditExportStoragePolicy(body)
	if err != nil || got != policy {
		t.Fatal("valid policy rejected", err)
	}
	for _, kind := range []string{"alias", "duplicate", "missing", "changed digest", "unknown", "trailing", "oversized"} {
		bad := string(body)
		switch kind {
		case "alias":
			bad = strings.Replace(bad, `"bucket":`, `"Bucket":`, 1)
		case "duplicate":
			bad = strings.Replace(bad, `{`, `{"bucket":"owned-export-fixture",`, 1)
		case "missing":
			bad = strings.Replace(bad, `"schema":"audit-export-policy-v1",`, "", 1)
		case "changed digest":
			bad = strings.Replace(bad, policy.PolicyDigest, strings.Repeat("b", 64), 1)
		case "unknown":
			bad = strings.Replace(bad, `{`, `{"url":"https://untrusted.invalid",`, 1)
		case "trailing":
			bad += `{}`
		case "oversized":
			bad += strings.Repeat(" ", 2048)
		}
		if _, err := decodeAuditExportStoragePolicy([]byte(bad)); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatal("bad policy accepted", kind, err)
		}
	}
}
