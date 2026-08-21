package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

type recordingAWSCollectionSecurityRunner struct {
	credential []byte
	request    awsdiscovery.CollectionSecurityRequest
}

func (runner *recordingAWSCollectionSecurityRunner) Collect(_ context.Context, request awsdiscovery.CollectionSecurityRequest, credential []byte) (awsdiscovery.CollectionSecurityResult, error) {
	runner.request = request
	runner.credential = bytes.Clone(credential)
	result := []byte(`{"findings":[],"version":"5.39.1"}`)
	if request.Mode == awsdiscovery.SecurityModeCartographyAWS {
		result = []byte(`{"policies":[],"roles":[],"version":"0.139.1"}`)
	}
	return awsdiscovery.CollectionSecurityResult{Mode: request.Mode, SourceDigest: request.SourceDigest, Result: result}, nil
}

func TestAWSSecurityRunnerValidatesCartographyEnvelopeWithoutForwardingSecret(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	delegate := &recordingAWSCollectionSecurityRunner{}
	analyzer, err := newDiscoveryAWSSecurityRunner(delegate, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	credential := mustDiscoveryAWSCredentialEnvelope(t, now.Add(15*time.Minute))
	request := awsdiscovery.CollectionSecurityRequest{Mode: awsdiscovery.SecurityModeCartographyAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, CredentialExpiresAt: now.Add(15 * time.Minute)}
	if _, err := analyzer.Collect(context.Background(), request, credential); err != nil {
		t.Fatal(err)
	}
	clear(credential)
	if len(delegate.credential) != 0 {
		t.Fatalf("Cartography received AWS credential material: %q", delegate.credential)
	}
}

func (*recordingAWSCollectionSecurityRunner) CheckCollectionReadiness(context.Context) error {
	return nil
}

func TestAWSSecurityRunnerDecodesOnlyExactJobCredentialEnvelope(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	delegate := &recordingAWSCollectionSecurityRunner{}
	analyzer, err := newDiscoveryAWSSecurityRunner(delegate, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	credential := mustDiscoveryAWSCredentialEnvelope(t, now.Add(15*time.Minute))
	request := awsdiscovery.CollectionSecurityRequest{Mode: awsdiscovery.SecurityModeProwlerAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, CredentialExpiresAt: now.Add(15 * time.Minute)}
	if _, err := analyzer.Collect(context.Background(), request, credential); err != nil {
		t.Fatal(err)
	}
	clear(credential)
	want := []byte(`{"access_key_id":"ASIAABCDEFGHIJKLMNOP","expires_at":"2026-08-20T12:15:00Z","secret_access_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	if !bytes.Equal(delegate.credential, want) {
		t.Fatalf("security credential = %s", delegate.credential)
	}
	clear(delegate.credential)
}
