package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// Actual provider collection and S3 driver, with only page IO and versioned S3
// bytes controlled. A product retry must not collide with its prior artifact;
// a resume must bind the producing effect supplied by the SQL checkpoint.
func TestProductDiscoveryArtifactsEffectAndResume(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	scope := discoveryCredentialScope(t)
	legacy := discoveryCredentialInput(scope, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/external-id/customer-0001", collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp/discovery"}`, now)
	legacy.ObservationTime = now
	raw, _ := json.Marshal(legacy)
	var input apiserver.DiscoveryCollectionInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	input.EffectID, input.Deadline = strings.Repeat("a", 64), now.Add(time.Hour)
	request, err := input.CollectionRequest(scope)
	if err != nil {
		t.Fatal(err)
	}
	request.Bounds.MaxPages = 10000
	request.Bounds.FreshPageLimit = 1
	storage := &productVersionedS3{items: map[string]*discoveryS3APIStub{}}
	artifacts, err := newProductionDiscoveryArtifactAuthority(storage, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	cache, err := newDiscoveryArtifactCache(artifacts, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"}, 1024, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	artifacts = cache
	first, err := awsdiscovery.NewCollectionPage(request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "next"}, false, []json.RawMessage{json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{"account_id":"123456789012"},"attributes":{}}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	api := &productArtifactPageAPI{page: first}
	base, err := awsdiscovery.NewCollectionClient(api, artifacts, awsdiscovery.CollectionClientConfig{CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	collect := func(client collection.ProviderClient, req collection.Request) (collection.Outcome, error) {
		ctx, cancel, err := collection.WithScopedProductEffect(context.Background(), req.EffectID, req.Scope, input.Deadline, func(context.Context) error { return nil })
		if err != nil {
			return nil, err
		}
		defer cancel()
		return client.CollectWithCredential(ctx, req, []byte("temporary-aws-credential"))
	}
	out, err := collect(base, request)
	partial, ok := out.(collection.PartialResult)
	if err != nil || !ok {
		t.Fatalf("first partial %T %v", out, err)
	}
	d := partial.Manifest().Descriptor()
	checksum := d.Checksum()
	seed := collection.ResumeSeed{EffectID: request.EffectID, CheckpointVersion: 1, CheckpointDigest: bytes.Repeat([]byte{7}, 32), Cursor: partial.NextCursor(), ManifestReference: d.ObjectReference(), ManifestKey: d.Key(), ManifestVersionID: d.VersionID(), ManifestChecksum: checksum[:], ManifestSizeBytes: d.Size(), ManifestMediaType: d.MediaType(), ManifestSchema: d.SchemaVersion(), ParserVersion: d.ParserVersion(), ToolVersion: d.ToolVersion()}
	// Same generation and cursor, newly authorized safe retry: distinct objects.
	request.EffectID = strings.Repeat("b", 64)
	out, err = collect(base, request)
	retry, ok := out.(collection.PartialResult)
	if err != nil || !ok || retry.Manifest().Descriptor().Key() == d.Key() || storage.writes != 4 {
		t.Fatalf("safe retry artifacts %T %v writes=%d", out, err, storage.writes)
	}
	request.EffectID = strings.Repeat("c", 64)
	request.Cursor = partial.NextCursor()
	request.Bounds.MaxPages = 2
	api.page, err = awsdiscovery.NewCollectionPage(request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "complete"}, true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resumable := base.(interface {
		WithResumeSeed(collection.ResumeSeed) (collection.ProviderClient, error)
	})
	bad := seed
	bad.EffectID = request.EffectID
	badClient, err := resumable.WithResumeSeed(bad)
	if err != nil {
		t.Fatal(err)
	}
	calls, writes := api.calls, storage.writes
	if _, err = collect(badClient, request); err == nil || api.calls != calls || storage.writes != writes {
		t.Fatal("foreign producing effect reached provider or write", err)
	}
	resumed, err := resumable.WithResumeSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	exhausted := request
	exhausted.Bounds.MaxPages = 1
	calls, writes = api.calls, storage.writes
	_, exhaustedErr := collect(resumed, exhausted)
	var exhaustedFailure *collection.Failure
	if !errors.As(exhaustedErr, &exhaustedFailure) || exhaustedFailure.Code() != collection.FailurePartial || api.calls != calls || storage.writes != writes {
		t.Fatal("exhausted total budget must stop without zero-progress artifacts", exhaustedErr)
	}
	reads := storage.reads
	out, err = collect(resumed, request)
	complete, ok := out.(collection.CompleteResult)
	if err != nil || !ok || complete.Snapshot().EntityCount() != 1 || len(complete.Manifest().Objects()) != 2 || api.lastCursor != seed.Cursor {
		t.Fatalf("prior effect resume %T %v cursor=%v", out, err, api.lastCursor)
	}
	// The two new writes retain their own Head/Get verification (four reads).
	if storage.reads != reads+4 {
		t.Fatal("verified cached resume reread storage", storage.reads-reads)
	}
}

type productArtifactPageAPI struct {
	page       awsdiscovery.CollectionPage
	calls      int
	lastCursor collection.Cursor
}

func (a *productArtifactPageAPI) FetchCollectionPage(_ context.Context, _ []byte, q awsdiscovery.CollectionPageRequest) (awsdiscovery.CollectionPage, error) {
	a.calls++
	a.lastCursor = q.Cursor
	return a.page, nil
}
func (*productArtifactPageAPI) CheckCollectionReadiness(context.Context) error { return nil }
