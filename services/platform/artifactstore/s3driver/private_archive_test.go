package s3driver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/zasp-ai/zasp-sec/services/platform/privatearchive"
	"strings"
	"testing"
	"time"
)

type privateS3Fixture struct {
	fakeS3
	versioning                                  types.BucketVersioningStatus
	listedKey, deletedVersion                   string
	deniedDelete, deniedGet, deniedList, marked bool
}

func (f *privateS3Fixture) GetBucketVersioning(_ context.Context, in *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if aws.ToString(in.ExpectedBucketOwner) != validConfig().ExpectedBucketOwner {
		return nil, errors.New("owner")
	}
	return &s3.GetBucketVersioningOutput{Status: f.versioning}, nil
}
func (f *privateS3Fixture) ListObjectVersions(_ context.Context, in *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	f.listedKey = aws.ToString(in.Prefix)
	if f.deniedList || aws.ToString(in.ExpectedBucketOwner) != validConfig().ExpectedBucketOwner || aws.ToInt32(in.MaxKeys) != 2 {
		return nil, errors.New("denied")
	}
	out := &s3.ListObjectVersionsOutput{Name: in.Bucket, Prefix: in.Prefix, IsTruncated: aws.Bool(false)}
	if f.marked {
		out.DeleteMarkers = []types.DeleteMarkerEntry{{Key: in.Prefix}}
	}
	if f.stored != nil {
		out.Versions = []types.ObjectVersion{{Key: in.Prefix, VersionId: aws.String(f.stored.version), Size: aws.Int64(int64(len(f.stored.body)))}}
	}
	return out, nil
}
func (f *privateS3Fixture) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.deletedVersion = aws.ToString(in.VersionId)
	if f.deniedDelete || f.stored == nil || f.stored.version != f.deletedVersion || aws.ToString(in.Key) != f.put.key || aws.ToString(in.ExpectedBucketOwner) != validConfig().ExpectedBucketOwner {
		return nil, errors.New("blocked")
	}
	f.stored = nil
	return &s3.DeleteObjectOutput{}, nil
}
func (f *privateS3Fixture) GetObject(ctx context.Context, in *s3.GetObjectInput, o ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if f.deniedGet {
		return nil, &smithy.GenericAPIError{Code: "AccessDenied"}
	}
	if f.stored == nil {
		return nil, &smithy.GenericAPIError{Code: "NoSuchVersion"}
	}
	return f.fakeS3.GetObject(ctx, in, o...)
}
func TestS3PrivateArchivesPinStorageEncryptionAndDeletion(t *testing.T) {
	ctx := context.Background()
	obj := fixtureObject(t)
	scope := strings.Join([]string{obj.OrganizationID().String(), obj.WorkspaceID().String(), obj.EnvironmentID().String()}, "/")
	sum := sha256.Sum256(obj.Body)
	b := privatearchive.Binding{Scope: scope, Grant: obj.Reference.ArtifactID().String(), Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(obj.Body)), Deadline: time.Now().Add(time.Hour).Unix()}
	cfg := validConfig()
	cfg.MaximumBytes = privatearchive.MaxBytes
	f := &privateS3Fixture{versioning: types.BucketVersioningStatusSuspended}
	if _, e := NewPrivateArchives(ctx, f, cfg, scope); e == nil {
		t.Fatal("suspended versioning accepted")
	}
	f.versioning = types.BucketVersioningStatusEnabled
	s, e := NewPrivateArchives(ctx, f, cfg, scope)
	if e != nil {
		t.Fatal(e)
	}
	foreign := b
	foreign.Scope = strings.Replace(scope, "000000000003", "000000000008", 1)
	if _, e := s.Put(ctx, foreign, obj.Body); e == nil || f.putCalls != 0 {
		t.Fatal("foreign prefix touched")
	}
	if _, e := s.Put(ctx, b, []byte("bad")); e == nil || f.putCalls != 0 {
		t.Fatal("uncertified bytes written")
	}
	v, e := s.Put(ctx, b, obj.Body)
	if e != nil || v == "" || f.put.key != b.Key() || f.put.kmsKey != cfg.KMSKeyARN || f.put.owner != cfg.ExpectedBucketOwner || f.put.ifNoneMatch != "*" {
		t.Fatal("unverified scoped encrypted object", e)
	}
	if got, present, e := s.Lookup(ctx, b); e != nil || !present || got != v || f.listedKey != b.Key() {
		t.Fatal("lost write recovery", e)
	}
	f.deniedDelete = true
	if e := s.DeleteExact(ctx, b, v); e == nil {
		t.Fatal("blocked delete accepted")
	}
	f.deniedDelete = false
	f.deniedGet = true
	if e := s.DeleteExact(ctx, b, v); e == nil {
		t.Fatal("unverified delete accepted")
	}
	f.deniedGet = false
	if e := s.DeleteExact(ctx, b, v); e != nil || f.deletedVersion != v {
		t.Fatal("lost deletion response recovery", e)
	}
	f.marked = true
	if _, _, e := s.Lookup(ctx, b); e == nil {
		t.Fatal("delete marker passed as complete erasure")
	}
	f.marked = false
	f.deniedList = true
	if _, _, e := s.Lookup(ctx, b); e == nil {
		t.Fatal("access denied passed as absence")
	}
	f.deniedList = false
	if _, ok, e := s.Lookup(ctx, b); e != nil || ok {
		t.Fatal("all-version absence check failed")
	}
}
