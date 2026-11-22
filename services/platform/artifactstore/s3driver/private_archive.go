package s3driver

import (
	"context"
	"crypto/sha256"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/privatearchive"
)

type PrivateArchiveAPI interface {
	API
	ExportCleanupAPI
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
}
type privateLocator struct {
	locator   string
	scope     domain.Scope
	reference domain.EvidenceRef
}
type PrivateArchives struct {
	client PrivateArchiveAPI
	config Config
	scope  string
}

func NewPrivateArchives(ctx context.Context, client PrivateArchiveAPI, cfg Config, scope string) (*PrivateArchives, error) {
	if _, e := privatearchive.ParseScope(scope); e != nil || cfg.MaximumBytes != privatearchive.MaxBytes {
		return nil, ErrConfiguration
	}
	if _, e := New(client, cfg); e != nil {
		return nil, e
	}
	p := &PrivateArchives{client, cfg, scope}
	if e := p.versioned(ctx); e != nil {
		return nil, e
	}
	return p, nil
}
func (s *PrivateArchives) versioned(ctx context.Context) error {
	v, e := s.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(s.config.Bucket), ExpectedBucketOwner: aws.String(s.config.ExpectedBucketOwner)}, oneAttemptOption)
	if e != nil || v == nil || v.Status != s3types.BucketVersioningStatusEnabled {
		return ErrConfiguration
	}
	return nil
}
func (s *PrivateArchives) bound(spec privatearchive.Binding) (*Driver, artifactstore.DriverLocator, error) {
	var loc artifactstore.DriverLocator
	if !spec.Valid() || spec.Scope != s.scope {
		return nil, loc, ErrArtifact
	}
	scope, _ := privatearchive.ParseScope(spec.Scope)
	grant, _ := domain.ParseProductID(spec.Grant)
	ref, _ := domain.NewEvidenceRef(grant)
	loc = artifactstore.DriverLocator{Scope: scope, Reference: ref, Key: spec.Key()}
	return &Driver{config: s.config, client: s.client, privateBinding: &privateLocator{spec.Key(), scope, ref}}, loc, nil
}
func (s *PrivateArchives) Put(ctx context.Context, b privatearchive.Binding, body []byte) (string, error) {
	d, loc, e := s.bound(b)
	if e != nil || !b.Matches(body) {
		return "", ErrArtifact
	}
	if e = s.versioned(ctx); e != nil {
		return "", e
	}
	obj, e := d.Put(ctx, artifactstore.DriverObject{DriverLocator: loc, Body: body, Size: b.Size, SHA256: sha256.Sum256(body), MediaType: "application/octet-stream"})
	if e != nil || !validVersion(obj.VersionID) || obj.VersionID == "null" {
		return "", ErrPut
	}
	return obj.VersionID, nil
}
func (s *PrivateArchives) Lookup(ctx context.Context, b privatearchive.Binding) (string, bool, error) {
	d, loc, e := s.bound(b)
	if e != nil {
		return "", false, e
	}
	out, e := s.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(s.config.Bucket), ExpectedBucketOwner: aws.String(s.config.ExpectedBucketOwner), Prefix: aws.String(loc.Key), MaxKeys: aws.Int32(2)}, oneAttemptOption)
	if e != nil || out == nil || aws.ToBool(out.IsTruncated) || len(out.DeleteMarkers) > 0 || len(out.CommonPrefixes) > 0 || len(out.Versions) > 1 {
		return "", false, ErrGet
	}
	if len(out.Versions) == 0 {
		return "", false, nil
	}
	v := out.Versions[0]
	loc.VersionID = aws.ToString(v.VersionId)
	if aws.ToString(v.Key) != loc.Key || !validVersion(loc.VersionID) || loc.VersionID == "null" || aws.ToInt64(v.Size) != b.Size {
		return "", false, ErrGet
	}
	obj, e := d.Get(ctx, loc)
	if e != nil || !b.Matches(obj.Body) {
		return "", false, ErrGet
	}
	return loc.VersionID, true, nil
}
func (s *PrivateArchives) DeleteExact(ctx context.Context, b privatearchive.Binding, v string) error {
	d, loc, e := s.bound(b)
	if e != nil {
		return e
	}
	loc.VersionID = v
	if v == "" || !d.validLocator(loc) {
		return ErrArtifact
	}
	return deletePinnedAndVerify(ctx, s.client, s.config, loc)
}
