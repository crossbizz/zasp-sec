package s3driver

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

type evidenceGetMismatch struct{ *fakeS3 }

func (f evidenceGetMismatch) GetObject(ctx context.Context, i *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	out, err := f.fakeS3.GetObject(ctx, i, opts...)
	if err == nil {
		out.ServerSideEncryption = s3types.ServerSideEncryptionAwsKms
		out.SSEKMSKeyId = aws.String(validConfig().KMSKeyARN)
	}
	return out, err
}

func TestSSES3ReconcilesLostCreateAndPinsIntegrity(t *testing.T) {
	ctx := context.Background()
	object := fixtureObject(t)
	fake := &fakeS3{loseFirstPutResponse: true}
	cfg := validConfig()
	cfg.KMSKeyARN = ""
	driver, err := NewSSES3(fake, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := driver.Put(ctx, object)
		if err != nil || got.VersionID != "version-1" || got.SHA256 != object.SHA256 {
			t.Fatalf("reconciled version %q: %v", got.VersionID, err)
		}
	}
	if fake.createdObjects() != 1 || fake.stored.algorithm != s3types.ServerSideEncryptionAes256 || fake.put.kmsKey != "" || fake.put.ifNoneMatch != "*" || fake.put.owner != cfg.ExpectedBucketOwner {
		t.Fatal("write lost its scoped, encrypted, create-only contract")
	}
	loc := object.DriverLocator
	loc.VersionID = "version-1"
	if _, err := driver.Get(ctx, loc); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*storedObject)
	}{
		{"corrupt bytes", func(s *storedObject) { s.body[0] ^= 1 }},
		{"wrong key on AES", func(s *storedObject) { s.kmsKey = validConfig().KMSKeyARN }},
		{"missing encryption", func(s *storedObject) { s.algorithm = "" }},
		{"null version", func(s *storedObject) { s.version = "null" }},
		{"wrong scope", func(s *storedObject) { s.metadata["workspace_id"] = "another" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := *fake.stored
			saved.body = append([]byte(nil), saved.body...)
			saved.metadata = cloneMap(saved.metadata)
			tc.edit(fake.stored)
			if _, err := driver.Get(ctx, loc); !errors.Is(err, artifactstore.ErrIntegrity) {
				t.Fatalf("expected integrity rejection: %v", err)
			}
			*fake.stored = saved
		})
	}
	other, err := NewSSES3(evidenceGetMismatch{fake}, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get(ctx, loc); !errors.Is(err, artifactstore.ErrIntegrity) {
		t.Fatalf("GET contradicted HEAD encryption: %v", err)
	}
}

func TestSSES3ReadsOnlyPinnedLegacyKMSVersions(t *testing.T) {
	ctx := context.Background()
	obj := fixtureObject(t)
	fake := &fakeS3{}
	kms, err := New(fake, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	written, err := kms.Put(ctx, obj)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := NewSSES3(fake, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = managed.Get(ctx, written.DriverLocator); err != nil {
		t.Fatal(err)
	}
	if _, err = managed.Put(ctx, obj); !errors.Is(err, ErrPut) {
		t.Fatalf("a previous KMS write satisfied a new SSE-S3 write: %v", err)
	}
	for _, key := range []string{"", "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222"} {
		cfg := validConfig()
		cfg.KMSKeyARN = key
		reader, err := NewSSES3(fake, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = reader.Get(ctx, written.DriverLocator); !errors.Is(err, artifactstore.ErrIntegrity) {
			t.Fatalf("read unpinned legacy object: %v", err)
		}
	}
	fake.stored.algorithm = s3types.ServerSideEncryptionAes256
	fake.stored.kmsKey = ""
	if _, err = kms.Get(ctx, written.DriverLocator); !errors.Is(err, artifactstore.ErrIntegrity) {
		t.Fatalf("default KMS reader accepted SSE-S3: %v", err)
	}
}
