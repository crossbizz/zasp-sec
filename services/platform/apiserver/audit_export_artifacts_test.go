package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type auditExportArtifactFixture struct {
	object     artifactstore.Artifact
	reference  string
	gets       int
	locator    artifactstore.Locator
	cancel     context.CancelFunc
	failure    string
	references int
}

func (store *auditExportArtifactFixture) Get(_ context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	store.gets++
	if store.failure == "get panic" {
		panic("private provider detail")
	}
	if store.failure == "get error" {
		return artifactstore.Artifact{}, errors.New("private provider detail")
	}
	store.locator = locator
	if store.cancel != nil {
		store.cancel()
	}
	return store.object, nil
}
func (store *auditExportArtifactFixture) ObjectReference(artifactstore.Locator) (string, error) {
	store.references++
	if store.failure == "reference panic" {
		panic("private provider detail")
	}
	if store.failure == "reference error" {
		return "", errors.New("private provider detail")
	}
	return store.reference, nil
}

func auditExportArtifactFixtureForTest(t *testing.T) (*auditExportArtifactFixture, string, string) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	id, err := domain.ParseProductID("pid_73000001-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := domain.NewEvidenceRef(id)
	if err != nil {
		t.Fatal(err)
	}
	key, err := bucketlayout.ExportKey(identity.Scope, id)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"immutable":"export"}`)
	hash := sha256.Sum256(body)
	store := &auditExportArtifactFixture{object: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: identity.Scope, Reference: ref, VersionID: "version-1"}, MediaType: "application/json", Body: body, Size: int64(len(body)), SHA256: hash}, reference: "s3://owned-export-fixture/" + key}
	return store, id.String(), hex.EncodeToString(hash[:])
}

func TestAuditExportArtifactReadsExactPersistedVersion(t *testing.T) {
	store, id, digest := auditExportArtifactFixtureForTest(t)
	body, err := readAuditExportArtifact(context.Background(), store, store.object.Scope, id, store.reference, "version-1", digest, store.object.Size, 2048)
	if err != nil || string(body) != string(store.object.Body) || store.gets != 1 || store.locator != store.object.Locator {
		t.Fatal("pinned read failed", err)
	}
	body[0] = 'x'
	if store.object.Body[0] == 'x' {
		t.Fatal("returned mutable provider buffer")
	}
}

func TestAuditExportArtifactRejectsMutableNullVersion(t *testing.T) {
	store, id, digest := auditExportArtifactFixtureForTest(t)
	store.object.VersionID = "null"
	if _, err := readAuditExportArtifact(context.Background(), store, store.object.Scope, id, store.reference, "null", digest, store.object.Size, 2048); err == nil || store.gets != 0 || store.references != 0 {
		t.Fatal("mutable null version reached provider", err)
	}
}

func TestAuditExportArtifactRejectsWrongProviderResults(t *testing.T) {
	for _, kind := range []string{"version", "scope", "body", "same length recomputed digest", "wrong persisted digest", "size", "digest", "media", "reference", "canceled", "get panic", "get error", "reference panic", "reference error"} {
		t.Run(kind, func(t *testing.T) {
			store, id, digest := auditExportArtifactFixtureForTest(t)
			scope, reference, size := store.object.Scope, store.reference, store.object.Size
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "version":
				store.object.VersionID = "version-2"
			case "scope":
				store.object.Scope = domain.Scope{}
			case "body":
				store.object.Body = []byte(`{"wrong":"bytes"}`)
			case "same length recomputed digest":
				store.object.Body[2] = 'I'
				store.object.SHA256 = sha256.Sum256(store.object.Body)
			case "wrong persisted digest":
				hash := sha256.Sum256([]byte("other persisted artifact"))
				digest = hex.EncodeToString(hash[:])
			case "size":
				store.object.Size++
			case "digest":
				store.object.SHA256 = sha256.Sum256([]byte("wrong"))
			case "media":
				store.object.MediaType = "text/plain"
			case "reference":
				reference = "https://untrusted.invalid/export"
			case "canceled":
				store.cancel = cancel
			case "get panic", "get error", "reference panic", "reference error":
				store.failure = kind
			}
			_, err := readAuditExportArtifact(ctx, store, scope, id, reference, "version-1", digest, size, 2048)
			want := ErrRepositoryUnavailable
			if kind == "canceled" {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatal("accepted wrong artifact", err)
			}
			if err != want {
				t.Fatal("unsanitized provider error", err)
			}
			if kind == "reference" && store.gets != 0 {
				t.Fatal("foreign reference reached provider")
			}
		})
	}
}

func TestAuditExportArtifactRefusesInvalidBoundsBeforeProvider(t *testing.T) {
	for _, kind := range []string{"zero size", "oversize", "zero maximum", "oversize maximum", "empty version", "version newline", "version too long", "invalid digest", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			store, id, digest := auditExportArtifactFixtureForTest(t)
			size, maximum, version := store.object.Size, int64(2048), "version-1"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "zero size":
				size = 0
			case "oversize":
				size = maximum + 1
			case "zero maximum":
				maximum = 0
			case "oversize maximum":
				maximum = 1<<20 + 1
			case "empty version":
				version = ""
			case "version newline":
				version = "bad\nversion"
			case "version too long":
				version = string(make([]byte, 1025))
			case "invalid digest":
				digest = "bad"
			case "canceled":
				cancel()
			}
			if _, err := readAuditExportArtifact(ctx, store, store.object.Scope, id, store.reference, version, digest, size, maximum); err == nil || store.gets != 0 || store.references != 0 {
				t.Fatal("invalid input reached provider", err)
			}
		})
	}
}
