package s3driver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const providerSecret = "s3-provider-secret-must-not-escape"

const exportFixtureKey = "organizations/pid_00000000-0000-4000-8000-000000000001/workspaces/pid_00000000-0000-4000-8000-000000000002/environments/pid_00000000-0000-4000-8000-000000000003/exports/pid_00000000-0000-4000-8000-000000000004"

func TestPlannedObjectReferenceUsesTypedStoreWithoutSDKCalls(t *testing.T) {
	for _, kind := range []string{"export", "legacy", "mixed export store", "mixed export driver", "nonempty version", "forged driver key", "scope mismatch"} {
		t.Run(kind, func(t *testing.T) {
			transport := &exportSDKTransport{t: t}
			client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://export.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
			newDriver, newStore := NewExport, artifactstore.NewExport
			if kind == "legacy" || kind == "mixed export store" {
				newDriver = New
			}
			if kind == "legacy" || kind == "mixed export driver" {
				newStore = artifactstore.New
			}
			driver, err := newDriver(client, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			store, err := newStore(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			object := fixtureObject(t)
			locator := artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}
			if kind == "nonempty version" {
				locator.VersionID = "version-1"
			}
			var got string
			if kind == "forged driver key" || kind == "scope mismatch" {
				candidate := object.DriverLocator
				candidate.Key = exportFixtureKey
				candidate.VersionID = ""
				if kind == "forged driver key" {
					candidate.Key += "/../other"
				} else {
					candidate.Scope = domain.Scope{}
				}
				got, err = driver.PlannedObjectReference(candidate)
			} else {
				got, err = store.PlannedObjectReference(locator)
			}
			if kind == "export" || kind == "legacy" {
				want := "s3://zasp-production-evidence/" + exportFixtureKey
				if kind == "legacy" {
					want = strings.Replace(want, "/exports/", "/artifacts/", 1)
				}
				if err != nil || got != want {
					t.Fatal("planned immutable destination refused", got, err)
				}
			} else if err == nil || got != "" {
				t.Fatal("invalid planned destination accepted", got)
			}
			if transport.firstPath != "" || transport.puts != 0 || transport.gets != 0 || transport.writes != 0 {
				t.Fatal("planned reference performed provider I/O")
			}
			if _, err := store.ObjectReference(artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}); !errors.Is(err, artifactstore.ErrReference) {
				t.Fatal("legacy versioned reference now accepts unversioned locator")
			}
		})
	}
}

func TestPlannedObjectReferenceRejectsUninitializedDrivers(t *testing.T) {
	locator := fixtureObject(t).DriverLocator
	locator.VersionID = ""
	for _, driver := range []*Driver{nil, {}} {
		if got, err := driver.PlannedObjectReference(locator); got != "" || !errors.Is(err, ErrArtifact) {
			t.Fatal("uninitialized driver returned a destination", err)
		}
	}
}

// Catches either layer selecting the legacy artifact prefix. The SDK is real;
// only the HTTP transport is controlled, with no cloud endpoint or credentials.
func TestExportStoreSDKUsesScopedExportPrefix(t *testing.T) {
	transport := &exportSDKTransport{t: t, losePut: true}
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://export.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
	driver, err := NewExport(client, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: 5 * time.Second, MaximumBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	object := fixtureObject(t)
	request := artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}, MediaType: object.MediaType, Body: object.Body}
	created, err := store.Put(context.Background(), request)
	if err != nil {
		t.Fatalf("export Put failed: %v; first provider path=%q", err, transport.firstPath)
	}
	if created.VersionID != "version-1" || created.SHA256 != object.SHA256 || !bytes.Equal(created.Body, object.Body) {
		t.Fatal("export content authority changed")
	}
	replayed, err := store.Put(context.Background(), request)
	if err != nil || replayed.VersionID != created.VersionID || transport.writes != 1 {
		t.Fatal("export replay created another version", err)
	}
	got, err := store.Get(context.Background(), created.Locator)
	if err != nil || !bytes.Equal(got.Body, object.Body) || got.SHA256 != object.SHA256 {
		t.Fatal("export pinned read failed", err)
	}
	reference, err := store.ObjectReference(created.Locator)
	if err != nil || reference != "s3://zasp-production-evidence/"+exportFixtureKey {
		t.Fatal("export reference escaped profile", reference, err)
	}
	if transport.puts != 2 || transport.gets != 3 {
		t.Fatalf("unexpected provider attempts: puts=%d gets=%d", transport.puts, transport.gets)
	}
}

func TestExportStoreSDKCancellationAfterSavedPutRemainsRecoverable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := &exportSDKTransport{t: t, cancelPut: cancel}
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://export.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
	driver, err := NewExport(client, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: 5 * time.Second, MaximumBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	object := fixtureObject(t)
	request := artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}, MediaType: object.MediaType, Body: object.Body}
	if _, err := store.Put(ctx, request); !errors.Is(err, artifactstore.ErrPut) || transport.writes != 1 || transport.gets != 0 {
		t.Fatal("canceled saved export treated as success or read after cancellation", err)
	}
	created, err := store.Put(context.Background(), request)
	if err != nil || created.VersionID != "version-1" || transport.writes != 1 || !bytes.Equal(created.Body, object.Body) {
		t.Fatal("canceled saved export could not recover exact version", err)
	}
}

func TestExportProfilesRejectMixedConstructionBeforeProviderIO(t *testing.T) {
	for _, item := range []struct {
		name        string
		exportStore bool
	}{{"export store legacy driver", true}, {"legacy store export driver", false}} {
		t.Run(item.name, func(t *testing.T) {
			client := &fakeS3{}
			newDriver, newStore := NewExport, artifactstore.New
			if item.exportStore {
				newDriver, newStore = New, artifactstore.NewExport
			}
			driver, err := newDriver(client, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			store, err := newStore(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			object := fixtureObject(t)
			locator := artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}
			if _, err := store.Put(context.Background(), artifactstore.PutRequest{Locator: locator, Body: object.Body, MediaType: object.MediaType}); !errors.Is(err, artifactstore.ErrPut) {
				t.Fatal("mixed Put accepted", err)
			}
			locator.VersionID = "version-1"
			if _, err := store.Get(context.Background(), locator); !errors.Is(err, artifactstore.ErrGet) {
				t.Fatal("mixed Get accepted", err)
			}
			if _, err := store.ObjectReference(locator); !errors.Is(err, artifactstore.ErrReference) {
				t.Fatal("mixed reference accepted", err)
			}
			if err := store.Delete(context.Background(), locator); !errors.Is(err, artifactstore.ErrDelete) {
				t.Fatal("mixed Delete accepted", err)
			}
			if client.totalCalls() != 0 {
				t.Fatal("mixed profile reached provider")
			}
		})
	}
}

func TestExportDriverRejectsForgedKeysAndScopesBeforeProviderIO(t *testing.T) {
	object := fixtureObject(t)
	object.Key = exportFixtureKey
	for _, item := range []struct {
		name   string
		mutate func(*artifactstore.DriverObject)
	}{
		{"legacy prefix", func(o *artifactstore.DriverObject) { o.Key = strings.Replace(o.Key, "/exports/", "/artifacts/", 1) }},
		{"traversal", func(o *artifactstore.DriverObject) { o.Key += "/../other" }},
		{"encoded traversal", func(o *artifactstore.DriverObject) { o.Key += "%2f..%2fother" }},
		{"foreign organization", func(o *artifactstore.DriverObject) { o.Key = strings.Replace(o.Key, "000000000001", "000000000099", 1) }},
		{"foreign workspace", func(o *artifactstore.DriverObject) { o.Key = strings.Replace(o.Key, "000000000002", "000000000099", 1) }},
		{"foreign environment", func(o *artifactstore.DriverObject) { o.Key = strings.Replace(o.Key, "000000000003", "000000000099", 1) }},
		{"foreign reference", func(o *artifactstore.DriverObject) { o.Key = strings.Replace(o.Key, "000000000004", "000000000099", 1) }},
		{"missing scope", func(o *artifactstore.DriverObject) { o.Scope = domain.Scope{} }},
		{"scope ID reused as reference", func(o *artifactstore.DriverObject) {
			o.Reference, _ = domain.NewEvidenceRef(o.OrganizationID())
			o.Key = strings.Replace(o.Key, "000000000004", "000000000001", 1)
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			client := &fakeS3{}
			driver, err := NewExport(client, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			candidate := object
			item.mutate(&candidate)
			if _, err := driver.Put(context.Background(), candidate); !errors.Is(err, ErrArtifact) {
				t.Fatal("forged Put accepted", err)
			}
			candidate.VersionID = "version-1"
			if _, err := driver.Get(context.Background(), candidate.DriverLocator); !errors.Is(err, ErrArtifact) {
				t.Fatal("forged Get accepted", err)
			}
			if _, err := driver.ObjectReference(candidate.DriverLocator); !errors.Is(err, ErrArtifact) {
				t.Fatal("forged reference accepted", err)
			}
			if err := driver.Delete(context.Background(), candidate.DriverLocator); !errors.Is(err, ErrArtifact) {
				t.Fatal("forged Delete accepted", err)
			}
			if client.totalCalls() != 0 {
				t.Fatal("forged export reached provider")
			}
		})
	}
}

func TestExportReadRefusesCorruptedProviderAuthority(t *testing.T) {
	for _, fault := range []struct {
		name   string
		mutate func(*storedObject)
	}{
		{"organization", func(o *storedObject) { o.metadata["organization_id"] = "foreign" }},
		{"workspace", func(o *storedObject) { o.metadata["workspace_id"] = "foreign" }},
		{"environment", func(o *storedObject) { o.metadata["environment_id"] = "foreign" }},
		{"reference", func(o *storedObject) { o.metadata["artifact_id"] = "foreign" }},
		{"digest metadata", func(o *storedObject) { o.metadata["sha256"] = strings.Repeat("0", 64) }},
		{"missing checksum", func(o *storedObject) { o.checksum = "" }},
		{"wrong checksum", func(o *storedObject) { o.checksum = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"wrong KMS", func(o *storedObject) {
			o.kmsKey = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000000"
		}},
		{"wrong version", func(o *storedObject) { o.version = "version-other" }},
		{"changed body", func(o *storedObject) { o.body = []byte(`{"different":true}`) }},
		{"oversized read", func(o *storedObject) { o.body = bytes.Repeat([]byte("x"), 1025) }},
	} {
		t.Run(fault.name, func(t *testing.T) {
			client := &fakeS3{}
			driver, err := NewExport(client, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: 5 * time.Second, MaximumBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			object := fixtureObject(t)
			created, err := store.Put(context.Background(), artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}, MediaType: object.MediaType, Body: object.Body})
			if err != nil {
				t.Fatal(err)
			}
			client.mutateStored(fault.mutate)
			before := client.totalCalls()
			if _, err := store.Get(context.Background(), created.Locator); !errors.Is(err, artifactstore.ErrGet) {
				t.Fatal("corrupt export accepted", err)
			}
			if client.totalCalls() <= before {
				t.Fatal("read fault did not reach provider boundary")
			}
		})
	}
}

func TestExportDriverKeepsImmutableReplayLimitsAndCancellation(t *testing.T) {
	client := &fakeS3{loseFirstPutResponse: true}
	driver, err := NewExport(client, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	object := fixtureObject(t)
	object.Key = exportFixtureKey
	created, err := driver.Put(context.Background(), object)
	if err != nil {
		t.Fatal(err)
	}
	client.assertExactCreateOnlyRequest(t, object)
	changed := object
	changed.Body = []byte(`{"changed":true}`)
	changed.Size = int64(len(changed.Body))
	changed.SHA256 = sha256.Sum256(changed.Body)
	if _, err := driver.Put(context.Background(), changed); !errors.Is(err, ErrPut) {
		t.Fatal("different existing bytes accepted", err)
	}
	client.installLatest(changed, "version-2")
	client.setCurrentUnavailable(true)
	got, err := driver.Get(context.Background(), created.DriverLocator)
	if err != nil || !bytes.Equal(got.Body, object.Body) || got.VersionID != "version-1" {
		t.Fatal("export read used latest version", err)
	}
	before := client.totalCalls()
	if err := driver.Delete(context.Background(), created.DriverLocator); !errors.Is(err, ErrImmutable) {
		t.Fatal("export deleted", err)
	}
	invalid := object
	invalid.Body = bytes.Repeat([]byte("x"), 1025)
	invalid.Size = 1025
	invalid.SHA256 = sha256.Sum256(invalid.Body)
	if _, err := driver.Put(context.Background(), invalid); !errors.Is(err, ErrArtifact) {
		t.Fatal("oversized export sent", err)
	}
	invalid = object
	invalid.SHA256 = [32]byte{}
	if _, err := driver.Put(context.Background(), invalid); !errors.Is(err, ErrArtifact) {
		t.Fatal("invalid digest sent", err)
	}
	if _, err := driver.Get(context.Background(), object.DriverLocator); !errors.Is(err, ErrArtifact) {
		t.Fatal("unversioned export read", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := driver.Put(ctx, object); !errors.Is(err, ErrPut) {
		t.Fatal("canceled export write", err)
	}
	if _, err := driver.Get(ctx, created.DriverLocator); !errors.Is(err, ErrGet) {
		t.Fatal("canceled export read", err)
	}
	if client.totalCalls() != before || !client.allCallsUsedOneAttempt() {
		t.Fatal("invalid export reached provider or retried")
	}
}

type exportSDKTransport struct {
	t                  *testing.T
	firstPath          string
	body               []byte
	headers            http.Header
	losePut            bool
	cancelPut          context.CancelFunc
	puts, gets, writes int
}

func (transport *exportSDKTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.firstPath == "" {
		transport.firstPath = request.URL.Path
	}
	if request.URL.Host != "export.invalid" || request.URL.Path != "/zasp-production-evidence/"+exportFixtureKey {
		return nil, errors.New("unexpected export key")
	}
	if request.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
		transport.t.Error("missing expected bucket owner")
	}
	status, body := http.StatusOK, []byte(nil)
	if request.Method == http.MethodPut {
		transport.puts++
		if request.Header.Get("If-None-Match") != "*" || request.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" || request.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != validConfig().KMSKeyARN {
			transport.t.Error("export Put lost conditional/KMS authority")
		}
		if transport.writes > 0 {
			status = http.StatusPreconditionFailed
		} else {
			var err error
			transport.body, err = io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			transport.headers = request.Header.Clone()
			transport.headers.Set("X-Amz-Version-Id", "version-1")
			transport.headers.Set("Content-Length", strconv.Itoa(len(transport.body)))
			transport.writes++
			if transport.cancelPut != nil {
				transport.cancelPut()
				transport.cancelPut = nil
			}
			if transport.losePut {
				transport.losePut = false
				return nil, errors.New("saved object; lost response")
			}
		}
	} else {
		if request.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" {
			transport.t.Error("export read omitted checksum mode")
		}
		version := request.URL.Query().Get("versionId")
		if request.Method == http.MethodGet {
			transport.gets++
			if version != "version-1" {
				transport.t.Error("export GET was not version pinned")
			}
			body = bytes.Clone(transport.body)
		} else if request.Method != http.MethodHead || version != "" && version != "version-1" {
			transport.t.Error("unexpected export SDK request")
		}
	}
	return &http.Response{StatusCode: status, Header: transport.headers.Clone(), Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
}

func TestDriverAcceptsOnlyTheOwnedRecoveryMediaTypes(t *testing.T) {
	for _, mediaType := range []string{
		"application/vnd.zasp.recovery-configuration+json",
		"application/vnd.zasp.recovery-projection+json",
		"application/vnd.zasp.recovery-evidence+json",
		"application/vnd.zasp.recovery-manifest+json",
	} {
		if !validMediaType(mediaType) {
			t.Fatalf("recovery media type rejected: %q", mediaType)
		}
	}
	if validMediaType("application/vnd.zasp.recovery-secret+json") {
		t.Fatal("unowned recovery media type accepted")
	}
}

func TestDriverPutIsCreateOnlyAndReconcilesLostAcknowledgement(t *testing.T) {
	client := &fakeS3{loseFirstPutResponse: true}
	driver := mustDriver(t, client)
	object := fixtureObject(t)

	created, err := driver.Put(context.Background(), object)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if created.VersionID != "version-1" || created.Key != object.Key || created.Scope != object.Scope || created.Reference != object.Reference || created.MediaType != object.MediaType || !bytes.Equal(created.Body, object.Body) {
		t.Fatalf("Put() = %#v", created)
	}
	client.assertExactCreateOnlyRequest(t, object)

	replayed, err := driver.Put(context.Background(), object)
	if err != nil || replayed.VersionID != created.VersionID {
		t.Fatalf("replay = %#v, %v", replayed, err)
	}
	if client.createdObjects() != 1 {
		t.Fatalf("created objects = %d, want 1", client.createdObjects())
	}

	changed := object
	changed.Body = []byte(`{"changed":true}`)
	changed.Size = int64(len(changed.Body))
	changed.SHA256 = sha256.Sum256(changed.Body)
	if _, err := driver.Put(context.Background(), changed); !errors.Is(err, ErrPut) || strings.Contains(err.Error(), providerSecret) {
		t.Fatalf("changed replay error = %q", err)
	}
}

func TestDriverGetPinsVersionAndValidatesEveryBoundary(t *testing.T) {
	client := &fakeS3{}
	driver := mustDriver(t, client)
	object := fixtureObject(t)
	created, err := driver.Put(context.Background(), object)
	if err != nil {
		t.Fatal(err)
	}
	got, err := driver.Get(context.Background(), created.DriverLocator)
	if err != nil || got.VersionID != "version-1" || got.SHA256 != object.SHA256 || !bytes.Equal(got.Body, object.Body) {
		t.Fatalf("Get() = %#v, %v", got, err)
	}
	if client.lastGetVersion() != "version-1" {
		t.Fatalf("Get version = %q", client.lastGetVersion())
	}

	for _, mutate := range []func(*storedObject){
		func(value *storedObject) { value.metadata["sha256"] = strings.Repeat("0", 64) },
		func(value *storedObject) { value.contentType = "text/plain" },
		func(value *storedObject) {
			value.kmsKey = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000000"
		},
		func(value *storedObject) { value.body = append(value.body, 'x') },
		func(value *storedObject) { value.version = "" },
	} {
		client.mutateStored(mutate)
		if _, err := driver.Get(context.Background(), created.DriverLocator); !errors.Is(err, ErrGet) {
			t.Fatalf("hostile Get error = %v", err)
		}
		client.restore(object)
	}
}

func TestDriverBuildsTheObjectReferenceFromItsExactBucketAuthority(t *testing.T) {
	t.Parallel()
	driver := mustDriver(t, &fakeS3{})
	locator := fixtureObject(t).DriverLocator
	locator.VersionID = "version-1"
	reference, err := driver.ObjectReference(locator)
	if err != nil || reference != "s3://"+validConfig().Bucket+"/"+locator.Key {
		t.Fatalf("ObjectReference() = %q, %v", reference, err)
	}
	invalid := locator
	invalid.Key += "/drift"
	if reference, err := driver.ObjectReference(invalid); !errors.Is(err, ErrArtifact) || reference != "" {
		t.Fatalf("invalid ObjectReference() = %q, %v", reference, err)
	}
}

func TestDriverReadUsesThePersistedVersionAcrossNewerVersionsAndDeleteMarkers(t *testing.T) {
	client := &fakeS3{}
	driver := mustDriver(t, client)
	original := fixtureObject(t)
	created, err := driver.Put(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	newer := original
	newer.Body = []byte(`{"newer":true}`)
	newer.Size = int64(len(newer.Body))
	newer.SHA256 = sha256.Sum256(newer.Body)
	client.installLatest(newer, "version-2")

	got, err := driver.Get(context.Background(), created.DriverLocator)
	if err != nil || got.VersionID != "version-1" || !bytes.Equal(got.Body, original.Body) {
		t.Fatalf("version-pinned Get() = %#v, %v", got, err)
	}
	client.setCurrentUnavailable(true)
	got, err = driver.Get(context.Background(), created.DriverLocator)
	if err != nil || got.VersionID != "version-1" || !bytes.Equal(got.Body, original.Body) {
		t.Fatalf("delete-marker Get() = %#v, %v", got, err)
	}

	unversioned := created.DriverLocator
	unversioned.VersionID = ""
	before := client.totalCalls()
	if _, err := driver.Get(context.Background(), unversioned); !errors.Is(err, ErrArtifact) || client.totalCalls() != before {
		t.Fatalf("unversioned Get() = %v, calls delta=%d", err, client.totalCalls()-before)
	}
	missing := created.DriverLocator
	missing.VersionID = "version-missing"
	if _, err := driver.Get(context.Background(), missing); !errors.Is(err, ErrGet) {
		t.Fatalf("missing version error = %v", err)
	}
}

func TestDriverRejectsInvalidInputBeforeCloudAndNeverDeletesImmutableEvidence(t *testing.T) {
	client := &fakeS3{}
	driver := mustDriver(t, client)
	object := fixtureObject(t)
	invalid := []artifactstore.DriverObject{{}, object}
	invalid[1].Key += "-cross-scope"
	for _, candidate := range invalid {
		if _, err := driver.Put(context.Background(), candidate); !errors.Is(err, ErrArtifact) {
			t.Fatalf("invalid Put error = %v", err)
		}
	}
	if _, err := driver.Get(context.Background(), invalid[1].DriverLocator); !errors.Is(err, ErrArtifact) {
		t.Fatalf("invalid Get error = %v", err)
	}
	if err := driver.Delete(context.Background(), object.DriverLocator); !errors.Is(err, ErrImmutable) {
		t.Fatalf("Delete error = %v", err)
	}
	if client.totalCalls() != 0 {
		t.Fatalf("cloud calls = %d, want 0", client.totalCalls())
	}
}

func TestDriverUsesOneAttemptAndContainsCancellationProviderErrorsAndPanics(t *testing.T) {
	object := fixtureObject(t)
	for _, client := range []*fakeS3{
		{putErr: errors.New(providerSecret)},
		{panicPut: true},
	} {
		driver := mustDriver(t, client)
		_, err := driver.Put(context.Background(), object)
		if !errors.Is(err, ErrPut) || strings.Contains(err.Error(), providerSecret) {
			t.Fatalf("Put error = %q", err)
		}
		if !client.allCallsUsedOneAttempt() {
			t.Fatal("SDK retryer was not forced to one attempt")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	client := &fakeS3{}
	driver := mustDriver(t, client)
	if _, err := driver.Put(canceled, object); !errors.Is(err, ErrPut) || client.totalCalls() != 0 {
		t.Fatalf("canceled Put = %v, calls=%d", err, client.totalCalls())
	}
}

func TestNewRejectsHostileConfigurationAndTypedNilClient(t *testing.T) {
	valid := validConfig()
	var typedNil *fakeS3
	for _, candidate := range []struct {
		client API
		config Config
	}{
		{nil, valid}, {typedNil, valid}, {&fakeS3{}, Config{}},
		{&fakeS3{}, Config{Bucket: valid.Bucket, ExpectedBucketOwner: valid.ExpectedBucketOwner, KMSKeyARN: valid.KMSKeyARN, MaximumBytes: 64*1024*1024 + 1}},
		{&fakeS3{}, Config{Bucket: "s3://bucket", ExpectedBucketOwner: valid.ExpectedBucketOwner, KMSKeyARN: valid.KMSKeyARN, MaximumBytes: 1}},
		{&fakeS3{}, Config{Bucket: valid.Bucket, ExpectedBucketOwner: "*", KMSKeyARN: valid.KMSKeyARN, MaximumBytes: 1}},
		{&fakeS3{}, Config{Bucket: valid.Bucket, ExpectedBucketOwner: valid.ExpectedBucketOwner, KMSKeyARN: "alias/ambient", MaximumBytes: 1}},
	} {
		for _, constructor := range []func(API, Config) (*Driver, error){New, NewExport} {
			if _, err := constructor(candidate.client, candidate.config); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("artifact/export constructor(%#v) error = %v", candidate.config, err)
			}
		}
	}
}

func mustDriver(t *testing.T, client API) *Driver {
	t.Helper()
	driver, err := New(client, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func validConfig() Config {
	return Config{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 1024}
}

func fixtureObject(t *testing.T) artifactstore.DriverObject {
	t.Helper()
	ids := make([]domain.ProductID, 4)
	for index := range ids {
		value, err := domain.ParseProductID("pid_00000000-0000-4000-8000-00000000000" + string(rune('1'+index)))
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = value
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	reference, err := domain.NewEvidenceRef(ids[3])
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"fixture":true}`)
	return artifactstore.DriverObject{
		DriverLocator: artifactstore.DriverLocator{Key: "organizations/" + ids[0].String() + "/workspaces/" + ids[1].String() + "/environments/" + ids[2].String() + "/artifacts/" + ids[3].String(), Scope: scope, Reference: reference},
		MediaType:     "application/json", Body: body, Size: int64(len(body)), SHA256: sha256.Sum256(body),
	}
}

type storedObject struct {
	body                                   []byte
	contentType, checksum, version, kmsKey string
	metadata                               map[string]string
}

type observedPut struct {
	bucket, key, owner, kmsKey, ifNoneMatch, contentType, checksum string
	contentLength                                                  int64
	metadata                                                       map[string]string
}

type fakeS3 struct {
	mu                                     sync.Mutex
	stored                                 *storedObject
	versions                               map[string]*storedObject
	currentUnavailable                     bool
	put                                    observedPut
	lastVersion                            string
	putCalls, headCalls, getCalls, created int
	loseFirstPutResponse                   bool
	putErr                                 error
	panicPut                               bool
	oneAttempt                             []bool
}

func (client *fakeS3) PutObject(ctx context.Context, input *s3.PutObjectInput, options ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.putCalls++
	client.oneAttempt = append(client.oneAttempt, oneAttempt(options))
	if client.panicPut {
		panic(providerSecret)
	}
	if client.putErr != nil {
		return nil, client.putErr
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	client.put = observedPut{bucket: aws.ToString(input.Bucket), key: aws.ToString(input.Key), owner: aws.ToString(input.ExpectedBucketOwner), kmsKey: aws.ToString(input.SSEKMSKeyId), ifNoneMatch: aws.ToString(input.IfNoneMatch), contentType: aws.ToString(input.ContentType), checksum: aws.ToString(input.ChecksumSHA256), contentLength: aws.ToInt64(input.ContentLength), metadata: cloneMap(input.Metadata)}
	if client.stored != nil {
		return nil, errors.New("precondition failed")
	}
	client.created++
	client.stored = &storedObject{body: bytes.Clone(body), contentType: aws.ToString(input.ContentType), checksum: aws.ToString(input.ChecksumSHA256), version: "version-1", kmsKey: aws.ToString(input.SSEKMSKeyId), metadata: cloneMap(input.Metadata)}
	if client.versions == nil {
		client.versions = map[string]*storedObject{}
	}
	client.versions[client.stored.version] = client.stored
	if client.loseFirstPutResponse {
		client.loseFirstPutResponse = false
		return nil, errors.New("lost acknowledgement")
	}
	return &s3.PutObjectOutput{VersionId: aws.String(client.stored.version), ChecksumSHA256: aws.String(client.stored.checksum), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(client.stored.kmsKey)}, nil
}

func (client *fakeS3) HeadObject(ctx context.Context, input *s3.HeadObjectInput, options ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.headCalls++
	client.oneAttempt = append(client.oneAttempt, oneAttempt(options))
	value := client.stored
	requestedVersion := aws.ToString(input.VersionId)
	if requestedVersion != "" {
		value = client.versions[requestedVersion]
	}
	if ctx.Err() != nil || value == nil || requestedVersion == "" && client.currentUnavailable {
		return nil, errors.New("unavailable")
	}
	return &s3.HeadObjectOutput{ContentLength: aws.Int64(int64(len(value.body))), ContentType: aws.String(value.contentType), ChecksumSHA256: aws.String(value.checksum), VersionId: aws.String(value.version), Metadata: cloneMap(value.metadata), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(value.kmsKey)}, nil
}

func (client *fakeS3) GetObject(ctx context.Context, input *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.getCalls++
	client.oneAttempt = append(client.oneAttempt, oneAttempt(options))
	client.lastVersion = aws.ToString(input.VersionId)
	value := client.stored
	if requestedVersion := aws.ToString(input.VersionId); requestedVersion != "" {
		value = client.versions[requestedVersion]
	}
	if ctx.Err() != nil || value == nil {
		return nil, errors.New("unavailable")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(value.body)), ContentLength: aws.Int64(int64(len(value.body))), ContentType: aws.String(value.contentType), ChecksumSHA256: aws.String(value.checksum), VersionId: aws.String(value.version), Metadata: cloneMap(value.metadata), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(value.kmsKey)}, nil
}

func oneAttempt(options []func(*s3.Options)) bool {
	value := s3.Options{}
	for _, option := range options {
		option(&value)
	}
	return value.Retryer != nil && value.Retryer.MaxAttempts() == 1
}
func cloneMap(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
func (client *fakeS3) createdObjects() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.created
}
func (client *fakeS3) totalCalls() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.putCalls + client.headCalls + client.getCalls
}
func (client *fakeS3) lastGetVersion() string {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.lastVersion
}
func (client *fakeS3) allCallsUsedOneAttempt() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	for _, value := range client.oneAttempt {
		if !value {
			return false
		}
	}
	return len(client.oneAttempt) > 0
}
func (client *fakeS3) mutateStored(mutate func(*storedObject)) {
	client.mu.Lock()
	defer client.mu.Unlock()
	mutate(client.stored)
}
func (client *fakeS3) restore(object artifactstore.DriverObject) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.stored = &storedObject{body: bytes.Clone(object.Body), contentType: object.MediaType, checksum: base64.StdEncoding.EncodeToString(object.SHA256[:]), version: "version-1", kmsKey: validConfig().KMSKeyARN, metadata: metadata(object)}
	if client.versions == nil {
		client.versions = map[string]*storedObject{}
	}
	client.versions[client.stored.version] = client.stored
}
func (client *fakeS3) installLatest(object artifactstore.DriverObject, version string) {
	client.mu.Lock()
	defer client.mu.Unlock()
	value := &storedObject{body: bytes.Clone(object.Body), contentType: object.MediaType, checksum: base64.StdEncoding.EncodeToString(object.SHA256[:]), version: version, kmsKey: validConfig().KMSKeyARN, metadata: metadata(object)}
	if client.versions == nil {
		client.versions = map[string]*storedObject{}
	}
	client.versions[version] = value
	client.stored = value
}
func (client *fakeS3) setCurrentUnavailable(value bool) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.currentUnavailable = value
}
func (client *fakeS3) assertExactCreateOnlyRequest(t *testing.T, object artifactstore.DriverObject) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	wantChecksum := base64.StdEncoding.EncodeToString(object.SHA256[:])
	if client.put.bucket != validConfig().Bucket || client.put.owner != validConfig().ExpectedBucketOwner || client.put.kmsKey != validConfig().KMSKeyARN || client.put.key != object.Key || client.put.ifNoneMatch != "*" || client.put.contentType != object.MediaType || client.put.contentLength != object.Size || client.put.checksum != wantChecksum || !equalTestMap(client.put.metadata, metadata(object)) {
		t.Fatalf("Put request = %#v", client.put)
	}
}
func equalTestMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
