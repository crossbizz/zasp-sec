package artifactstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const driverSecret = "artifact-driver-secret-must-not-escape"

func TestStorePutGetDeleteHappyPath(t *testing.T) {
	t.Parallel()

	request := validPutRequest(t)
	wantLocator, err := buildDriverLocator(request.Scope, request.Reference)
	if err != nil {
		t.Fatal(err)
	}
	wantKey := wantLocator.Key
	wantChecksum := sha256.Sum256(request.Body)
	var retained DriverObject
	driver := &recordingDriver{}
	driver.put = func(ctx context.Context, object DriverObject) (DriverObject, error) {
		requireDeadline(t, ctx)
		if object.Key != wantKey || object.Scope != request.Scope || object.Reference != request.Reference ||
			object.MediaType != request.MediaType || object.Size != int64(len(request.Body)) || object.SHA256 != wantChecksum ||
			!bytes.Equal(object.Body, request.Body) {
			t.Fatalf("Put object = %#v", object)
		}
		retained = cloneDriverObject(object)
		return cloneDriverObject(object), nil
	}
	driver.get = func(ctx context.Context, locator DriverLocator) (DriverObject, error) {
		requireDeadline(t, ctx)
		if locator.Key != wantKey || locator.Scope != request.Scope || locator.Reference != request.Reference {
			t.Fatalf("Get locator = %#v", locator)
		}
		return cloneDriverObject(retained), nil
	}
	driver.delete = func(ctx context.Context, locator DriverLocator) error {
		requireDeadline(t, ctx)
		if locator.Key != wantKey || locator.Scope != request.Scope || locator.Reference != request.Reference {
			t.Fatalf("Delete locator = %#v", locator)
		}
		return nil
	}

	store := mustStore(t, driver, Config{OperationTimeout: time.Second, MaximumBytes: 1024})
	var contract ArtifactStore = store
	artifact, err := contract.Put(context.Background(), request)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	assertArtifact(t, artifact, request, wantChecksum)

	request.Body[0] = 'X'
	artifact.Body[0] = 'Y'
	if retained.Body[0] != '{' {
		t.Fatal("Put did not defensively copy caller bytes")
	}
	got, err := contract.Get(context.Background(), request.Locator)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Body[0] != '{' || got.SHA256 != wantChecksum {
		t.Fatalf("Get() = %#v", got)
	}
	got.Body[0] = 'Z'
	if retained.Body[0] != '{' {
		t.Fatal("Get did not defensively copy driver bytes")
	}
	if err := contract.Delete(context.Background(), request.Locator); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestStorePreservesAnOpaqueDriverVersionWithoutLettingItChangeContentIdentity(t *testing.T) {
	t.Parallel()
	request := validPutRequest(t)
	driver := &recordingDriver{put: func(_ context.Context, object DriverObject) (DriverObject, error) {
		object.VersionID = "version-1"
		return object, nil
	}}
	store := mustStore(t, driver, validConfig())
	artifact, err := store.Put(context.Background(), request)
	if err != nil || artifact.VersionID != "version-1" {
		t.Fatalf("Put() = %#v, %v", artifact, err)
	}

	hostile := &recordingDriver{put: func(_ context.Context, object DriverObject) (DriverObject, error) {
		object.VersionID = "version 1"
		return object, nil
	}}
	if _, err := mustStore(t, hostile, validConfig()).Put(context.Background(), request); !errors.Is(err, ErrPut) {
		t.Fatalf("hostile version error = %v", err)
	}
}

func TestNewRejectsInvalidConfigurationAndDriver(t *testing.T) {
	t.Parallel()

	valid := &recordingDriver{}
	configs := []Config{
		{},
		{OperationTimeout: time.Second},
		{OperationTimeout: time.Second, MaximumBytes: -1},
		{OperationTimeout: 0, MaximumBytes: 1},
		{OperationTimeout: -time.Second, MaximumBytes: 1},
		{OperationTimeout: 30*time.Second + time.Nanosecond, MaximumBytes: 1},
		{OperationTimeout: time.Second, MaximumBytes: 64*1024*1024 + 1},
	}
	for index, config := range configs {
		if _, err := New(valid, config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("config %d error = %v", index, err)
		}
	}
	if _, err := New(nil, validConfig()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil driver error = %v", err)
	}
	var typedNil *recordingDriver
	if _, err := New(typedNil, validConfig()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("typed nil driver error = %v", err)
	}
}

func TestOperationsRejectInvalidProductRequestsBeforeDriver(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	driver := &recordingDriver{
		put:    func(context.Context, DriverObject) (DriverObject, error) { calls.Add(1); return DriverObject{}, nil },
		get:    func(context.Context, DriverLocator) (DriverObject, error) { calls.Add(1); return DriverObject{}, nil },
		delete: func(context.Context, DriverLocator) error { calls.Add(1); return nil },
	}
	store := mustStore(t, driver, Config{OperationTimeout: time.Second, MaximumBytes: 8})
	valid := validPutRequest(t)
	invalidPuts := []PutRequest{
		{},
		{Locator: Locator{Reference: valid.Reference}, MediaType: valid.MediaType, Body: []byte("x")},
		{Locator: Locator{Scope: valid.Scope}, MediaType: valid.MediaType, Body: []byte("x")},
		{Locator: valid.Locator, MediaType: "application/xml", Body: []byte("x")},
		{Locator: valid.Locator, MediaType: " application/json", Body: []byte("x")},
		{Locator: valid.Locator, MediaType: "application/json"},
		{Locator: valid.Locator, MediaType: "application/json", Body: []byte("123456789")},
	}
	for index, request := range invalidPuts {
		if _, err := store.Put(context.Background(), request); !errors.Is(err, ErrArtifact) {
			t.Fatalf("invalid Put %d error = %v", index, err)
		}
	}
	if _, err := store.Put(nil, valid); !errors.Is(err, ErrPut) {
		t.Fatalf("nil-context Put error = %v", err)
	}
	if _, err := store.Get(context.Background(), Locator{}); !errors.Is(err, ErrArtifact) {
		t.Fatalf("invalid Get error = %v", err)
	}
	if err := store.Delete(context.Background(), Locator{}); !errors.Is(err, ErrArtifact) {
		t.Fatalf("invalid Delete error = %v", err)
	}
	if _, err := store.Get(nil, valid.Locator); !errors.Is(err, ErrGet) {
		t.Fatalf("nil-context Get error = %v", err)
	}
	if err := store.Delete(nil, valid.Locator); !errors.Is(err, ErrDelete) {
		t.Fatalf("nil-context Delete error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("driver calls = %d, want 0", calls.Load())
	}
}

func TestPutRejectsEveryMismatchedDriverResult(t *testing.T) {
	t.Parallel()

	request := validPutRequest(t)
	base := driverObject(request)
	other := fixtureLocator(t, 5)
	cases := []struct {
		name   string
		mutate func(*DriverObject)
	}{
		{name: "key", mutate: func(value *DriverObject) { value.Key += "-other" }},
		{name: "scope", mutate: func(value *DriverObject) { value.Scope = other.Scope }},
		{name: "reference", mutate: func(value *DriverObject) { value.Reference = other.Reference }},
		{name: "media", mutate: func(value *DriverObject) { value.MediaType = "text/plain" }},
		{name: "body", mutate: func(value *DriverObject) { value.Body = []byte("different") }},
		{name: "size", mutate: func(value *DriverObject) { value.Size++ }},
		{name: "checksum", mutate: func(value *DriverObject) { value.SHA256[0] ^= 1 }},
		{name: "oversized", mutate: func(value *DriverObject) {
			value.Body = bytes.Repeat([]byte("x"), 1025)
			value.Size = int64(len(value.Body))
			value.SHA256 = sha256.Sum256(value.Body)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			returned := cloneDriverObject(base)
			test.mutate(&returned)
			store := mustStore(t, &recordingDriver{put: func(context.Context, DriverObject) (DriverObject, error) {
				return returned, nil
			}}, validConfig())
			if _, err := store.Put(context.Background(), request); !errors.Is(err, ErrPut) {
				t.Fatalf("Put() error = %v", err)
			}
		})
	}
}

func TestGetValidatesExactDriverStateAndChecksum(t *testing.T) {
	t.Parallel()

	request := validPutRequest(t)
	base := driverObject(request)
	cases := []struct {
		name   string
		mutate func(*DriverObject)
	}{
		{name: "empty", mutate: func(value *DriverObject) { *value = DriverObject{} }},
		{name: "key", mutate: func(value *DriverObject) { value.Key += "-other" }},
		{name: "media", mutate: func(value *DriverObject) { value.MediaType = "image/png" }},
		{name: "size", mutate: func(value *DriverObject) { value.Size++ }},
		{name: "checksum", mutate: func(value *DriverObject) { value.SHA256[0] ^= 1 }},
		{name: "body checksum", mutate: func(value *DriverObject) { value.Body[0] ^= 1 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			returned := cloneDriverObject(base)
			test.mutate(&returned)
			store := mustStore(t, &recordingDriver{get: func(context.Context, DriverLocator) (DriverObject, error) {
				return returned, nil
			}}, validConfig())
			if _, err := store.Get(context.Background(), request.Locator); !errors.Is(err, ErrGet) {
				t.Fatalf("Get() error = %v", err)
			}
		})
	}
}

func TestOperationsContainDriverErrorsAndPanics(t *testing.T) {
	t.Parallel()

	request := validPutRequest(t)
	tests := []struct {
		name   string
		driver Driver
		run    func(*Store) error
		want   error
	}{
		{name: "put error", driver: &recordingDriver{put: func(context.Context, DriverObject) (DriverObject, error) {
			return DriverObject{}, errors.New(driverSecret)
		}}, run: func(store *Store) error { _, err := store.Put(context.Background(), request); return err }, want: ErrPut},
		{name: "put panic", driver: &recordingDriver{put: func(context.Context, DriverObject) (DriverObject, error) { panic(driverSecret) }}, run: func(store *Store) error { _, err := store.Put(context.Background(), request); return err }, want: ErrPut},
		{name: "get error", driver: &recordingDriver{get: func(context.Context, DriverLocator) (DriverObject, error) {
			return DriverObject{}, errors.New(driverSecret)
		}}, run: func(store *Store) error { _, err := store.Get(context.Background(), request.Locator); return err }, want: ErrGet},
		{name: "get panic", driver: &recordingDriver{get: func(context.Context, DriverLocator) (DriverObject, error) { panic(driverSecret) }}, run: func(store *Store) error { _, err := store.Get(context.Background(), request.Locator); return err }, want: ErrGet},
		{name: "delete error", driver: &recordingDriver{delete: func(context.Context, DriverLocator) error { return errors.New(driverSecret) }}, run: func(store *Store) error { return store.Delete(context.Background(), request.Locator) }, want: ErrDelete},
		{name: "delete panic", driver: &recordingDriver{delete: func(context.Context, DriverLocator) error { panic(driverSecret) }}, run: func(store *Store) error { return store.Delete(context.Background(), request.Locator) }, want: ErrDelete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := mustStore(t, test.driver, validConfig())
			err := test.run(store)
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), driverSecret) {
				t.Fatalf("operation error = %q, want fixed %v", err, test.want)
			}
		})
	}
}

func TestOperationsUseOneBoundedContextAndHonorCancellation(t *testing.T) {
	t.Parallel()

	request := validPutRequest(t)
	tests := []struct {
		name string
		run  func(*Store, context.Context) error
		want error
	}{
		{name: "put", run: func(store *Store, ctx context.Context) error { _, err := store.Put(ctx, request); return err }, want: ErrPut},
		{name: "get", run: func(store *Store, ctx context.Context) error { _, err := store.Get(ctx, request.Locator); return err }, want: ErrGet},
		{name: "delete", run: func(store *Store, ctx context.Context) error { return store.Delete(ctx, request.Locator) }, want: ErrDelete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := &recordingDriver{
				put: func(ctx context.Context, object DriverObject) (DriverObject, error) {
					<-ctx.Done()
					return object, ctx.Err()
				},
				get: func(ctx context.Context, _ DriverLocator) (DriverObject, error) {
					<-ctx.Done()
					return DriverObject{}, ctx.Err()
				},
				delete: func(ctx context.Context, _ DriverLocator) error { <-ctx.Done(); return ctx.Err() },
			}
			store := mustStore(t, driver, Config{OperationTimeout: 20 * time.Millisecond, MaximumBytes: 1024})
			started := time.Now()
			err := test.run(store, context.Background())
			if !errors.Is(err, test.want) || time.Since(started) > 500*time.Millisecond {
				t.Fatalf("operation = %v after %v", err, time.Since(started))
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if err := test.run(store, canceled); !errors.Is(err, test.want) {
				t.Fatalf("canceled operation = %v", err)
			}
		})
	}
}

func TestCanonicalKeyIsStableAndContainsOnlyProductIdentity(t *testing.T) {
	t.Parallel()

	locator := fixtureLocator(t, 1)
	driverLocator, err := buildDriverLocator(locator.Scope, locator.Reference)
	if err != nil {
		t.Fatalf("buildDriverLocator() error = %v", err)
	}
	want := "organizations/pid_00000000-0000-4000-8000-000000000001/" +
		"workspaces/pid_00000000-0000-4000-8000-000000000002/" +
		"environments/pid_00000000-0000-4000-8000-000000000003/" +
		"artifacts/pid_00000000-0000-4000-8000-000000000004"
	if driverLocator.Key != want || driverLocator.Scope != locator.Scope || driverLocator.Reference != locator.Reference {
		t.Fatalf("buildDriverLocator() = %#v, want key %q", driverLocator, want)
	}
	if strings.Contains(driverLocator.Key, "bucket") || strings.Contains(driverLocator.Key, "s3") {
		t.Fatal("canonical key exposed provider vocabulary")
	}
}

func TestBuildDriverLocatorRejectsInvalidIdentity(t *testing.T) {
	t.Parallel()

	valid := fixtureLocator(t, 1)
	for name, input := range map[string]Locator{
		"zero":      {},
		"scope":     {Reference: valid.Reference},
		"reference": {Scope: valid.Scope},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := buildDriverLocator(input.Scope, input.Reference)
			if !errors.Is(err, ErrArtifact) || got != (DriverLocator{}) {
				t.Fatalf("buildDriverLocator() = %#v, %v", got, err)
			}
		})
	}
}

func TestStoreDeniesSameSessionCrossOrganizationRead(t *testing.T) {
	t.Parallel()

	organizationA, organizationB := crossOrganizationLocators(t)
	driver := &memoryDriver{objects: make(map[string]DriverObject)}
	store := mustStore(t, driver, validConfig())
	request := PutRequest{Locator: organizationB, MediaType: "application/json", Body: []byte(`{"fixture":"organization-b"}`)}
	if _, err := store.Put(context.Background(), request); err != nil {
		t.Fatalf("Organization B Put() error = %v", err)
	}
	got, err := store.Get(context.Background(), organizationA)
	if !errors.Is(err, ErrGet) || got.Locator != (Locator{}) || got.MediaType != "" || got.Body != nil || got.Size != 0 || got.SHA256 != ([sha256.Size]byte{}) {
		t.Fatalf("Organization A Get() = %#v, %v", got, err)
	}

	organizationALocator, err := buildDriverLocator(organizationA.Scope, organizationA.Reference)
	if err != nil {
		t.Fatal(err)
	}
	organizationBLocator, err := buildDriverLocator(organizationB.Scope, organizationB.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if organizationALocator.Key == organizationBLocator.Key {
		t.Fatal("cross-Organization locators aliased")
	}
	aSuffix := strings.TrimPrefix(organizationALocator.Key, "organizations/"+organizationA.OrganizationID().String()+"/")
	bSuffix := strings.TrimPrefix(organizationBLocator.Key, "organizations/"+organizationB.OrganizationID().String()+"/")
	if aSuffix != bSuffix {
		t.Fatalf("same lower-scope suffixes differ: %q != %q", aSuffix, bSuffix)
	}
	putCalls, getCalls := driver.calls()
	if len(putCalls) != 1 || putCalls[0] != organizationBLocator || len(getCalls) != 1 || getCalls[0] != organizationALocator {
		t.Fatalf("driver calls = put %#v, get %#v", putCalls, getCalls)
	}
}

func TestStoreDerivesConcurrentOrganizationPrefixesPerCall(t *testing.T) {
	t.Parallel()

	organizationA, organizationB := crossOrganizationLocators(t)
	driver := &memoryDriver{objects: make(map[string]DriverObject)}
	store := mustStore(t, driver, validConfig())
	requests := []PutRequest{
		{Locator: organizationA, MediaType: "application/json", Body: []byte(`{"organization":"a"}`)},
		{Locator: organizationB, MediaType: "application/json", Body: []byte(`{"organization":"b"}`)},
	}

	var group sync.WaitGroup
	for index := range 64 {
		group.Add(1)
		go func(request PutRequest) {
			defer group.Done()
			if _, err := store.Put(context.Background(), request); err != nil {
				t.Errorf("Put() error = %v", err)
			}
		}(requests[index%len(requests)])
	}
	group.Wait()

	putCalls, _ := driver.calls()
	if len(putCalls) != 64 {
		t.Fatalf("Put calls = %d, want 64", len(putCalls))
	}
	for _, call := range putCalls {
		wantPrefix := "organizations/" + call.OrganizationID().String() + "/"
		if !strings.HasPrefix(call.Key, wantPrefix) {
			t.Fatalf("locator %q does not match call scope %q", call.Key, wantPrefix)
		}
	}
}

func TestStoreSupportsConcurrentIndependentOperations(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	driver := &recordingDriver{put: func(context.Context, DriverObject) (DriverObject, error) {
		calls.Add(1)
		return DriverObject{}, errors.New("expected")
	}}
	store := mustStore(t, driver, validConfig())
	request := validPutRequest(t)
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := store.Put(context.Background(), request); !errors.Is(err, ErrPut) {
				t.Errorf("Put() error = %v", err)
			}
		}()
	}
	group.Wait()
	if calls.Load() != 32 {
		t.Fatalf("driver calls = %d, want 32", calls.Load())
	}
}

type recordingDriver struct {
	put    func(context.Context, DriverObject) (DriverObject, error)
	get    func(context.Context, DriverLocator) (DriverObject, error)
	delete func(context.Context, DriverLocator) error
}

type memoryDriver struct {
	mu       sync.Mutex
	objects  map[string]DriverObject
	putCalls []DriverLocator
	getCalls []DriverLocator
}

func (driver *memoryDriver) Put(_ context.Context, object DriverObject) (DriverObject, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.putCalls = append(driver.putCalls, object.DriverLocator)
	driver.objects[object.Key] = cloneDriverObject(object)
	return cloneDriverObject(object), nil
}

func (driver *memoryDriver) Get(_ context.Context, locator DriverLocator) (DriverObject, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.getCalls = append(driver.getCalls, locator)
	object, ok := driver.objects[locator.Key]
	if !ok {
		return DriverObject{}, errors.New("missing")
	}
	return cloneDriverObject(object), nil
}

func (driver *memoryDriver) Delete(_ context.Context, locator DriverLocator) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	delete(driver.objects, locator.Key)
	return nil
}

func (driver *memoryDriver) calls() ([]DriverLocator, []DriverLocator) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return append([]DriverLocator(nil), driver.putCalls...), append([]DriverLocator(nil), driver.getCalls...)
}

func (driver *recordingDriver) Put(ctx context.Context, object DriverObject) (DriverObject, error) {
	if driver.put == nil {
		return object, nil
	}
	return driver.put(ctx, object)
}

func (driver *recordingDriver) Get(ctx context.Context, locator DriverLocator) (DriverObject, error) {
	if driver.get == nil {
		return DriverObject{}, errors.New("get not configured")
	}
	return driver.get(ctx, locator)
}

func (driver *recordingDriver) Delete(ctx context.Context, locator DriverLocator) error {
	if driver.delete == nil {
		return nil
	}
	return driver.delete(ctx, locator)
}

func mustStore(t *testing.T, driver Driver, config Config) *Store {
	t.Helper()
	store, err := New(driver, config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return store
}

func validConfig() Config {
	return Config{OperationTimeout: time.Second, MaximumBytes: 1024}
}

func validPutRequest(t *testing.T) PutRequest {
	t.Helper()
	return PutRequest{Locator: fixtureLocator(t, 1), MediaType: "application/json", Body: []byte(`{"fixture":true}`)}
}

func fixtureLocator(t *testing.T, offset int) Locator {
	t.Helper()
	ids := make([]domain.ProductID, 4)
	for index := range ids {
		text := "pid_00000000-0000-4000-8000-00000000000" + string(rune('0'+offset+index))
		parsed, err := domain.ParseProductID(text)
		if err != nil {
			t.Fatalf("ParseProductID(%q) error = %v", text, err)
		}
		ids[index] = parsed
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	reference, err := domain.NewEvidenceRef(ids[3])
	if err != nil {
		t.Fatalf("NewEvidenceRef() error = %v", err)
	}
	return Locator{Scope: scope, Reference: reference}
}

func crossOrganizationLocators(t *testing.T) (Locator, Locator) {
	t.Helper()
	ids := make([]domain.ProductID, 5)
	for index := range ids {
		text := "pid_00000000-0000-4000-8000-00000000000" + string(rune('1'+index))
		parsed, err := domain.ParseProductID(text)
		if err != nil {
			t.Fatalf("ParseProductID(%q) error = %v", text, err)
		}
		ids[index] = parsed
	}
	scopeA, err := domain.NewScope(ids[0], ids[2], ids[3])
	if err != nil {
		t.Fatal(err)
	}
	scopeB, err := domain.NewScope(ids[1], ids[2], ids[3])
	if err != nil {
		t.Fatal(err)
	}
	reference, err := domain.NewEvidenceRef(ids[4])
	if err != nil {
		t.Fatal(err)
	}
	return Locator{Scope: scopeA, Reference: reference}, Locator{Scope: scopeB, Reference: reference}
}

func driverObject(request PutRequest) DriverObject {
	body := bytes.Clone(request.Body)
	locator, err := buildDriverLocator(request.Scope, request.Reference)
	if err != nil {
		panic(err)
	}
	return DriverObject{
		DriverLocator: locator,
		MediaType:     request.MediaType,
		Body:          body,
		Size:          int64(len(body)),
		SHA256:        sha256.Sum256(body),
	}
}

func assertArtifact(t *testing.T, artifact Artifact, request PutRequest, checksum [32]byte) {
	t.Helper()
	if artifact.Locator != request.Locator || artifact.MediaType != request.MediaType ||
		artifact.Size != int64(len(request.Body)) || artifact.SHA256 != checksum || !bytes.Equal(artifact.Body, request.Body) {
		t.Fatalf("Artifact = %#v", artifact)
	}
}

func requireDeadline(t *testing.T, ctx context.Context) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
		t.Fatalf("context deadline = %v, %v", deadline, ok)
	}
}
