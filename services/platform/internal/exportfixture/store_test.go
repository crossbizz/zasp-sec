package exportfixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const kms = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"

func fixture(t *testing.T) (*Store, Config) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := Config{filepath.Join(parent, "export-store"), "zasp-compliance-exports", "123456789012", kms, 8 << 20}
	s, err := Create(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, c
}
func client(s *Store, o Options) *s3.Client {
	return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: s.Transport(o)}, Retryer: aws.NopRetryer{}})
}
func bounded(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func put(ctx context.Context, c *s3.Client, key, body string) (*s3.PutObjectOutput, error) {
	h := sha256.Sum256([]byte(body))
	return c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("zasp-compliance-exports"), Key: aws.String(key), Body: bytes.NewReader([]byte(body)), ContentType: aws.String("application/json"), IfNoneMatch: aws.String("*"), ExpectedBucketOwner: aws.String("123456789012"), ServerSideEncryption: "aws:kms", SSEKMSKeyId: aws.String(kms), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(h[:])), Metadata: map[string]string{"scope": "retained"}})
}
func get(ctx context.Context, c *s3.Client, key, version string) (*s3.GetObjectOutput, error) {
	return c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("zasp-compliance-exports"), Key: aws.String(key), VersionId: aws.String(version), ExpectedBucketOwner: aws.String("123456789012")})
}
func code(err error) string {
	var e smithy.APIError
	if errors.As(err, &e) {
		return e.ErrorCode()
	}
	return ""
}

// Collapsing all keys into one object or accepting a duplicate PUT loses this proof.
func TestStoreScopesRestartAndConditionalWrite(t *testing.T) {
	s, cfg := fixture(t)
	ctx := bounded(t)
	c := client(s, Options{})
	keys := []string{"org-a/work-a/env-a/exports/one", "org-b/work-b/env-b/exports/two"}
	versions := []string{}
	for i, k := range keys {
		r, err := put(ctx, c, k, []string{"{\"tenant\":\"a\"}", "{\"tenant\":\"b\"}"}[i])
		if err != nil {
			t.Fatal(err)
		}
		versions = append(versions, aws.ToString(r.VersionId))
	}
	if _, err := put(ctx, c, keys[0], "changed"); code(err) != "PreconditionFailed" {
		t.Fatalf("retry=%v", err)
	}
	_ = s.Close()
	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	objects, err := s2.Objects(ctx)
	if err != nil || len(objects) != 2 {
		t.Fatalf("objects=%v err=%v", objects, err)
	}
	for i, k := range keys {
		r, err := get(ctx, client(s2, Options{ReadOnly: true}), k, versions[i])
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(b) != []string{"{\"tenant\":\"a\"}", "{\"tenant\":\"b\"}"}[i] {
			t.Fatalf("foreign bytes=%s", b)
		}
	}
	entries, err := s2.Requests(ctx)
	if err != nil || len(entries) < 9 {
		t.Fatalf("missing durable log=%v %v", entries, err)
	}
}

func TestStoreExactDeleteAndReadOnly(t *testing.T) {
	s, _ := fixture(t)
	ctx := bounded(t)
	c := client(s, Options{})
	r, err := put(ctx, c, "a/exports/one", "one")
	if err != nil {
		t.Fatal(err)
	}
	v := aws.ToString(r.VersionId)
	if _, err = put(ctx, client(s, Options{ReadOnly: true}), "a/exports/two", "two"); err == nil {
		t.Fatal("read-only wrote")
	}
	if _, err = get(ctx, c, "a/exports/one", ""); err == nil {
		t.Fatal("unpinned GET")
	}
	if _, err = get(ctx, c, "a/exports/one", "foreign"); code(err) != "NoSuchVersion" {
		t.Fatalf("wrong version=%v", err)
	}
	_, err = c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("zasp-compliance-exports"), Key: aws.String("a/exports/one"), VersionId: aws.String(v), ExpectedBucketOwner: aws.String("123456789012")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = get(ctx, c, "a/exports/one", v); code(err) != "NoSuchVersion" {
		t.Fatalf("absence=%v", err)
	}
	if _, err = put(ctx, c, "a/exports/one", "replacement"); code(err) != "PreconditionFailed" {
		t.Fatal("deleted immutable identity reused", err)
	}
}

func TestStoreAfterWriteLossAndBarrier(t *testing.T) {
	s, _ := fixture(t)
	ctx := bounded(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	c := client(s, Options{After: func(ctx context.Context, r Request) *Fault {
		if r.Method == "PUT" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return &Fault{Err: errors.New("lost response")}
		}
		return nil
	}})
	go func() { _, err := put(ctx, c, "a/exports/one", "persisted"); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("barrier never entered")
	}
	objects, err := s.Objects(ctx)
	if err != nil || len(objects) != 1 || string(objects[0].Body) != "persisted" {
		t.Fatal("PUT not durable before barrier", err)
	}
	close(release)
	if <-done == nil {
		t.Fatal("lost reply accepted")
	}
	if _, err = put(ctx, client(s, Options{}), "a/exports/one", "persisted"); code(err) != "PreconditionFailed" {
		t.Fatal("lost write repeated", err)
	}
}

func TestStoreConcurrentHandles(t *testing.T) {
	s, cfg := fixture(t)
	other, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx := bounded(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*Store{s, other} {
		wg.Add(1)
		go func(st *Store) {
			defer wg.Done()
			_, e := put(ctx, client(st, Options{}), "a/exports/one", "identical")
			results <- e
		}(store)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if code(e) == "PreconditionFailed" {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}

func TestStoreRefusesUnsafePathsSizeAndCleanup(t *testing.T) {
	s, cfg := fixture(t)
	ctx := bounded(t)
	for _, key := range []string{"../exports/x", "a/../exports/x", "a//exports/x", "a/exports/../../x"} {
		if _, err := put(ctx, client(s, Options{}), key, "bad"); err == nil {
			t.Fatal("unsafe key accepted", key)
		}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/a", nil)
	if _, err := s.Transport(Options{}).RoundTrip(req); err == nil {
		t.Fatal("external host accepted")
	}
	req, _ = http.NewRequest("GET", "https://controlled.invalid/a", nil)
	if _, err := s.Transport(Options{}).RoundTrip(req); err == nil {
		t.Fatal("unbounded request accepted")
	}
	if _, err := put(ctx, client(s, Options{}), "a/exports/huge", string(bytes.Repeat([]byte("x"), int(cfg.MaximumBytes)+1))); err == nil {
		t.Fatal("oversize accepted")
	}
	other, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = other.Remove(); err == nil {
		t.Fatal("borrower removed store")
	}
	other.Close()
	if err = s.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(cfg.Directory); !os.IsNotExist(err) {
		t.Fatal("owned directory retained", err)
	}
}

func TestStoreRejectsSymlinkState(t *testing.T) {
	s, cfg := fixture(t)
	outside := filepath.Join(filepath.Dir(cfg.Directory), "outside")
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.Directory, "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cfg.Directory, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Objects(bounded(t)); err == nil {
		t.Fatal("symlink state read")
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "untouched" {
		t.Fatal("outside changed")
	}
}

// The real artifact store checks SDK HEAD/GET metadata after both first PUT and
// conditional replay. This catches a transport that only works with raw SDK calls.
func TestStoreProductDriverAndExactCleanup(t *testing.T) {
	s, _ := fixture(t)
	ctx := bounded(t)
	config := s3driver.Config{Bucket: "zasp-compliance-exports", ExpectedBucketOwner: "123456789012", KMSKeyARN: kms, MaximumBytes: 8 << 20}
	driver, err := s3driver.NewExport(client(s, Options{}), config)
	if err != nil {
		t.Fatal(err)
	}
	product, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	ids := []domain.ProductID{}
	for _, id := range []string{"pid_00000000-0000-4000-8000-000000000001", "pid_00000000-0000-4000-8000-000000000002", "pid_00000000-0000-4000-8000-000000000003"} {
		parsed, e := domain.ParseProductID(id)
		if e != nil {
			t.Fatal(e)
		}
		ids = append(ids, parsed)
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	ref, err := domain.ParseEvidenceRef("pid_00000000-0000-4000-8000-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	request := artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/json", Body: []byte(`{"frozen":"source"}`)}
	first, err := product.Put(ctx, request)
	if err != nil {
		t.Fatal("real store PUT", err)
	}
	second, err := product.Put(ctx, request)
	if err != nil || first.VersionID != second.VersionID {
		t.Fatal("conditional retry", err)
	}
	readerDriver, err := s3driver.NewExport(client(s, Options{ReadOnly: true}), config)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := artifactstore.NewExport(readerDriver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Get(ctx, first.Locator)
	if err != nil || !bytes.Equal(got.Body, request.Body) {
		t.Fatal("real read", err)
	}
	objects, err := s.Objects(ctx)
	if err != nil || len(objects) != 1 {
		t.Fatal("versions", err)
	}
	cleanup, err := s3driver.NewExportCleanup(client(s, Options{After: func(_ context.Context, r Request) *Fault {
		if r.Method == "DELETE" {
			return &Fault{Err: errors.New("lost DELETE reply")}
		}
		return nil
	}}), config)
	if err != nil {
		t.Fatal(err)
	}
	if err = cleanup.DeleteExact(ctx, artifactstore.DriverLocator{Scope: scope, Reference: ref, Key: objects[0].Key, VersionID: first.VersionID}); err != nil {
		t.Fatal("typed absence after lost DELETE", err)
	}
	if _, err = reader.Get(ctx, first.Locator); err == nil {
		t.Fatal("deleted package readable")
	}
	entries, err := s.Requests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	attempts, created, deletes := 0, 0, 0
	for i, r := range entries {
		if r.Sequence != int64(i+1) {
			t.Fatal("unordered log")
		}
		if r.Method == "PUT" && r.Stage == "before" {
			attempts++
		}
		if r.Method == "PUT" && r.Stage == "stored" && r.Status == 200 {
			created++
		}
		if r.Method == "DELETE" && r.Stage == "stored" && r.Status == 204 {
			deletes++
		}
	}
	if attempts != 2 || created != 1 || deletes != 1 {
		t.Fatalf("attempts=%d creations=%d deletes=%d", attempts, created, deletes)
	}
}

func TestStoreFaultsAndCancelledBarrier(t *testing.T) {
	s, _ := fixture(t)
	ctx := bounded(t)
	c := client(s, Options{})
	p, err := put(ctx, c, "a/exports/one", "frozen")
	if err != nil {
		t.Fatal(err)
	}
	version := aws.ToString(p.VersionId)
	denied := client(s, Options{Before: func(_ context.Context, r Request) *Fault {
		if r.Method == "DELETE" {
			return &Fault{StatusCode: 403, Code: "AccessDenied"}
		}
		return nil
	}})
	if _, err = denied.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("zasp-compliance-exports"), Key: aws.String("a/exports/one"), VersionId: &version, ExpectedBucketOwner: aws.String("123456789012")}); code(err) != "AccessDenied" {
		t.Fatal(err)
	}
	got, err := get(ctx, c, "a/exports/one", version)
	if err != nil {
		t.Fatal("denied delete lost bytes", err)
	}
	got.Body.Close()
	entered := make(chan struct{})
	cancelCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := get(cancelCtx, client(s, Options{Before: func(ctx context.Context, r Request) *Fault {
			close(entered)
			<-ctx.Done()
			return &Fault{Err: ctx.Err()}
		}}), "a/exports/one", version)
		done <- e
	}()
	select {
	case <-entered:
		cancel()
	case <-ctx.Done():
		t.Fatal("barrier not reached")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled read succeeded")
		}
	case <-ctx.Done():
		t.Fatal("cancelled caller not joined")
	}
	corrupt, err := get(ctx, client(s, Options{After: func(_ context.Context, r Request) *Fault { return &Fault{Body: []byte("changed")} }}), "a/exports/one", version)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(corrupt.Body)
	corrupt.Body.Close()
	if string(body) != "changed" {
		t.Fatal("fault body missing")
	}
	objects, _ := s.Objects(ctx)
	if string(objects[0].Body) != "frozen" {
		t.Fatal("response corruption changed stored version")
	}
}

func TestStorePinnedHeadAndDeleteBoundaries(t *testing.T) {
	s, _ := fixture(t)
	ctx := bounded(t)
	c := client(s, Options{})
	p, err := put(ctx, c, "a/exports/one", "one")
	if err != nil {
		t.Fatal(err)
	}
	v := aws.ToString(p.VersionId)
	for _, tc := range []struct {
		name, version string
		readOnly      bool
		allowed       bool
	}{{"writer discovery", "", false, true}, {"reader current key", "", true, false}, {"reader exact", v, true, true}, {"reader foreign", "foreign", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := client(s, Options{ReadOnly: tc.readOnly}).HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("zasp-compliance-exports"), Key: aws.String("a/exports/one"), VersionId: aws.String(tc.version), ExpectedBucketOwner: aws.String("123456789012")})
			if (e == nil) != tc.allowed {
				t.Fatal("HEAD authority", e)
			}
		})
	}
	for _, tc := range []struct {
		version  string
		readOnly bool
	}{{"", false}, {v, true}, {"foreign", false}} {
		_, e := client(s, Options{ReadOnly: tc.readOnly}).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("zasp-compliance-exports"), Key: aws.String("a/exports/one"), VersionId: aws.String(tc.version), ExpectedBucketOwner: aws.String("123456789012")})
		if e == nil {
			t.Fatal("invalid DELETE succeeded")
		}
	}
	got, err := get(ctx, c, "a/exports/one", v)
	if err != nil {
		t.Fatal("wrong DELETE removed current version", err)
	}
	got.Body.Close()
}

func TestStoreCrossProcess(t *testing.T) {
	if raw := os.Getenv("ZASP_EXPORT_STORE_CHILD_CONFIG"); raw != "" {
		var cfg Config
		if json.Unmarshal([]byte(raw), &cfg) != nil {
			t.Fatal("child config")
		}
		s, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		_, err = put(bounded(t), client(s, Options{}), "cross-process/exports/one", "frozen")
		if err == nil {
			t.Log("write=created")
		} else if code(err) == "PreconditionFailed" {
			t.Log("write=conditional-conflict")
		} else {
			t.Fatal(err)
		}
		return
	}
	s, cfg := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	results := make(chan string, 2)
	failures := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestStoreCrossProcess$", "-test.v", "-test.timeout=10s")
			cmd.Env = append(os.Environ(), "ZASP_EXPORT_STORE_CHILD_CONFIG="+string(raw))
			out, e := cmd.CombinedOutput()
			results <- string(out)
			failures <- e
		}()
	}
	created, conflict := 0, 0
	for i := 0; i < 2; i++ {
		output := <-results
		if strings.Contains(output, "write=created") {
			created++
		}
		if strings.Contains(output, "write=conditional-conflict") {
			conflict++
		}
		t.Log(output)
	}
	for i := 0; i < 2; i++ {
		if e := <-failures; e != nil {
			t.Fatal(e)
		}
	}
	objects, err := s.Objects(ctx)
	if err != nil || len(objects) != 1 || created != 1 || conflict != 1 {
		t.Fatalf("process objects=%d created=%d conflicts=%d err=%v", len(objects), created, conflict, err)
	}
}

func TestStoreOwnershipAndDiskSafety(t *testing.T) {
	s, cfg := fixture(t)
	if _, err := Create(cfg); err == nil {
		t.Fatal("recreated existing owned store")
	}
	wrong := cfg
	wrong.Owner = "foreign"
	if _, err := Open(wrong); err == nil {
		t.Fatal("opened foreign config")
	}
	parent := filepath.Dir(cfg.Directory)
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(cfg.Directory, alias); err != nil {
		t.Fatal(err)
	}
	wrong = cfg
	wrong.Directory = alias
	if _, err := Open(wrong); err == nil {
		t.Fatal("symlink root opened")
	}
	for _, name := range []string{"requests.jsonl", "lock", "owner.json"} {
		t.Run(name, func(t *testing.T) {
			local, c := fixture(t)
			outside := filepath.Join(filepath.Dir(c.Directory), "external")
			if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(c.Directory, name)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(c.Directory, name)); err != nil {
				t.Fatal(err)
			}
			if name == "owner.json" {
				if _, err := Open(c); err == nil {
					t.Fatal("symlink owner read")
				}
			} else if _, err := local.Requests(bounded(t)); err == nil {
				t.Fatal("symlink file accepted")
			}
			if err := local.Remove(); err == nil {
				t.Fatal("unsafe cleanup accepted")
			}
			raw, _ := os.ReadFile(outside)
			if string(raw) != "secret" {
				t.Fatal("outside modified")
			}
		})
	}
	if err := os.WriteFile(filepath.Join(cfg.Directory, "unexpected"), []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(); err == nil {
		t.Fatal("unexpected owned-root entry deleted")
	}
}

func TestStoreDeleteErasesOnlyExactBytes(t *testing.T) {
	s, _ := fixture(t)
	ctx := bounded(t)
	c := client(s, Options{})
	one, err := put(ctx, c, "tenant-a/exports/one", "erase-this-artifact")
	if err != nil {
		t.Fatal(err)
	}
	two, err := put(ctx, c, "tenant-b/exports/two", "retain-this-artifact")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("zasp-compliance-exports"), Key: aws.String("tenant-a/exports/one"), VersionId: one.VersionId, ExpectedBucketOwner: aws.String("123456789012")})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := s.Objects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 {
		t.Fatal("immutable tombstone lost")
	}
	for _, object := range objects {
		if object.Key == "tenant-a/exports/one" {
			if !object.Deleted || len(object.Body) != 0 || len(object.Headers) != 0 {
				t.Fatal("deleted object bytes remain in snapshot")
			}
		} else if object.Key == "tenant-b/exports/two" {
			if object.Deleted || string(object.Body) != "retain-this-artifact" || object.VersionID != aws.ToString(two.VersionId) {
				t.Fatal("foreign object changed")
			}
		} else {
			t.Fatal("unexpected object")
		}
	}
}
