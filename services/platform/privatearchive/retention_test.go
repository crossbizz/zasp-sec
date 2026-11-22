package privatearchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const testScope = "pid_00000000-0000-4000-8000-000000000001/pid_00000000-0000-4000-8000-000000000002/pid_00000000-0000-4000-8000-000000000003"
const testGrant = "pid_00000000-0000-4000-8000-000000000004"

func root(t *testing.T) *os.Root {
	t.Helper()
	r, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return r
}
func spec(t *testing.T, now time.Time, body []byte) Binding {
	sum := sha256.Sum256(body)
	return Binding{testScope, testGrant, "sha256:" + hex.EncodeToString(sum[:]), int64(len(body)), now.Add(24 * time.Hour).Unix()}
}

type failCleanup struct {
	Backend
	fail, failLookup bool
}

func (f *failCleanup) DeleteExact(c context.Context, b Binding, v string) error {
	if f.fail {
		return errors.New("held or unavailable")
	}
	return f.Backend.DeleteExact(c, b, v)
}
func (f *failCleanup) Lookup(c context.Context, b Binding) (string, bool, error) {
	if f.failLookup {
		return "", false, ErrUnavailable
	}
	return f.Backend.Lookup(c, b)
}
func TestPrivateArchiveLifecycle(t *testing.T) {
	now := time.Now().UTC()
	data := []byte("private instructions; should never reach local disk as plaintext")
	b := spec(t, now, data)
	encrypted := root(t)
	store, e := NewEncryptedLocal(encrypted, testScope, bytes.Repeat([]byte{33}, 32))
	if e != nil {
		t.Fatal(e)
	}
	back := &failCleanup{Backend: store}
	j := &Journal{Root: root(t), Scope: testScope, Store: back, Now: func() time.Time { return now }}
	ctx := context.Background()
	if _, err := j.Put(ctx, b, []byte("modified")); err == nil {
		t.Fatal("modified bytes accepted")
	}
	other := b
	other.Scope = strings.Replace(b.Scope, "000000000003", "000000000008", 1)
	if _, e := j.Put(ctx, other, data); e == nil {
		t.Fatal("cross scope accepted")
	}
	written, e := j.Put(ctx, b, data)
	if e != nil || written.State != "retained" || written.Version == "" {
		t.Fatal(written, e)
	}
	body, e := encrypted.ReadFile(b.Key())
	if e != nil || bytes.Contains(body, data) {
		t.Fatal("plaintext on disk")
	}
	if !strings.Contains(b.Key(), b.Grant) || !strings.Contains(b.Key(), strings.TrimPrefix(b.Digest, "sha256:")) || !strings.HasSuffix(b.Key(), "/"+fmt.Sprint(b.Size)+".zip") {
		t.Fatal("key missing binding")
	}
	repeated, e := j.Put(ctx, b, data)
	if e != nil || written.Version != repeated.Version {
		t.Fatal("replay drift")
	}
	if e := store.DeleteExact(ctx, b, "wrong-version"); e == nil {
		t.Fatal("unpinned deletion")
	}
	now = now.Add(24*time.Hour + time.Second)
	back.fail = true
	if j.Sweep(ctx) == nil {
		t.Fatal("false deletion after backend refusal")
	}
	r, _ := j.Status(b.Grant)
	if r.State != "cleanup_pending" || r.DeletedAt != nil {
		t.Fatal("false deletion receipt")
	}
	back.fail = false
	back.failLookup = true
	if _, e := j.Delete(ctx, b.Grant); e == nil {
		t.Fatal("delete without affirmative readback")
	}
	// A new process can repeat the pinned delete after an ambiguous first one.
	restart := &Journal{Root: j.Root, Scope: j.Scope, Store: store, Now: j.Now}
	if e := restart.Sweep(ctx); e != nil {
		t.Fatal(e)
	}
	r, e = restart.Status(b.Grant)
	if e != nil || r.State != "deleted" || r.DeletedAt == nil {
		t.Fatal(r, e)
	}
	if _, exists, e := store.Lookup(ctx, b); e != nil || exists {
		t.Fatal("encrypted version survived")
	}
	if _, err := restart.Put(ctx, b, data); err == nil {
		t.Fatal("deleted grant resurrected")
	}
}
func TestRetainedGrantAdmission(t *testing.T) {
	now := time.Now()
	body := []byte("zip")
	b := spec(t, now, body)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	origin := "https://worker.example"
	g := grant{Version: "private-addon-upload-retained.v1", Audience: origin, Scope: b.Scope, Actor: testGrant, ID: b.Grant, Digest: b.Digest, Size: b.Size, Expires: now.Unix() + 300, RetainUntil: b.Deadline}
	token := func(g grant) string {
		raw, _ := json.Marshal(g)
		sig := ed25519.Sign(key, append([]byte("zasp-private-addon-upload.v1\x00"), raw...))
		return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	verify := func(g grant) error {
		_, err := Verify(key.Public().(ed25519.PublicKey), origin, b.Scope, b.Grant, token(g), now)
		return err
	}
	if e := verify(g); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*grant){func(g *grant) { g.Version = "private-addon-upload.v1" }, func(g *grant) { g.Audience += ".invalid" }, func(g *grant) { g.Expires-- }, func(g *grant) { g.RetainUntil++ }, func(g *grant) { g.Scope += "/other" }, func(g *grant) { g.Size = MaxBytes + 1 }} {
		bad := g
		mutate(&bad)
		if verify(bad) == nil {
			t.Fatal("mutated grant accepted")
		}
	}
}

func TestJournalRejectsChangedObjectStoreOrScope(t *testing.T) {
	dir := root(t)
	if e := BindJournal(dir, testScope, "s3/tenant-bucket/original-key"); e != nil {
		t.Fatal(e)
	}
	if BindJournal(dir, testScope, "s3/empty-bucket/original-key") == nil || BindJournal(dir, strings.Replace(testScope, "000000000003", "000000000008", 1), "s3/tenant-bucket/original-key") == nil {
		t.Fatal("different destination could claim previous receipts")
	}
	if e := BindJournal(dir, testScope, "s3/tenant-bucket/original-key"); e != nil {
		t.Fatal("exact reconnect", e)
	}
}
