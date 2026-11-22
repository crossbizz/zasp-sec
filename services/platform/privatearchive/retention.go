// Package privatearchive manages explicitly consented private static-scan
// inputs for a single Environment. The journal holds metadata only.
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
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const MaxBytes int64 = 8 << 20

var ErrRejected = errors.New("retained archive binding rejected")
var ErrUnavailable = errors.New("retained archive storage unavailable")
var digestPattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")

type Binding struct {
	Scope    string `json:"scope"`
	Grant    string `json:"grant_id"`
	Digest   string `json:"archive_digest"`
	Size     int64  `json:"archive_bytes"`
	Deadline int64  `json:"retain_until"`
}

func ParseScope(s string) (domain.Scope, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 3 {
		return domain.Scope{}, ErrRejected
	}
	var ids [3]domain.ProductID
	for i, part := range parts {
		id, err := domain.ParseProductID(part)
		if err != nil {
			return domain.Scope{}, ErrRejected
		}
		ids[i] = id
	}
	return domain.NewScope(ids[0], ids[1], ids[2])
}
func (b Binding) Valid() bool {
	_, e := ParseScope(b.Scope)
	_, i := domain.ParseProductID(b.Grant)
	return e == nil && i == nil && digestPattern.MatchString(b.Digest) && b.Size > 0 && b.Size <= MaxBytes && b.Deadline > 0
}
func (b Binding) Key() string {
	if !b.Valid() {
		return ""
	}
	s := strings.Split(b.Scope, "/")
	return fmt.Sprintf("organizations/%s/workspaces/%s/environments/%s/private-addons/%s/%s/%d.zip", s[0], s[1], s[2], b.Grant, strings.TrimPrefix(b.Digest, "sha256:"), b.Size)
}

func (b Binding) Matches(body []byte) bool {
	if !b.Valid() || int64(len(body)) != b.Size {
		return false
	}
	sum := sha256.Sum256(body)
	return b.Digest == "sha256:"+hex.EncodeToString(sum[:])
}

type grant struct {
	Version     string `json:"version"`
	Audience    string `json:"audience"`
	Scope       string `json:"scope"`
	Actor       string `json:"actor"`
	ID          string `json:"id"`
	Digest      string `json:"sha256"`
	Size        int64  `json:"size"`
	Expires     int64  `json:"expires"`
	Registry    bool   `json:"registry,omitempty"`
	RetainUntil int64  `json:"retain_until"`
}

// Verify repeats the signed audience, scope and lifetime checks at the storage
// process; a scanner or local socket client cannot authorize retention.
func Verify(key ed25519.PublicKey, origin, scope, id, token string, now time.Time) (Binding, error) {
	var g grant
	if len(key) != ed25519.PublicKeySize || len(token) > 3072 {
		return Binding{}, ErrRejected
	}
	a, b, ok := strings.Cut(token, ".")
	raw, e := base64.RawURLEncoding.Strict().DecodeString(a)
	sig, f := base64.RawURLEncoding.Strict().DecodeString(b)
	if !ok || e != nil || f != nil || !ed25519.Verify(key, append([]byte("zasp-private-addon-upload.v1\x00"), raw...), sig) {
		return Binding{}, ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&g) != nil || d.Decode(&struct{}{}) != io.EOF {
		return Binding{}, ErrRejected
	}
	spec := Binding{g.Scope, g.ID, g.Digest, g.Size, g.RetainUntil}
	_, actorErr := domain.ParseProductID(g.Actor)
	if !spec.Valid() || actorErr != nil || g.Version != "private-addon-upload-retained.v1" || g.Audience != origin || g.Scope != scope || g.ID != id || g.Expires <= now.Unix() || g.Expires > now.Add(5*time.Minute).Unix() || g.RetainUntil != g.Expires+int64((24*time.Hour-5*time.Minute)/time.Second) {
		return Binding{}, ErrRejected
	}
	return spec, nil
}

// Lookup proves presence and recovers an unacknowledged immutable write.
// Absent is authoritative for all versions of this unique private object key.
type Backend interface {
	Put(context.Context, Binding, []byte) (string, error)
	Lookup(context.Context, Binding) (version string, present bool, err error)
	DeleteExact(context.Context, Binding, string) error
}
type Record struct {
	Binding
	State        string     `json:"state"`
	Version      string     `json:"storage_version,omitempty"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
	DeleteReason string     `json:"delete_reason,omitempty"`
	RequestedAt  *time.Time `json:"delete_requested_at,omitempty"`
}
type Journal struct {
	Root  *os.Root
	Scope string
	Store Backend
	Now   func() time.Time
	mu    sync.Mutex
}

func (j *Journal) read(id string) (Record, error) {
	var r Record
	if _, e := domain.ParseProductID(id); e != nil {
		return r, ErrRejected
	}
	f, e := j.Root.Open(id + ".json")
	if e != nil {
		return r, e
	}
	defer f.Close()
	m, e := f.Stat()
	if e != nil || !m.Mode().IsRegular() || m.Mode().Perm()&0077 != 0 || m.Size() > 4096 {
		return r, ErrRejected
	}
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(&struct{}{}) != io.EOF || !r.Binding.Valid() || r.Grant != id || r.Scope != j.Scope {
		return Record{}, ErrRejected
	}
	switch r.State {
	case "writing", "retained", "cleanup_pending", "deleted":
	default:
		return Record{}, ErrRejected
	}
	return r, nil
}
func (j *Journal) save(r Record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	temp := r.Grant + ".tmp"
	f, err := j.Root.OpenFile(temp, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, w := f.Write(raw)
	syncErr := f.Sync()
	c := f.Close()
	if err := errors.Join(w, syncErr, c); err != nil {
		return err
	}
	if err := j.Root.Rename(temp, r.Grant+".json"); err != nil {
		return err
	}
	d, err := j.Root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (j *Journal) Put(ctx context.Context, b Binding, body []byte) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if b.Scope != j.Scope || !b.Matches(body) || !j.Now().Before(time.Unix(b.Deadline, 0)) {
		return Record{}, ErrRejected
	}
	old, err := j.read(b.Grant)
	if err == nil {
		if old.Binding != b || old.State == "deleted" || old.State == "cleanup_pending" {
			return Record{}, ErrRejected
		}
		if old.State == "retained" {
			v, present, e := j.Store.Lookup(ctx, b)
			if e != nil || !present || v != old.Version {
				return Record{}, ErrUnavailable
			}
			return old, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrUnavailable
	}
	r := Record{Binding: b, State: "writing"}
	if err := j.save(r); err != nil {
		return Record{}, ErrUnavailable
	}
	v, err := j.Store.Put(ctx, b, body)
	if err != nil || !safeVersion(v) {
		return Record{}, ErrUnavailable
	}
	r.State, r.Version = "retained", v
	if err := j.save(r); err != nil {
		return Record{}, ErrUnavailable
	}
	return r, nil
}
func safeVersion(v string) bool {
	return len(v) > 0 && len(v) <= 1024 && v != "null" && !strings.ContainsAny(v, "\r\n\x00")
}
func (j *Journal) Status(id string) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.read(id)
}

// Verify checks the retained version's bytes and binding without exposing its contents.
func (j *Journal) Verify(ctx context.Context, id string) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, err := j.read(id)
	if err != nil {
		return Record{}, err
	}
	if r.State != "retained" || !j.Now().Before(time.Unix(r.Deadline, 0)) {
		return Record{}, ErrRejected
	}
	v, exists, err := j.Store.Lookup(ctx, r.Binding)
	if err != nil || !exists || v != r.Version {
		return Record{}, ErrUnavailable
	}
	return r, nil
}
func (j *Journal) Delete(ctx context.Context, id string) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, e := j.read(id)
	if e != nil {
		return Record{}, e
	}
	return j.remove(ctx, r, "operator_requested")
}
func (j *Journal) remove(ctx context.Context, r Record, reason string) (Record, error) {
	if r.State == "deleted" {
		return r, nil
	}
	if r.RequestedAt == nil {
		stamp := j.Now().UTC()
		r.RequestedAt = &stamp
		r.DeleteReason = reason
	}
	r.State = "cleanup_pending"
	if e := j.save(r); e != nil {
		return r, ErrUnavailable
	}
	if r.Version == "" {
		v, exists, e := j.Store.Lookup(ctx, r.Binding)
		if e != nil {
			return r, ErrUnavailable
		}
		if exists {
			if !safeVersion(v) {
				return r, ErrUnavailable
			}
			r.Version = v
			if e := j.save(r); e != nil {
				return r, ErrUnavailable
			}
		}
	}
	if r.Version != "" && j.Store.DeleteExact(ctx, r.Binding, r.Version) != nil {
		return r, ErrUnavailable
	}
	// Remove interrupted staging ciphertext even if a final version was never published.
	if local, ok := j.Store.(*EncryptedLocal); ok {
		if err := local.cleanupTemporary(r.Binding); err != nil {
			return r, ErrUnavailable
		}
	}
	// Verify all versions as well. A delete marker or denied listing cannot prove erasure.
	if _, exists, e := j.Store.Lookup(ctx, r.Binding); e != nil || exists {
		return r, ErrUnavailable
	}
	stamp := j.Now().UTC()
	r.State = "deleted"
	r.DeletedAt = &stamp
	if e := j.save(r); e != nil {
		return r, ErrUnavailable
	}
	return r, nil
}

// Sweep processes bounded pages without retaining the whole directory in memory.
// A failed object leaves a durable retry and does not block other expirations.
func (j *Journal) Sweep(ctx context.Context) error {
	d, e := j.Root.Open(".")
	if e != nil {
		return e
	}
	defer d.Close()
	var failed bool
	for {
		entries, readErr := d.ReadDir(64)
		for _, entry := range entries {
			id, ok := strings.CutSuffix(entry.Name(), ".json")
			if !ok {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			j.mu.Lock()
			r, e := j.read(id)
			if e == nil && r.State != "deleted" && (r.State == "cleanup_pending" || !j.Now().Before(time.Unix(r.Deadline, 0))) {
				_, e = j.remove(ctx, r, "retention_expired")
			}
			j.mu.Unlock()
			if e != nil {
				failed = true
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if failed {
		return ErrUnavailable
	}
	return nil
}
