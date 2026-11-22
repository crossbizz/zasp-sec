// Package skillfixture defines the only supported synthetic skill workspaces.
// Customer archives and their contents can never select executable code.
package skillfixture

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/privatearchive"
)

const schema = "zasp.synthetic-skill-fixture.v1"
const Control = "declared"
const Difference = "undeclared-local-socket"
const MaxDuration = 60 * time.Second

var ErrRefused = errors.New("synthetic fixture unavailable")
var capabilities = []string{"file.read", "process.exec", "local_socket.connect"}

func declarations(name string) ([]string, bool) {
	switch name {
	case Control:
		return slices.Clone(capabilities), true
	case Difference:
		return slices.Clone(capabilities[:2]), true
	default:
		return nil, false
	}
}

// Archive produces one reproducible ZIP. The attack-lab runner and retention
// service compute the same byte identity. The ZIP has a declaration and marker
// only. The executable for exercising it is part of the released runner image.
func Archive(name string) ([]byte, error) {
	declared, ok := declarations(name)
	if !ok {
		return nil, ErrRefused
	}
	spec, err := json.Marshal(struct {
		Schema       string   `json:"schema"`
		Capabilities []string `json:"capabilities"`
	}{schema, declared})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"SKILL.md", []byte("# Zasp synthetic skill fixture\nFixed local file, process and Unix socket exercise.\n")}, {"zasp-fixture.json", spec}} {
		h := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		h.SetMode(0600)
		f, err := w.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err = f.Write(entry.body); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func identity(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func known(digest string, size int64) (string, bool) {
	for _, name := range []string{Control, Difference} {
		b, err := Archive(name)
		if err == nil && int64(len(b)) == size && identity(b) == digest {
			return name, true
		}
	}
	return "", false
}

type Claim struct {
	Schema    string                 `json:"schema"`
	Binding   privatearchive.Binding `json:"archive"`
	Fixture   string                 `json:"fixture"`
	IssuedAt  int64                  `json:"issued_at"`
	ExpiresAt int64                  `json:"expires_at"`
}
type Handoff struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func Sign(key ed25519.PrivateKey, r privatearchive.Record, now time.Time) (Handoff, error) {
	name, ok := known(r.Digest, r.Size)
	if len(key) != ed25519.PrivateKeySize || !ok || !r.Binding.Valid() || r.State != "retained" || r.Version == "" || r.Deadline <= now.Unix() {
		return Handoff{}, ErrRefused
	}
	claim := Claim{schema, r.Binding, name, now.Unix(), min(now.Add(MaxDuration).Unix(), r.Deadline)}
	raw, err := json.Marshal(claim)
	if err != nil {
		return Handoff{}, err
	}
	return Handoff{raw, ed25519.Sign(key, raw)}, nil
}
func Verify(key ed25519.PublicKey, scope string, input io.Reader, now time.Time) (Claim, error) {
	var h Handoff
	if Parse(input, &h) != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, h.Payload, h.Signature) {
		return Claim{}, ErrRefused
	}
	var c Claim
	if Parse(bytes.NewReader(h.Payload), &c) != nil || c.Schema != schema || c.Binding.Scope != scope || !c.Binding.Valid() || c.IssuedAt > now.Unix() || c.ExpiresAt <= now.Unix() || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt > c.IssuedAt+int64(MaxDuration/time.Second) || c.ExpiresAt > c.Binding.Deadline {
		return Claim{}, ErrRefused
	}
	name, ok := known(c.Binding.Digest, c.Binding.Size)
	if !ok || c.Fixture != name {
		return Claim{}, ErrRefused
	}
	return c, nil
}
func Parse(in io.Reader, out any) error {
	content, err := io.ReadAll(io.LimitReader(in, 4097))
	if err != nil || len(content) > 4096 {
		return ErrRefused
	}
	d := json.NewDecoder(bytes.NewReader(content))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(&struct{}{}) != io.EOF {
		return ErrRefused
	}
	return nil
}

type Result struct {
	Schema        string    `json:"schema"`
	ArchiveDigest string    `json:"archive_digest"`
	Scope         string    `json:"scope"`
	Grant         string    `json:"grant_id"`
	Fixture       string    `json:"fixture"`
	Status        string    `json:"status"`
	Declared      []string  `json:"declared"`
	Observed      []string  `json:"observed"`
	Undeclared    []string  `json:"undeclared"`
	Missing       []string  `json:"missing"`
	CompletedAt   time.Time `json:"completed_at"`
}

func result(c Claim, seen []string, complete bool, now time.Time) Result {
	declared, _ := declarations(c.Fixture)
	r := Result{Schema: "zasp.synthetic-skill-result.v1", ArchiveDigest: c.Binding.Digest, Scope: c.Binding.Scope, Grant: c.Binding.Grant, Fixture: c.Fixture, Status: "inconclusive", Declared: declared, Observed: slices.Clone(seen), Undeclared: []string{}, Missing: []string{}, CompletedAt: now.UTC()}
	for _, v := range seen {
		if !slices.Contains(declared, v) {
			r.Undeclared = append(r.Undeclared, v)
		}
	}
	for _, v := range declared {
		if !slices.Contains(seen, v) {
			r.Missing = append(r.Missing, v)
		}
	}
	if complete && now.Unix() < c.ExpiresAt {
		r.Status = "matches_declarations"
		if len(r.Undeclared)+len(r.Missing) > 0 {
			r.Status = "declaration_difference"
		}
	}
	return r
}
