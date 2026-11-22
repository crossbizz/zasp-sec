package privatearchive

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
)

// EncryptedLocal is a staging-only backend. The object body is AES-256-GCM
// sealed with the full scoped object key as associated data.
type EncryptedLocal struct {
	Root   *os.Root
	scope  string
	cipher cipher.AEAD
}

func NewEncryptedLocal(root *os.Root, scope string, key []byte) (*EncryptedLocal, error) {
	if _, e := ParseScope(scope); e != nil || root == nil || len(key) != 32 {
		return nil, ErrRejected
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrRejected
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	return &EncryptedLocal{root, scope, a}, nil
}
func (l *EncryptedLocal) Lookup(ctx context.Context, b Binding) (string, bool, error) {
	if b.Scope != l.scope || !b.Valid() || ctx.Err() != nil {
		return "", false, ErrRejected
	}
	f, e := l.Root.Open(b.Key())
	if errors.Is(e, os.ErrNotExist) {
		return "", false, nil
	}
	if e != nil {
		return "", false, ErrUnavailable
	}
	defer f.Close()
	meta, e := f.Stat()
	if e != nil || !meta.Mode().IsRegular() || meta.Mode().Perm()&0077 != 0 || meta.Size() != b.Size+int64(l.cipher.NonceSize()+l.cipher.Overhead()) {
		return "", false, ErrUnavailable
	}
	c, e := io.ReadAll(io.LimitReader(f, meta.Size()+1))
	if e != nil || int64(len(c)) != meta.Size() {
		return "", false, ErrUnavailable
	}
	n := l.cipher.NonceSize()
	plain, e := l.cipher.Open(nil, c[:n], c[n:], []byte(b.Key()))
	defer clear(plain)
	if e != nil || !b.Matches(plain) {
		return "", false, ErrUnavailable
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), true, nil
}
func (l *EncryptedLocal) Put(ctx context.Context, b Binding, plain []byte) (string, error) {
	if b.Scope != l.scope || !b.Matches(plain) || ctx.Err() != nil {
		return "", ErrRejected
	}
	if v, ok, e := l.Lookup(ctx, b); e != nil || ok {
		return v, e
	}
	k := b.Key()
	dir := path.Dir(k)
	if e := l.Root.MkdirAll(dir, 0700); e != nil {
		return "", ErrUnavailable
	}
	nonce := make([]byte, l.cipher.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return "", ErrUnavailable
	}
	body := l.cipher.Seal(nonce, nonce, plain, []byte(k))
	// A crash before rename may leave ciphertext; a retry/lookup cleans the
	// fixed temporary path at expiration along with the committed object.
	f, e := l.Root.OpenFile(k+".writing", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return "", ErrUnavailable
	}
	_, w := io.Copy(f, bytes.NewReader(body))
	s := f.Sync()
	c := f.Close()
	if errors.Join(w, s, c) != nil {
		return "", ErrUnavailable
	}
	if e := l.Root.Rename(k+".writing", k); e != nil {
		return "", ErrUnavailable
	}
	if e := syncRootDir(l.Root, dir); e != nil {
		return "", ErrUnavailable
	}
	v, ok, e := l.Lookup(ctx, b)
	if !ok || e != nil {
		return "", ErrUnavailable
	}
	return v, nil
}
func (l *EncryptedLocal) DeleteExact(ctx context.Context, b Binding, version string) error {
	v, ok, e := l.Lookup(ctx, b)
	if e != nil {
		return e
	}
	if ok {
		if v != version {
			return ErrRejected
		}
		if e = l.Root.Remove(b.Key()); e != nil {
			return ErrUnavailable
		}
	}
	if e := l.cleanupTemporary(b); e != nil {
		return e
	}
	_, exists, e := l.Lookup(ctx, b)
	if e != nil || exists {
		return ErrUnavailable
	}
	return nil
}
func (l *EncryptedLocal) cleanupTemporary(b Binding) error {
	if !b.Valid() || b.Scope != l.scope {
		return ErrRejected
	}
	e := l.Root.Remove(b.Key() + ".writing")
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	e = syncRootDir(l.Root, path.Dir(b.Key()))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return e
}
func syncRootDir(root *os.Root, dir string) error {
	f, e := root.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
