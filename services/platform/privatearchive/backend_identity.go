package privatearchive

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

// BindJournal prevents a reconfigured bucket, local volume, or encryption key
// from producing false "deleted" receipts for the previous storage destination.
// The caller holds this directory's exclusive process lock.
func BindJournal(root *os.Root, scope, identity string) error {
	if _, err := ParseScope(scope); err != nil || root == nil || identity == "" {
		return ErrRejected
	}
	fingerprint := sha256.Sum256([]byte("zasp.private-retention-journal.v1\x00" + scope + "\x00" + identity))
	want := hex.EncodeToString(fingerprint[:])
	data, err := root.ReadFile(".backend")
	if err == nil {
		if string(data) != want {
			return ErrRejected
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	d, err := root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer d.Close()
	for {
		rows, e := d.ReadDir(64)
		for _, row := range rows {
			if strings.HasSuffix(row.Name(), ".json") {
				return ErrRejected
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return ErrUnavailable
		}
	}
	return writeIdentity(root, ".backend", []byte(want))
}
func writeIdentity(root *os.Root, name string, v []byte) error {
	f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrUnavailable
	}
	_, w := f.Write(v)
	s := f.Sync()
	c := f.Close()
	if errors.Join(w, s, c) != nil {
		return ErrUnavailable
	}
	return syncRootDir(root, ".")
}
func LocalIdentity(root *os.Root, key []byte) (string, error) {
	if root == nil || len(key) != 32 {
		return "", ErrRejected
	}
	raw, e := root.ReadFile(".store-identity")
	if errors.Is(e, os.ErrNotExist) {
		raw = make([]byte, 32)
		if _, e := rand.Read(raw); e != nil {
			return "", ErrUnavailable
		}
		if e := writeIdentity(root, ".store-identity", raw); e != nil {
			return "", e
		}
	} else if e != nil {
		return "", ErrUnavailable
	}
	if len(raw) != 32 {
		return "", ErrRejected
	}
	sig := sha256.New()
	sig.Write([]byte("zasp.local-private-store.v1"))
	sig.Write(raw)
	sig.Write(key)
	return "local:" + hex.EncodeToString(sig.Sum(nil)), nil
}
