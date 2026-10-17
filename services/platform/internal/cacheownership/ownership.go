// Package cacheownership coordinates cooperating cache owners under an already
// pinned directory. It does not protect against a malicious directory owner or
// another process with the same UID that ignores this protocol.
package cacheownership

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var ErrUnavailable = errors.New("cache ownership unavailable")

type Guard struct {
	mu   sync.Mutex
	root *os.Root
	file *os.File
	name string
}

func Supported() bool { return platformSupported() }

// Acquire uses a stable sibling lock, independent of the replaceable cache
// inode. It never truncates, renames, removes, or changes an existing lock.
func Acquire(root *os.Root, basename string) (*Guard, error) {
	if root == nil || basename == "" || basename == "." || basename == ".." || !filepath.IsLocal(basename) || filepath.Base(basename) != basename || strings.ContainsAny(basename, "/\\\x00") || len(basename) > 255 {
		return nil, ErrUnavailable
	}
	sum := sha256.Sum256([]byte(basename))
	return acquirePlatform(root, ".zasp-cache-ownership-"+hex.EncodeToString(sum[:])+".lock")
}

// Valid rechecks both the held descriptor and its current sibling pathname.
// Once the pathname is replaced it no longer represents exclusive ownership.
func (g *Guard) Valid() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.file == nil || g.root == nil {
		return false
	}
	descriptor, err := g.file.Stat()
	if err != nil || !safeFile(descriptor) {
		return false
	}
	path, err := g.root.Lstat(g.name)
	return err == nil && safeFile(path) && os.SameFile(descriptor, path)
}

// Close releases only the held descriptor; the stable sibling remains in place.
func (g *Guard) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.file == nil {
		return nil
	}
	file := g.file
	g.file = nil
	g.root = nil
	if file.Close() != nil {
		return ErrUnavailable
	}
	return nil
}
