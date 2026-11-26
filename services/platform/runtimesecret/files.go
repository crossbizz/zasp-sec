// Package runtimesecret reads private startup credentials from file projections.
package runtimesecret

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func trustedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func trustedParents(path string) bool {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || !trustedOwner(info) || info.Mode().Perm()&0022 != 0 && (dir == filepath.Dir(path) || info.Mode()&os.ModeSticky == 0) {
			return false
		}
		if dir == filepath.Dir(dir) {
			return true
		}
	}
}

func ReadPrivateFile(path string, limit int64) ([]byte, error) {
	return readFile(path, limit, 0077)
}

// ReadTrustFile permits a public CA bundle while protecting it against modification.
func ReadTrustFile(path string, limit int64) ([]byte, error) {
	return readFile(path, limit, 0022)
}

func readFile(path string, limit int64, forbidden os.FileMode) ([]byte, error) {
	invalid := errors.New("invalid protected credential file")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") || !trustedParents(path) {
		return nil, invalid
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !trustedParents(real) {
		return nil, invalid
	}
	// Allow administrator-managed atomic projections. Open the resolved path
	// without following a replacement symlink or blocking on a FIFO.
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, invalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !trustedOwner(info) || info.Mode().Perm()&forbidden != 0 || info.Size() < 1 || info.Size() > limit {
		return nil, invalid
	}
	value, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(value) == 0 || int64(len(value)) > limit {
		clear(value)
		return nil, invalid
	}
	return value, nil
}

// FromFiles resolves explicitly named overrides once at startup. An explicit
// file and a direct value are mutually exclusive. Existing validators remain
// responsible for the format and meaning of every value.
func FromFiles(getenv func(string) string, names ...string) (func(string) string, error) {
	resolved := make(map[string]string)
	for _, name := range names {
		path := getenv(name + "_FILE")
		if path == "" {
			continue
		}
		if getenv(name) != "" {
			return nil, errors.New(name + " and " + name + "_FILE are mutually exclusive")
		}
		value, err := ReadPrivateFile(path, 16385)
		if err != nil {
			return nil, errors.New("invalid " + name + "_FILE")
		}
		value = bytes.TrimSuffix(value, []byte("\n"))
		if len(value) == 0 || bytes.ContainsAny(value, "\r\n\x00") {
			clear(value)
			return nil, errors.New("invalid " + name + "_FILE value")
		}
		resolved[name] = string(value)
		clear(value)
	}
	return func(name string) string {
		if value, ok := resolved[name]; ok {
			return value
		}
		return getenv(name)
	}, nil
}
