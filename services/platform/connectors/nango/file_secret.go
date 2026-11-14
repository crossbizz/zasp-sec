package nango

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileServiceSecretResolver reads the Nango service key from a file mounted
// into the process (a Kubernetes secret volume). It answers for exactly one
// service secret reference.
type FileServiceSecretResolver struct {
	path      string
	reference string
}

// NewFileServiceSecretResolver accepts an absolute, clean path whose base
// name is "service-key" and the reference the file stands for.
func NewFileServiceSecretResolver(path, reference string) (*FileServiceSecretResolver, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "service-key" || strings.Contains(path, "..") || !referencePattern.MatchString(reference) {
		return nil, ErrInvalid
	}
	return &FileServiceSecretResolver{path: path, reference: reference}, nil
}

// Resolve returns the key. The file must be a regular file of 16 to 4096
// bytes that only its owner, or its owner and group, may read.
func (resolver *FileServiceSecretResolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	if resolver == nil || resolver.path == "" || ctx == nil || ctx.Err() != nil || reference != resolver.reference {
		return nil, ErrInvalid
	}
	file, err := os.Open(resolver.path)
	if err != nil {
		return nil, ErrProxy
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 16 || info.Size() > 4096 || info.Mode().Perm() != 0o400 && info.Mode().Perm() != 0o440 {
		return nil, ErrProxy
	}
	value, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(value) > 4096 || ctx.Err() != nil || !validServiceSecret(value) {
		clear(value)
		return nil, ErrProxy
	}
	return value, nil
}

var _ ServiceSecretResolver = (*FileServiceSecretResolver)(nil)
