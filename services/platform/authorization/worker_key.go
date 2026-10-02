package authorization

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func (WorkerKey) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[worker authorization key]"))
}

func (WorkerDecision) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[worker authorization decision]"))
}

// LoadWorkerKeyFile accepts only a bounded, pinned, owner-read-only regular
// file. It has no environment fallback and never returns a path-bearing error.
func LoadWorkerKeyFile(purpose WorkerPurpose, path string) (*WorkerKey, error) {
	if purpose != WorkerForward && purpose != CapturedCompensation || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || before.Size() < 32 || before.Size() > 4096 {
		return nil, ErrInvalid
	}
	// Match the platform's pinned-file consumers: a FIFO substituted after
	// Lstat must not block Open, and a symlink must never be followed.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o400 || !os.SameFile(before, opened) || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		_ = file.Close()
		return nil, ErrInvalid
	}
	seed, readErr := io.ReadAll(io.LimitReader(file, 4097))
	defer clear(seed)
	closeErr := file.Close()
	after, afterErr := os.Lstat(path)
	if readErr != nil || closeErr != nil || afterErr != nil || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 || !os.SameFile(opened, after) || before.Size() != after.Size() || before.Size() != int64(len(seed)) || !before.ModTime().Equal(after.ModTime()) {
		return nil, ErrInvalid
	}
	return NewWorkerKey(purpose, seed)
}
