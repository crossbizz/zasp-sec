//go:build linux

package gatewaypodidentity

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Reopen every time to observe operator rotation. No file bytes or OS error
// messages escape the verifier. The parent directory is operator trust.
func reviewerCredential(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrDenied
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrDenied
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil {
		return nil, ErrDenied
	}
	native, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || stat.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || native.Uid != uint32(os.Getuid()) || native.Nlink != 1 || stat.Size() < 1 || stat.Size() > 16384 {
		return nil, ErrDenied
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16385))
	after, e2 := f.Stat()
	pathStat, e3 := os.Lstat(path)
	// Both snapshots must retain the original safe ownership and metadata. A
	// same inode alone does not establish that the final pathname is protected.
	stable := func(current os.FileInfo) bool {
		if current == nil {
			return false
		}
		n, ok := current.Sys().(*syscall.Stat_t)
		return ok && os.SameFile(stat, current) && current.Mode() == stat.Mode() && current.Size() == stat.Size() && current.ModTime().Equal(stat.ModTime()) && n.Uid == native.Uid && n.Gid == native.Gid && n.Nlink == 1 && n.Mode == native.Mode && n.Ctim == native.Ctim && n.Mtim == native.Mtim
	}
	if e != nil || e2 != nil || e3 != nil || !stable(after) || !stable(pathStat) || int64(len(raw)) != stat.Size() || !bearer(raw, 16384) {
		clear(raw)
		return nil, ErrDenied
	}

	return raw, nil
}
