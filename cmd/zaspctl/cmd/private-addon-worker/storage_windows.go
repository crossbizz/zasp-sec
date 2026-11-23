package main

import (
	"errors"
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/privatewin"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func openReportSecret(path string) (*os.File, error) { return privatewin.Open(path, false) }
func pinnedDirectory(root *os.Root) (*os.File, error) {
	f, err := privatewin.Open(root.Name(), true)
	if err != nil {
		return nil, err
	}
	a, err := f.Stat()
	b, rootErr := root.Stat(".")
	if err != nil || rootErr != nil || !os.SameFile(a, b) {
		f.Close()
		return nil, errors.New("marker directory changed")
	}
	return f, nil
}
func privateSpool(root *os.Root) bool {
	f, err := pinnedDirectory(root)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
func claimGrant(root *os.Root, id string) error { return persistFile(root, id+".claiming", id, nil) }

// FlushFileBuffers on a read-only directory handle does not perform a durable
// publication on Windows. Publish within one pinned directory with the native
// write-through rename. Omitting REPLACE_EXISTING also enforces one-time use.
func publishName(root *os.Root, from, to string) error {
	dir, err := pinnedDirectory(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	name := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(dir.Fd()), &name[0], uint32(len(name)), 0)
	if err != nil || n == 0 || n >= uint32(len(name)) {
		return errors.New("private directory identity unavailable")
	}
	path := windows.UTF16ToString(name[:n])
	src, err := windows.UTF16PtrFromString(filepath.Join(path, from))
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(filepath.Join(path, to))
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(src, dst, windows.MOVEFILE_WRITE_THROUGH)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return os.ErrExist
	}
	return err
}
