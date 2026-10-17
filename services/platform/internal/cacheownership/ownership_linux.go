//go:build linux

package cacheownership

import (
	"errors"
	"os"
	"syscall"
)

func platformSupported() bool { return true }
func safeFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}
func acquirePlatform(root *os.Root, name string) (*Guard, error) {
	before, err := root.Lstat(name)
	existing := err == nil
	if existing && !safeFile(before) || err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	var file *os.File
	if existing {
		file, err = root.OpenFile(name, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	} else {
		file, err = root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if errors.Is(err, os.ErrExist) {
			return nil, ErrUnavailable
		}
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	fail := func() (*Guard, error) { file.Close(); return nil, ErrUnavailable }
	descriptor, err := file.Stat()
	if err != nil || !safeFile(descriptor) || existing && !os.SameFile(before, descriptor) {
		return fail()
	}
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail()
	}
	path, err := root.Lstat(name)
	if err != nil || !safeFile(path) || !os.SameFile(descriptor, path) {
		return fail()
	}
	return &Guard{root: root, file: file, name: name}, nil
}
