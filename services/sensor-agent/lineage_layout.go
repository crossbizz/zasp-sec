package main

import (
	"io"
	"os"
	"runtime"
	"syscall"
)

type lineageLayoutEntry struct {
	name     string
	uid, gid uint32
	mode     os.FileMode
	info     os.FileInfo
	complete bool
}

// This initializer receives only the persistent layout mount. It never opens
// product tokens, a provider socket or existing consumer/producer file contents.
// It changes ownership only on an empty, root-owned fixed directory. Existing
// completed directories are left intact, even when they contain retained work.
func initializeLineageLayout(path string, consumerUID uint32) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || consumerUID == 0 || consumerUID > 2147483647 || !validAbsolute(path) {
		return errSensorRuntime
	}
	before, err := os.Lstat(path)
	if err != nil || !validLineageLayoutRoot(before) {
		return errSensorRuntime
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return errSensorRuntime
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return errSensorRuntime
	}
	defer directory.Close()
	validRoot := func() bool {
		held, e := directory.Stat()
		named, n := os.Lstat(path)
		return e == nil && n == nil && validLineageLayoutRoot(held) && validLineageLayoutRoot(named) && os.SameFile(before, held) && os.SameFile(held, named)
	}
	if !validRoot() {
		return errSensorRuntime
	}
	if _, err := scanLineageLayout(root, consumerUID); err != nil {
		return err
	}
	lock, err := root.OpenFile(".layout.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errSensorRuntime
	}
	defer lock.Close()
	validLock := func() bool {
		held, e := lock.Stat()
		named, n := root.Lstat(".layout.lock")
		return e == nil && n == nil && lineageOwnedRegular(held, 0, 0600) && held.Size() == 0 && lineageOwnedRegular(named, 0, 0600) && os.SameFile(held, named)
	}
	if !validRoot() || !validLock() || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || !validLock() {
		return errSensorRuntime
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	entries, err := scanLineageLayout(root, consumerUID)
	if err != nil || !validRoot() || lock.Sync() != nil || directory.Sync() != nil {
		return errSensorRuntime
	}
	for _, entry := range entries {
		if !validRoot() || !validLock() {
			return errSensorRuntime
		}
		if entry.complete {
			// A prior initializer may have stopped after chown but before fsync.
			// Re-establish the inode barrier even for already-correct metadata.
			file, err := root.OpenFile(entry.name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return errSensorRuntime
			}
			err = syncCompletedLineageLayoutEntry(root, file, entry)
			file.Close()
			if err != nil {
				return errSensorRuntime
			}
			continue
		}
		if entry.info == nil {
			if err := root.Mkdir(entry.name, 0700); err != nil {
				return errSensorRuntime
			}
			entry.info, err = root.Lstat(entry.name)
			if err != nil {
				return errSensorRuntime
			}
		}
		file, err := root.OpenFile(entry.name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errSensorRuntime
		}
		err = finishLineageLayoutEntry(root, file, entry)
		file.Close()
		if err != nil || !validRoot() || !validLock() || directory.Sync() != nil {
			return errSensorRuntime
		}
	}
	entries, err = scanLineageLayout(root, consumerUID)
	if err != nil || !validRoot() || !validLock() {
		return errSensorRuntime
	}
	for _, entry := range entries {
		if !entry.complete {
			return errSensorRuntime
		}
	}
	if directory.Sync() != nil {
		return errSensorRuntime
	}
	return nil
}

func syncCompletedLineageLayoutEntry(root *os.Root, file *os.File, entry lineageLayoutEntry) error {
	valid := func() bool {
		held, err := file.Stat()
		named, nameErr := root.Lstat(entry.name)
		return err == nil && nameErr == nil && os.SameFile(entry.info, held) && os.SameFile(held, named) && lineageLayoutMatches(held, entry) && lineageLayoutMatches(named, entry)
	}
	if !valid() || file.Sync() != nil || !valid() {
		return errSensorRuntime
	}
	return nil
}

func validLineageLayoutRoot(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (info.Mode().Perm() != 0755 && info.Mode().Perm() != 0750) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func lineageLayoutMatches(info os.FileInfo, entry lineageLayoutEntry) bool {
	if info == nil || !info.IsDir() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != entry.mode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == entry.uid && stat.Gid == entry.gid
}

func lineageLayoutPartial(info os.FileInfo, entry lineageLayoutEntry) bool {
	if info == nil || !info.IsDir() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (info.Mode().Perm() != 0700 && info.Mode().Perm() != entry.mode) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && (stat.Gid == uint32(os.Getegid()) || stat.Gid == entry.gid)
}

func scanLineageLayout(root *os.Root, consumerUID uint32) ([]lineageLayoutEntry, error) {
	entries := []lineageLayoutEntry{{name: "producer", uid: 0, gid: consumerUID, mode: 0750}, {name: "acks", uid: consumerUID, gid: consumerUID, mode: 0750}, {name: "consumer", uid: consumerUID, gid: consumerUID, mode: 0700}}
	file, err := root.Open(".")
	if err != nil {
		return nil, errSensorRuntime
	}
	names, err := file.Readdirnames(5)
	file.Close()
	if err != nil && err != io.EOF || len(names) > 4 {
		return nil, errSensorRuntime
	}
	for _, name := range names {
		info, err := root.Lstat(name)
		if err != nil {
			return nil, errSensorRuntime
		}
		if name == ".layout.lock" {
			if !lineageOwnedRegular(info, 0, 0600) || info.Size() != 0 {
				return nil, errSensorRuntime
			}
			continue
		}
		found := false
		for index := range entries {
			entry := &entries[index]
			if entry.name != name {
				continue
			}
			found = true
			entry.info = info
			entry.complete = lineageLayoutMatches(info, *entry)
			if entry.complete {
				break
			}
			if !lineageLayoutPartial(info, *entry) {
				return nil, errSensorRuntime
			}
			child, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return nil, errSensorRuntime
			}
			held, statErr := child.Stat()
			contents, readErr := child.Readdirnames(1)
			child.Close()
			if statErr != nil || !os.SameFile(info, held) || len(contents) != 0 || readErr != io.EOF {
				return nil, errSensorRuntime
			}
			break
		}
		if !found {
			return nil, errSensorRuntime
		}
	}
	return entries, nil
}

func finishLineageLayoutEntry(root *os.Root, file *os.File, entry lineageLayoutEntry) error {
	held, err := file.Stat()
	named, nameErr := root.Lstat(entry.name)
	contents, readErr := file.Readdirnames(1)
	if err != nil || nameErr != nil || !os.SameFile(entry.info, held) || !os.SameFile(held, named) || !lineageLayoutPartial(held, entry) || len(contents) != 0 || readErr != io.EOF {
		return errSensorRuntime
	}
	if file.Chmod(entry.mode) != nil || file.Chown(int(entry.uid), int(entry.gid)) != nil || file.Sync() != nil {
		return errSensorRuntime
	}
	held, err = file.Stat()
	named, nameErr = root.Lstat(entry.name)
	if err != nil || nameErr != nil || !os.SameFile(entry.info, held) || !os.SameFile(held, named) || !lineageLayoutMatches(held, entry) || !lineageLayoutMatches(named, entry) {
		return errSensorRuntime
	}
	return nil
}
