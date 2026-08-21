package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

var gatewayEvidenceFilePattern = regexp.MustCompile(`^(LOCK|MANIFEST|MANIFEST-REWRITE|KEYREGISTRY|REWRITE-KEYREGISTRY|DISCARD|[0-9]{5}\.mem|[0-9]{6}\.(sst|vlog))$`)

func (store *gatewayEvidenceDiskStore) validDirectoryLocked() bool {
	if !store.validDirectoryIdentityLocked() {
		return false
	}
	_, _, ok := gatewayEvidenceDirectorySnapshot(store.root)
	return ok
}

func (store *gatewayEvidenceDiskStore) secureDirectoryFilesLocked() bool {
	if !store.validDirectoryIdentityLocked() {
		return false
	}
	directory, err := store.root.Open(".")
	if err != nil {
		return false
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return false
	}
	changed := false
	for _, entry := range entries {
		name := entry.Name()
		before, err := store.root.Lstat(name)
		if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || !gatewayEvidenceFilePattern.MatchString(name) {
			return false
		}
		if before.Mode().Perm() != 0o600 {
			if store.root.Chmod(name, 0o600) != nil {
				return false
			}
			changed = true
		}
		after, err := store.root.Lstat(name)
		if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 || after.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return !changed || syncGatewayEvidenceRoot(store.root) == nil
}

func gatewayEvidenceDirectorySnapshot(root *os.Root) (map[string]os.FileInfo, uint64, bool) {
	if root == nil {
		return nil, 0, false
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, 0, false
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return nil, 0, false
	}
	snapshot := make(map[string]os.FileInfo, len(entries))
	var total uint64
	for _, entry := range entries {
		name := entry.Name()
		before, err := root.Lstat(name)
		if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Mode()&os.ModeSymlink != 0 || !gatewayEvidenceFilePattern.MatchString(name) || before.Size() < 0 {
			return nil, 0, false
		}
		opened, openErr := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, 0, false
		}
		openedInfo, statErr := opened.Stat()
		closeErr := opened.Close()
		after, afterErr := root.Lstat(name)
		if statErr != nil || closeErr != nil || afterErr != nil || !os.SameFile(before, openedInfo) || !os.SameFile(openedInfo, after) || after.Mode().Perm() != 0o600 || after.Mode()&os.ModeSymlink != 0 {
			return nil, 0, false
		}
		size := uint64(after.Size())
		if stat, ok := after.Sys().(*syscall.Stat_t); ok && stat.Blocks >= 0 {
			blocks := uint64(stat.Blocks)
			if blocks > ^uint64(0)/512 {
				return nil, 0, false
			}
			size = blocks * 512
		}
		if total > ^uint64(0)-size {
			return nil, 0, false
		}
		total += size
		snapshot[name] = after
	}
	return snapshot, total, true
}

func secureNewGatewayEvidenceFiles(root *os.Root, existing map[string]os.FileInfo) bool {
	if root == nil {
		return false
	}
	directory, err := root.Open(".")
	if err != nil {
		return false
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return false
	}
	changed := false
	for _, entry := range entries {
		name := entry.Name()
		if _, found := existing[name]; found {
			continue
		}
		before, err := root.Lstat(name)
		if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || !gatewayEvidenceFilePattern.MatchString(name) {
			return false
		}
		if before.Mode().Perm() != 0o600 {
			if root.Chmod(name, 0o600) != nil {
				return false
			}
			changed = true
		}
		after, err := root.Lstat(name)
		if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 || after.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return !changed || syncGatewayEvidenceRoot(root) == nil
}

func (store *gatewayEvidenceDiskStore) validDirectoryIdentityLocked() bool {
	if store.parent == nil || store.root == nil || store.directory == nil || store.parentName == "" {
		return false
	}
	before, err := store.parent.Lstat(store.parentName)
	opened, openErr := store.root.Stat(".")
	fileInfo, fileErr := store.directory.Stat()
	if err != nil || openErr != nil || fileErr != nil || !before.IsDir() || before.Mode().Perm() != 0o700 || before.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, fileInfo) {
		return false
	}
	return true
}

func openGatewayEvidenceDirectory(path string) (*os.Root, *os.Root, *os.File, string, string, error) {
	parent, name, err := openGatewayEvidenceRoot(path)
	if err != nil {
		return nil, nil, nil, "", "", errGatewayRuntime
	}
	if info, err := parent.Lstat(name); errors.Is(err, os.ErrNotExist) {
		if parent.Mkdir(name, 0o700) != nil || syncGatewayEvidenceRoot(parent) != nil {
			_ = parent.Close()
			return nil, nil, nil, "", "", errGatewayRuntime
		}
	} else if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		_ = parent.Close()
		return nil, nil, nil, "", "", errGatewayRuntime
	}
	before, err := parent.Lstat(name)
	root, openErr := parent.OpenRoot(name)
	if err != nil || openErr != nil {
		_ = parent.Close()
		return nil, nil, nil, "", "", errGatewayRuntime
	}
	opened, statErr := root.Stat(".")
	after, afterErr := parent.Lstat(name)
	if statErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || after.Mode().Perm() != 0o700 || after.Mode()&os.ModeSymlink != 0 {
		_ = root.Close()
		_ = parent.Close()
		return nil, nil, nil, "", "", errGatewayRuntime
	}
	if err := ensureGatewayEvidenceLock(root); err != nil {
		_ = root.Close()
		_ = parent.Close()
		return nil, nil, nil, "", "", errGatewayRuntime
	}
	directory, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		_ = parent.Close()
		return nil, nil, nil, "", "", errGatewayRuntime
	}
	pinnedPath, err := gatewayEvidencePinnedPath(directory, path)
	if err != nil {
		_ = directory.Close()
		_ = root.Close()
		_ = parent.Close()
		return nil, nil, nil, "", "", errGatewayRuntime
	}
	return parent, root, directory, name, pinnedPath, nil
}

func openGatewayEvidenceRoot(path string) (*os.Root, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", errGatewayRuntime
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return nil, "", errGatewayRuntime
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, "", errGatewayRuntime
	}
	relative, err := filepath.Rel(string(filepath.Separator), filepath.Dir(path))
	if err != nil {
		_ = root.Close()
		return nil, "", errGatewayRuntime
	}
	if relative == "." {
		return root, name, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		before, err := root.Lstat(component)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			_ = root.Close()
			return nil, "", errGatewayRuntime
		}
		child, err := root.OpenRoot(component)
		if err != nil {
			_ = root.Close()
			return nil, "", errGatewayRuntime
		}
		opened, openErr := child.Stat(".")
		after, afterErr := root.Lstat(component)
		_ = root.Close()
		if openErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || after.Mode()&os.ModeSymlink != 0 {
			_ = child.Close()
			return nil, "", errGatewayRuntime
		}
		root = child
	}
	return root, name, nil
}

func ensureGatewayEvidenceLock(root *os.Root) error {
	if info, err := root.Lstat("LOCK"); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
			return errGatewayRuntime
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errGatewayRuntime
	}
	file, err := root.OpenFile("LOCK", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errGatewayRuntime
	}
	if file.Close() != nil || syncGatewayEvidenceRoot(root) != nil {
		return errGatewayRuntime
	}
	return nil
}

func syncGatewayEvidenceRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return errGatewayRuntime
	}
	defer file.Close()
	if file.Sync() != nil {
		return errGatewayRuntime
	}
	return nil
}

func gatewayEvidencePinnedPath(directory *os.File, originalPath string) (string, error) {
	if directory == nil {
		return "", errGatewayRuntime
	}
	expected, err := directory.Stat()
	if err != nil || !expected.IsDir() {
		return "", errGatewayRuntime
	}
	if runtime.GOOS == "linux" {
		path := filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(directory.Fd()), 10))
		actual, err := os.Stat(path)
		if err == nil && os.SameFile(expected, actual) {
			return path, nil
		}
	}
	if runtime.GOOS == "darwin" {
		actual, err := os.Stat(originalPath)
		if err == nil && os.SameFile(expected, actual) {
			return originalPath, nil
		}
	}
	return "", errGatewayRuntime
}
