package gatewayenrollmentcustody

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// pinParent walks the existing directory tree without adopting a symlink. No
// parent ownership, permissions, creation or mutation is performed.
func pinParent(path string) (*os.Root, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", ErrUnavailable
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || strings.HasPrefix(name, ".zasp-") || len(name) > 255 {
		return nil, "", ErrUnavailable
	}
	root, e := os.OpenRoot(string(filepath.Separator))
	if e != nil {
		return nil, "", ErrUnavailable
	}
	relative, e := filepath.Rel(string(filepath.Separator), filepath.Dir(path))
	if e != nil {
		root.Close()
		return nil, "", ErrUnavailable
	}
	if relative == "." {
		return root, name, nil
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		before, e := root.Lstat(part)
		if e != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, "", ErrUnavailable
		}
		next, e := root.OpenRoot(part)
		if e != nil {
			root.Close()
			return nil, "", ErrUnavailable
		}
		opened, oe := next.Stat(".")
		after, ae := root.Lstat(part)
		root.Close()
		if oe != nil || ae != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 {
			next.Close()
			return nil, "", ErrUnavailable
		}
		root = next
	}
	return root, name, nil
}
func readExactFile(root *os.Root, name string, links uint64) ([]byte, error) {
	before, e := root.Lstat(name)
	if e != nil || !safeInfo(before, links) || before.Size() < 1 || before.Size() > 16384 {
		return nil, ErrUnavailable
	}
	file, e := root.OpenFile(name, os.O_RDONLY|noFollowFlags(), 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	opened, e := file.Stat()
	if e != nil || !safeInfo(opened, links) || !os.SameFile(before, opened) {
		return nil, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(file, 16385))
	if e != nil || len(raw) == 0 || len(raw) > 16384 {
		return nil, ErrUnavailable
	}
	after, ae := root.Lstat(name)
	descriptor, de := file.Stat()
	if ae != nil || de != nil || !safeInfo(after, links) || !safeInfo(descriptor, links) || !os.SameFile(opened, after) || !os.SameFile(opened, descriptor) || opened.Size() != descriptor.Size() || int64(len(raw)) != descriptor.Size() {
		clear(raw)
		return nil, ErrUnavailable
	}
	return raw, nil
}

// readRecoverable accepts precisely one durable name or the expected two names
// of one link-publication inode. Arbitrary extra hardlinks are not adopted.
func readRecoverable(root *os.Root, name string) ([]byte, bool, error) {
	final, fe := root.Lstat(name)
	stageName := publicationStage(name)
	stage, se := root.Lstat(stageName)
	finalAbsent, stageAbsent := errors.Is(fe, os.ErrNotExist), errors.Is(se, os.ErrNotExist)
	if finalAbsent && stageAbsent {
		return nil, false, nil
	}
	if fe != nil && !finalAbsent || se != nil && !stageAbsent {
		return nil, false, ErrUnavailable
	}
	switch {
	case !finalAbsent && !stageAbsent:
		if !safeInfo(final, 2) || !safeInfo(stage, 2) || !os.SameFile(final, stage) {
			return nil, false, ErrUnavailable
		}
		raw, e := readExactFile(root, name, 2)
		if e != nil {
			return nil, false, ErrUnavailable
		}
		staged, e := readExactFile(root, stageName, 2)
		if e != nil || !bytes.Equal(raw, staged) {
			clear(raw)
			clear(staged)
			return nil, false, ErrUnavailable
		}
		clear(staged)
		return raw, true, nil
	case !finalAbsent:
		raw, e := readExactFile(root, name, 1)
		return raw, e == nil, e
	default:
		raw, e := readExactFile(root, stageName, 1)
		return raw, e == nil, e
	}
}
func syncDirectory(root *os.Root) error {
	dir, e := root.Open(".")
	if e != nil {
		return ErrUnavailable
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
}
func syncExisting(root *os.Root, name string) error {
	file, e := root.OpenFile(name, os.O_RDWR|noFollowFlags(), 0)
	if e != nil {
		return ErrUnavailable
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
}

// publish has one exclusive primitive: rooted Link. Every failure leaves all
// key-bearing paths intact. It never replaces a destination or deletes partial
// staging data. The caller holds the common stable logical-basename guard.
func publish(root *os.Root, name string, expected []byte) error {
	if root == nil || len(expected) == 0 || len(expected) > 16384 {
		return ErrUnavailable
	}
	existing, present, e := readRecoverable(root, name)
	if e != nil || present && !bytes.Equal(existing, expected) {
		return ErrUnavailable
	}
	clear(existing)
	stage := publicationStage(name)
	if !present {
		file, e := root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollowFlags(), 0600)
		if e != nil {
			return ErrUnavailable
		}
		info, e := file.Stat()
		path, pe := root.Lstat(stage)
		if e != nil || pe != nil || !safeInfo(info, 1) || !safeInfo(path, 1) || !os.SameFile(info, path) {
			file.Close()
			return ErrUnavailable
		}
		count, we := file.Write(expected)
		syncErr := file.Sync()
		closeErr := file.Close()
		if we != nil || count != len(expected) || syncErr != nil || closeErr != nil {
			return ErrUnavailable
		}
		if syncDirectory(root) != nil {
			return ErrUnavailable
		}
	}
	final, fe := root.Lstat(name)
	if errors.Is(fe, os.ErrNotExist) {
		staged, e := readExactFile(root, stage, 1)
		if e != nil || !bytes.Equal(staged, expected) {
			clear(staged)
			return ErrUnavailable
		}
		clear(staged)
		if syncExisting(root, stage) != nil || syncDirectory(root) != nil {
			return ErrUnavailable
		}
		if e = root.Link(stage, name); e != nil {
			return ErrUnavailable
		}
	} else if fe != nil || !final.Mode().IsRegular() {
		return ErrUnavailable
	}
	current, present, e := readRecoverable(root, name)
	if e != nil || !present || !bytes.Equal(current, expected) {
		clear(current)
		return ErrUnavailable
	}
	clear(current)
	if syncExisting(root, name) != nil || syncDirectory(root) != nil {
		return ErrUnavailable
	}
	staged, se := root.Lstat(stage)
	if se == nil {
		final, fe = root.Lstat(name)
		if fe != nil || !safeInfo(final, 2) || !safeInfo(staged, 2) || !os.SameFile(final, staged) {
			return ErrUnavailable
		}
		if root.Remove(stage) != nil {
			return ErrUnavailable
		}
		if syncDirectory(root) != nil {
			return ErrUnavailable
		}
	} else if !errors.Is(se, os.ErrNotExist) {
		return ErrUnavailable
	}
	current, e = readExactFile(root, name, 1)
	if e != nil || !bytes.Equal(current, expected) {
		clear(current)
		return ErrUnavailable
	}
	clear(current)
	return nil
}
