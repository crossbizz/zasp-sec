package gatewayenrollmentcustody

import (
	"os"
	"path/filepath"
	"strings"
)

// pinExportParent preserves the original no-symlink walk and additionally checks
// every pinned ancestor against the protected association namespace inode. This
// reserves nested and directory-alias destinations without scanning histories.
func (s *Store) pinExportParent(path string) (*os.Root, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", ErrUnavailable
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || strings.HasPrefix(name, ".zasp-") || len(name) > 255 {
		return nil, "", ErrUnavailable
	}
	var forbidden os.FileInfo
	if s.associationRoot != nil {
		var e error
		forbidden, e = s.associationRoot.Stat(".")
		if e != nil || !s.associationNamespaceValid() {
			return nil, "", ErrUnavailable
		}
	}
	allowed := func(root *os.Root) bool {
		info, e := root.Stat(".")
		return e == nil && (forbidden == nil || !os.SameFile(info, forbidden))
	}
	root, e := os.OpenRoot(string(filepath.Separator))
	if e != nil {
		return nil, "", ErrUnavailable
	}
	if !allowed(root) {
		root.Close()
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
		if oe != nil || ae != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !allowed(next) {
			next.Close()
			return nil, "", ErrUnavailable
		}
		root = next
	}
	return root, name, nil
}
