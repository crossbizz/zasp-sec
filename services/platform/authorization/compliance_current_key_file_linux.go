package authorization

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

type complianceCurrentHeldDirectory struct {
	fd, parent int
	name       string
	stat       syscall.Stat_t
}
type heldComplianceCurrentKeyFile struct {
	directories          []complianceCurrentHeldDirectory
	leaf                 *os.File
	leafName             string
	leafStat             syscall.Stat_t
	owner                int
	read, closed, failed bool
	closeErr             error
}

const complianceCurrentDirectoryOpenFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
const complianceCurrentLeafOpenFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

func complianceCurrentKeyStatEqual(a, b *syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Rdev == b.Rdev && a.Size == b.Size && a.Blksize == b.Blksize && a.Blocks == b.Blocks && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func complianceCurrentKeyStatAdmissible(st *syscall.Stat_t, owner int) bool {
	return st != nil && owner >= 0 && uint64(owner) <= uint64(^uint32(0)) && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&07777 == 0400 && st.Uid == uint32(owner) && st.Nlink == 1 && st.Size >= 32 && st.Size <= 4096
}
func complianceCurrentKeyFileAdmissible(fi os.FileInfo, owner int) bool {
	if fi == nil || !fi.Mode().IsRegular() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && complianceCurrentKeyStatAdmissible(st, owner)
}
func holdComplianceCurrentKeyFile(path string) (*heldComplianceCurrentKeyFile, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 || !utf8.ValidString(path) {
		return nil, ErrInvalid
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 1 || len(parts) > 256 {
		return nil, ErrInvalid
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, ErrInvalid
		}
	}
	h := &heldComplianceCurrentKeyFile{owner: os.Geteuid(), leafName: parts[len(parts)-1]}
	fail := func() (*heldComplianceCurrentKeyFile, error) {
		h.failed = true
		_ = h.validateAndClose()
		return nil, ErrInvalid
	}
	root, err := syscall.Open("/", complianceCurrentDirectoryOpenFlags, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	node := complianceCurrentHeldDirectory{fd: root, parent: -1}
	if syscall.Fstat(root, &node.stat) != nil || node.stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(root)
		return nil, ErrInvalid
	}
	h.directories = append(h.directories, node)
	parent := root
	for _, name := range parts[:len(parts)-1] {
		fd, err := syscall.Openat(parent, name, complianceCurrentDirectoryOpenFlags, 0)
		if err != nil {
			return fail()
		}
		node := complianceCurrentHeldDirectory{fd: fd, parent: parent, name: name}
		if syscall.Fstat(fd, &node.stat) != nil || node.stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			_ = syscall.Close(fd)
			return fail()
		}
		h.directories = append(h.directories, node)
		parent = fd
	}
	fd, err := syscall.Openat(parent, h.leafName, complianceCurrentLeafOpenFlags, 0)
	if err != nil {
		return fail()
	}
	h.leaf = os.NewFile(uintptr(fd), "compliance-current-key")
	if h.leaf == nil {
		_ = syscall.Close(fd)
		return fail()
	}
	if syscall.Fstat(fd, &h.leafStat) != nil || !complianceCurrentKeyStatAdmissible(&h.leafStat, h.owner) {
		return fail()
	}
	if h.validate() != nil {
		return fail()
	}
	return h, nil
}
func (h *heldComplianceCurrentKeyFile) validate() error {
	if h == nil || h.closed || h.leaf == nil || len(h.directories) == 0 {
		return ErrInvalid
	}
	for _, node := range h.directories {
		var held syscall.Stat_t
		if syscall.Fstat(node.fd, &held) != nil || !complianceCurrentKeyStatEqual(&node.stat, &held) {
			return ErrInvalid
		}
		var fd int
		var err error
		if node.parent == -1 {
			fd, err = syscall.Open("/", complianceCurrentDirectoryOpenFlags, 0)
		} else {
			fd, err = syscall.Openat(node.parent, node.name, complianceCurrentDirectoryOpenFlags, 0)
		}
		if err != nil {
			return ErrInvalid
		}
		var named syscall.Stat_t
		statErr := syscall.Fstat(fd, &named)
		closeErr := syscall.Close(fd)
		if statErr != nil || closeErr != nil || !complianceCurrentKeyStatEqual(&node.stat, &named) {
			return ErrInvalid
		}
	}
	var held syscall.Stat_t
	if syscall.Fstat(int(h.leaf.Fd()), &held) != nil || !complianceCurrentKeyStatAdmissible(&held, h.owner) || !complianceCurrentKeyStatEqual(&h.leafStat, &held) {
		return ErrInvalid
	}
	parent := h.directories[len(h.directories)-1].fd
	fd, err := syscall.Openat(parent, h.leafName, complianceCurrentLeafOpenFlags, 0)
	if err != nil {
		return ErrInvalid
	}
	var named syscall.Stat_t
	statErr := syscall.Fstat(fd, &named)
	closeErr := syscall.Close(fd)
	if statErr != nil || closeErr != nil || !complianceCurrentKeyStatAdmissible(&named, h.owner) || !complianceCurrentKeyStatEqual(&h.leafStat, &named) {
		return ErrInvalid
	}
	return nil
}
func (h *heldComplianceCurrentKeyFile) readSeed() ([]byte, error) {
	if h == nil || h.closed || h.read || h.failed {
		return nil, ErrInvalid
	}
	h.read = true
	if h.validate() != nil {
		h.failed = true
		return nil, ErrInvalid
	}
	seed, err := io.ReadAll(io.LimitReader(h.leaf, 4097))
	if err != nil || int64(len(seed)) != h.leafStat.Size || h.validate() != nil {
		clear(seed)
		h.failed = true
		return nil, ErrInvalid
	}
	return seed, nil
}
func (h *heldComplianceCurrentKeyFile) validateAndClose() error {
	if h == nil {
		return ErrInvalid
	}
	if h.closed {
		return h.closeErr
	}
	if h.failed || h.leaf == nil || h.validate() != nil {
		h.closeErr = ErrInvalid
	}
	// All owned descriptors close even when validation fails. No retry of close
	// can accidentally affect a reused descriptor number.
	if h.leaf != nil {
		if h.leaf.Close() != nil {
			h.closeErr = ErrInvalid
		}
		h.leaf = nil
	}
	for i := len(h.directories) - 1; i >= 0; i-- {
		if syscall.Close(h.directories[i].fd) != nil {
			h.closeErr = ErrInvalid
		}
	}
	h.directories = nil
	h.closed = true
	return h.closeErr
}
