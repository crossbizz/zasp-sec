package main

import (
	"io"
	"os"
	"regexp"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"golang.org/x/sys/unix"
)

var projectedTokenVersionPattern = regexp.MustCompile(`^\.\.[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}\.[0-9]{1,20}$`)

// Kubernetes publishes a Secret by replacing ..data, not the visible key link.
// Pin only the volume between sends. Resolve and verify a fresh version on each
// read; never retain a credential when a publication is missing or invalid.
// The caller holds reader.mu. This mode is only for the Linux, root-owned,
// read-only Secret volume with defaultMode 0440 and fsGroup equal to consumer UID.
func readProjectedLineageTokenLocked(reader *tokenReader, owner uint32) ([]byte, error) {
	if owner == 0 || owner != uint32(os.Geteuid()) || reader.name != "token" {
		return nil, errSensorRuntime
	}
	parent, err := reader.root.Open(".")
	if err != nil {
		return nil, errSensorRuntime
	}
	defer parent.Close()
	parentInfo, err := parent.Stat()
	if err != nil || !projectedTokenDirectory(parentInfo, owner, false) || !projectedTokenReadOnly(parent) || !projectedTokenRootBound(reader.root, parentInfo) {
		return nil, errSensorRuntime
	}
	visible, err := projectedTokenLink(reader.root, "token", "..data/token")
	if err != nil {
		return nil, errSensorRuntime
	}
	version, err := reader.root.Readlink("..data")
	if err != nil || !projectedTokenVersionPattern.MatchString(version) {
		return nil, errSensorRuntime
	}
	publication, err := projectedTokenLink(reader.root, "..data", version)
	if err != nil {
		return nil, errSensorRuntime
	}
	versionInfo, err := reader.root.Lstat(version)
	if err != nil || !projectedTokenDirectory(versionInfo, owner, true) || !projectedTokenSameDevice(parentInfo, versionInfo) {
		return nil, errSensorRuntime
	}
	versionRoot, err := reader.root.OpenRoot(version)
	if err != nil {
		return nil, errSensorRuntime
	}
	defer versionRoot.Close()
	openedVersion, err := versionRoot.Stat(".")
	if err != nil || !os.SameFile(versionInfo, openedVersion) || !projectedTokenDirectory(openedVersion, owner, true) {
		return nil, errSensorRuntime
	}
	before, err := versionRoot.Lstat("token")
	if err != nil || !projectedTokenFile(before, owner) || !projectedTokenSameDevice(parentInfo, before) {
		return nil, errSensorRuntime
	}
	file, err := versionRoot.OpenFile("token", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errSensorRuntime
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !projectedTokenFile(opened, owner) || !os.SameFile(before, opened) || !projectedTokenReadOnly(file) {
		return nil, errSensorRuntime
	}
	raw, err := io.ReadAll(io.LimitReader(file, 82))
	final, finalErr := file.Stat()
	named, namedErr := versionRoot.Lstat("token")
	currentVersion, versionErr := reader.root.Lstat(version)
	currentVisible, visibleErr := projectedTokenLink(reader.root, "token", "..data/token")
	currentPublication, publicationErr := projectedTokenLink(reader.root, "..data", version)
	if err != nil || len(raw) != 81 || finalErr != nil || namedErr != nil || versionErr != nil || visibleErr != nil || publicationErr != nil || !projectedTokenFile(final, owner) || !projectedTokenFile(named, owner) || !os.SameFile(opened, final) || !os.SameFile(final, named) || !projectedTokenDirectory(currentVersion, owner, true) || !os.SameFile(versionInfo, currentVersion) || !os.SameFile(visible, currentVisible) || !os.SameFile(publication, currentPublication) || !projectedTokenRootBound(reader.root, parentInfo) || !projectedTokenReadOnly(parent) || !projectedTokenReadOnly(file) {
		clear(raw)
		return nil, errSensorRuntime
	}
	credential, err := sensor.ParseTokenCredential(string(raw))
	if err != nil {
		clear(raw)
		return nil, errSensorRuntime
	}
	credential.Destroy()
	return raw, nil
}

func projectedTokenReadOnly(file *os.File) bool {
	var stat unix.Statfs_t
	return unix.Fstatfs(int(file.Fd()), &stat) == nil && stat.Flags&unix.ST_RDONLY != 0
}

func projectedTokenDirectory(info os.FileInfo, group uint32, version bool) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSetuid != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != group {
		return false
	}
	// The volume root can inherit tmpfs/emptyDir write bits. The verified RO
	// mount, not those bits, prevents consumer writes. Version dirs are 0755.
	return !version || info.Mode().Perm() == 0755 && info.Mode()&os.ModeSticky == 0
}

func projectedTokenFile(info os.FileInfo, group uint32) bool {
	if !lineageOwnedRegular(info, 0, 0440) || info.Size() != 81 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Gid == group
}

func projectedTokenSameDevice(a, b os.FileInfo) bool {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Dev == y.Dev
}

func projectedTokenRootBound(root *os.Root, before os.FileInfo) bool {
	named, err := os.Lstat(root.Name())
	return err == nil && os.SameFile(before, named) && before.Mode() == named.Mode() && projectedTokenDirectory(named, uint32(os.Geteuid()), false)
}

func projectedTokenLink(root *os.Root, name, target string) (os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeType != os.ModeSymlink {
		return nil, errSensorRuntime
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return nil, errSensorRuntime
	}
	value, err := root.Readlink(name)
	after, afterErr := root.Lstat(name)
	if err != nil || afterErr != nil || value != target || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		return nil, errSensorRuntime
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || afterStat.Uid != 0 || afterStat.Nlink != 1 {
		return nil, errSensorRuntime
	}
	return after, nil
}
