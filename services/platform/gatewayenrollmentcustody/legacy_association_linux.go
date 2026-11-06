//go:build linux

package gatewayenrollmentcustody

import (
	"os"
	"syscall"
)

// Access time is deliberately excluded because our readonly verification may
// update it. Identity, ownership, permissions, size and modification/change
// times must retain the originally pinned source metadata.
func legacySourceMetadataEqual(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, yes := b.Sys().(*syscall.Stat_t)
	return ok && yes && x.Dev == y.Dev && x.Ino == y.Ino && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Mode == y.Mode && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
