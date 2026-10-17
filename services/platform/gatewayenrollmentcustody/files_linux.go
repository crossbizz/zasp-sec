//go:build linux

package gatewayenrollmentcustody

import (
	"os"
	"syscall"
)

func noFollowFlags() int { return syscall.O_NOFOLLOW | syscall.O_NONBLOCK }
func safeInfo(info os.FileInfo, links uint64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == links
}
