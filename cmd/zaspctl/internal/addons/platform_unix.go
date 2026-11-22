//go:build unix

package addons

import (
	"io/fs"
	"os"
	"syscall"
)

const nonblockingFlag = syscall.O_NONBLOCK

func IsLink(info fs.FileInfo) bool { return info.Mode()&fs.ModeSymlink != 0 }

// Other hard links can place the same inode outside the selected bundle.
func unaliasedRegularFile(_ *os.File, info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
