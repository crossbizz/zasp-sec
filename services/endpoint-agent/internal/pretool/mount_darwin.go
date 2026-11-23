package pretool

import "golang.org/x/sys/unix"

// Query the kernel's cached table without refreshing remote filesystem stats.
// Never traverse a network volume or trigger an automount to classify a path.
func knownLocalVolume(path string) bool {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil || n < 1 || n > 1024 {
		return false
	}
	mounts := make([]unix.Statfs_t, n+1)
	count, err := unix.Getfsstat(mounts, unix.MNT_NOWAIT)
	if err != nil || count < 1 || count > n {
		return false
	}
	covered := false
	for _, m := range mounts[:count] {
		if mountContains(unix.ByteSliceToString(m.Mntonname[:]), path) {
			if m.Flags&unix.MNT_LOCAL == 0 || unix.ByteSliceToString(m.Fstypename[:]) == "autofs" {
				return false
			}
			covered = true
		}
	}
	return covered
}
