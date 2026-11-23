package pretool

import (
	"io"
	"os"
	"strings"
)

var mountEscapes = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, "\\")

// mountinfo is produced by the local kernel. Refuse network, automounter,
// pseudo and unknown filesystems before inspecting any component.
func knownLocalVolume(path string) bool {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return false
	}
	return localMountsCover(string(data), path)
}
func localMountsCover(table, path string) bool {
	covered := false
	for line := range strings.SplitSeq(strings.TrimSuffix(table, "\n"), "\n") {
		before, after, ok := strings.Cut(line, " - ")
		left := strings.Fields(before)
		right := strings.Fields(after)
		if !ok || len(left) < 6 || len(right) < 3 {
			return false
		}
		if !mountContains(mountEscapes.Replace(left[4]), path) {
			continue
		}
		switch right[0] {
		case "ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs", "ramfs", "overlay", "erofs", "f2fs", "zfs":
			covered = true
		default:
			return false
		}
	}
	return covered
}
