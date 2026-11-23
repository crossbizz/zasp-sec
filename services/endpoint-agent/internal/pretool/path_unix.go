//go:build !windows

package pretool

import (
	"os"
	"path/filepath"
	"strings"
)

func mountContains(root, path string) bool {
	return root == "/" || root == path || strings.HasPrefix(path, root+"/")
}
func pathChain(p string) (string, bool) {
	if !knownLocalVolume(p) {
		return "unverifiable_path", true
	}
	// Inspect each existing component without following a symlink to another
	// location. A chain that cannot be verified has unknown coverage.
	vol := filepath.VolumeName(p)
	cursor := vol + string(os.PathSeparator)
	for _, part := range strings.Split(strings.TrimPrefix(p, vol), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		cursor = filepath.Join(cursor, part)
		st, err := os.Lstat(cursor)
		if os.IsNotExist(err) {
			break
		}
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return "unverifiable_path", true
		}
	}
	return "", true
}
