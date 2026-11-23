package mcpschema

import (
	"errors"
	"os"
)

// OpenBaseline rejects links and unbounded or nonregular inputs before reading.
func OpenBaseline(path string) (*os.File, error) {
	invalid := errors.New("unreadable baseline")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limitBytes {
		return nil, invalid
	}
	f, err := os.OpenFile(path, os.O_RDONLY|readFlags, 0)
	if err != nil {
		return nil, invalid
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() {
		f.Close()
		return nil, invalid
	}
	return f, nil
}
