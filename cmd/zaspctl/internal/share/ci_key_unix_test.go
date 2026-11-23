//go:build unix

package share

import "os"

func writeTestCIKey(path string, data []byte) error { return os.WriteFile(path, data, 0600) }
