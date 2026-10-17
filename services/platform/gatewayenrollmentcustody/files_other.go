//go:build !linux

package gatewayenrollmentcustody

import "os"

func noFollowFlags() int                { return 0 }
func safeInfo(os.FileInfo, uint64) bool { return false }
