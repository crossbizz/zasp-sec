//go:build !linux

package gatewayenrollmentcustody

import "os"

func safeAssociationDirectory(os.FileInfo) bool { return false }
