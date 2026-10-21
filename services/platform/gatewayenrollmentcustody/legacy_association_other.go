//go:build !linux

package gatewayenrollmentcustody

import "os"

func legacySourceMetadataEqual(os.FileInfo, os.FileInfo) bool { return false }
