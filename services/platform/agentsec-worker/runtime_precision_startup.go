package main

func runtimePrecisionVersion(version string) bool {
	switch version {
	case "runtime-archive-v2", "runtime-index-v2", "runtime-correlation-v4", "runtime-projection-v3", "runtime-complete-v3":
		return true
	default:
		return false
	}
}
