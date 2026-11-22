//go:build !darwin && !linux && !windows

package pretool

func knownLocalVolume(string) bool { return false }
