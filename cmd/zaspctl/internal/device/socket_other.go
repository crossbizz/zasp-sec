//go:build !windows && (!darwin || !cgo)

package device

func queryEndpoint() ([]byte, error) { return nil, unavailable }
