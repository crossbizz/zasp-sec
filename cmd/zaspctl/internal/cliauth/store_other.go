//go:build (!darwin && !linux && !windows) || (darwin && !cgo)

package cliauth

func writeSecret(string, string, []byte) error  { return errStore }
func readSecret(string, string) ([]byte, error) { return nil, errStore }
