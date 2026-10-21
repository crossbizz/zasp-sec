//go:build !linux

package gatewaypodidentity

func reviewerCredential(string) ([]byte, error) { return nil, ErrDenied }
