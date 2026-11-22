//go:build !windows

package main

import (
	"errors"
	"os"
)

func privateSpool(root *os.Root) bool {
	info, err := root.Stat(".")
	return err == nil && info.Mode().Perm()&0022 == 0
}
func openReportSecret(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("private token file required")
	}
	return f, nil
}
func syncFolder(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func publishName(root *os.Root, from, to string) error {
	if err := root.Rename(from, to); err != nil {
		return err
	}
	return syncFolder(root)
}
func claimGrant(root *os.Root, id string) error {
	f, err := root.OpenFile(id, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return syncFolder(root)
}
