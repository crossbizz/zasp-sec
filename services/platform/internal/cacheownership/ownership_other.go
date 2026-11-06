//go:build !linux

package cacheownership

import "os"

func platformSupported() bool                          { return false }
func safeFile(os.FileInfo) bool                        { return false }
func acquirePlatform(*os.Root, string) (*Guard, error) { return nil, ErrUnavailable }
