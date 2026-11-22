//go:build !windows

package main

import "testing"

func testSpool(t *testing.T) string { t.Helper(); return t.TempDir() }
