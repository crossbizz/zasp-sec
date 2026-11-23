package main

import (
	"path/filepath"
	"testing"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/privatewin"
)

func TestCalibrationExportWindowsPrivateACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "calibration.jsonl")
	f, err := createCalibrationFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	pinned, err := privatewin.Open(path, false)
	if err != nil {
		t.Fatal("expected a private file owner and DACL", err)
	}
	pinned.Close()
	if other, err := createCalibrationFile(path); err == nil {
		other.Close()
		t.Fatal("exclusive creation replaced an existing export")
	}
}
