package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

type orderedCheckpointArtifacts struct {
	*release61ArtifactDriver
	phase  string
	fired  bool
	writes []artifactstore.DriverObject
}

func (d *orderedCheckpointArtifacts) Put(ctx context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	var shape struct {
		Schema string `json:"schema_version"`
	}
	if d.phase == "test-reserved" && !d.fired && json.Unmarshal(object.Body, &shape) == nil && shape.Schema == "red-team-runner-input-v2" {
		d.fired = true
		return artifactstore.DriverObject{}, errWorkerExecution
	}
	stored, err := d.release61ArtifactDriver.Put(ctx, object)
	if err == nil {
		stored.Body = bytes.Clone(stored.Body)
		d.writes = append(d.writes, stored)
	}
	return stored, err
}

// This is an expected process crash, not a successful Test execution. It is
// necessary for the started checkpoint: returning a Command error invokes the
// real runner's stop path before the separate69 recovery consumer can inspect.
func crashOrderedCheckpoint(t *testing.T, phase string, engineCalls int) {
	t.Helper()
	path := os.Getenv("ZASP_P7_ORDERED_CHECKPOINT_FILE")
	if (phase != "test-reserved" && phase != "test-started") || !filepath.IsAbs(path) || engineCalls != 0 {
		t.Fatal("invalid owned producer crash boundary")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("owned checkpoint marker", err)
	}
	_, err = file.WriteString(phase)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("owned checkpoint marker write", err, closeErr)
	}
	os.Exit(73)
}
