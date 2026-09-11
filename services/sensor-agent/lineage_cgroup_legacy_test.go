package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Runs the unchanged pre-v2 test binary's real spool-reader/consumer entry.
// This is opt-in local upgrade evidence, not a test mode in the shipped daemon.
func TestLineageCgroupHistoricalBinaryRefusesBeforeCursorAndACK(t *testing.T) {
	binary := os.Getenv("ZASP_TEST_LEGACY_SENSOR_BINARY")
	if binary == "" {
		t.Skip("requires compiled pre-v2 sensor test binary")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("legacy binary must be an absolute path")
	}
	root := t.TempDir()
	for _, name := range []string{"spool", "state", "acks"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	spool, err := newLineageSpool(filepath.Join(root, "spool"), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	source := lineageSpoolSource()
	source.Profile = "tetragon-local-stream-v2"
	generation, err := spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	line, err := sanitizeLineageEvent(lineageCgroupProviderFixture(9007199254740993))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal(err)
	}
	if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
		t.Fatal(err)
	}
	generation.Close()
	path := filepath.Join(root, "spool", "generation-"+source.GenerationID)
	before := recoveryEvidence(t, path)
	config := installedLineageProcessConfig{Action: "process", Endpoint: "https://runtime.example.test", CAPath: filepath.Join(root, "unopened-ca"), TokenPath: filepath.Join(root, "unopened-token"), SpoolPath: filepath.Join(root, "spool"), CursorPath: filepath.Join(root, "state", "cursor-0.json"), AckPath: filepath.Join(root, "acks"), ResultPath: filepath.Join(root, "result.json"), Source: source}
	configPath := filepath.Join(root, "config.json")
	encoded, err := json.Marshal(config)
	if err != nil || os.WriteFile(configPath, encoded, 0600) != nil {
		t.Fatal("write bounded legacy fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^(TestInstalledLineageConsumerProcess|TestLineageEventAllowlistedConversionReachesActualNormalizer)$", "-test.v")
	command.Env = []string{"ZASP_LINEAGE_CONSUMER_FIXTURE=" + configPath}
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: TestInstalledLineageConsumerProcess")) || !bytes.Contains(output, []byte("--- PASS: TestLineageEventAllowlistedConversionReachesActualNormalizer")) {
		t.Fatalf("historical reader/control failed: %v\n%s", err, output)
	}
	resultBytes, err := os.ReadFile(config.ResultPath)
	var result installedLineageProcessResult
	if err != nil || json.Unmarshal(resultBytes, &result) != nil || result.Outcome != "rejected" || result.TokenReads != 0 || result.Requests != 0 || result.Durable || result.Result.Read != 0 || result.Result.Dropped != 0 {
		t.Fatal("old reader consumed new source or reached credentials/transport", err)
	}
	for _, name := range []string{"state", "acks"} {
		entries, err := os.ReadDir(filepath.Join(root, name))
		if err != nil || len(entries) != 0 {
			t.Fatal("old reader created cursor or acknowledgment state", name, err)
		}
	}
	if !bytes.Equal(before, recoveryEvidence(t, path)) {
		t.Fatal("old reader changed retained source")
	}
	t.Log("unchanged historical binary refused v2 before credentials, transport, cursor, drop accounting or ACK; historical normalization control passed")
}
