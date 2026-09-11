package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The daemon replay composition needs exactly one upload, so its database
// totals can detect duplication under any batch identity.
func TestInstalledLineageSingleFixtureHasExactSealedFrontier(t *testing.T) {
	for _, fixture := range []struct {
		action string
		count  int
	}{{"initialize-single", 1}, {"initialize", 3}} {
		t.Run(fixture.action, func(t *testing.T) {
			config := installedLineageProcessConfig{
				Action: fixture.action, SpoolPath: t.TempDir(), Source: lineageSpoolSource(),
				Stamp: time.Now().UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano),
			}
			if err := initializeInstalledLineageFixture(context.Background(), config); err != nil {
				t.Fatal("initialize sealed fixture", err)
			}
			reader, err := newLineageSpoolReader(filepath.Join(config.SpoolPath, "generation-"+config.Source.GenerationID), config.Source.EnrollmentBinding, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			seal, found, err := reader.ReadSeal()
			// A sealed local fixture cannot establish complete live coverage.
			if err != nil || !found || seal.Chunks != fixture.count || seal.Records != fixture.count || seal.Dropped != 0 || seal.Filtered != 0 || seal.CoverageComplete || seal.Reason != "shutdown" {
				t.Fatal("fixture doesn't have the exact sealed frontier", seal, found, err)
			}
			for sequence := 1; sequence <= fixture.count; sequence++ {
				chunk, found, err := reader.ReadChunk(sequence)
				if err != nil || !found || len(chunk.Lines) != 1 {
					t.Fatal("missing exact fixture record", sequence, found, err)
				}
			}
			if _, found, err := reader.ReadChunk(fixture.count + 1); err != nil || found {
				t.Fatal("fixture frontier has unexpected records", found, err)
			}
			if initializeInstalledLineageFixture(context.Background(), config) == nil {
				t.Fatal("fixture initialization rewrote an existing generation")
			}
			after, found, err := reader.ReadSeal()
			if err != nil || !found || after != seal {
				t.Fatal("rejected initialization changed sealed history", err)
			}
		})
	}
}
