package main

import (
	"context"
	"testing"
	"time"
)

func TestLineagePumpTimedRotationFlushesAndSeals(t *testing.T) {
	generation, _, events, _, path := lineagePumpFixture(t)
	events.events <- lineageProviderFixture("exec")
	config := lineagePumpTestConfig(100)
	config.FlushInterval = time.Second
	config.MaximumDuration = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := runLineagePump(ctx, generation, config)
	if err != nil || !result.Sealed || result.Reason != "rotation" || result.Records != 1 || result.Dropped != 0 || result.Uncertain != 0 {
		t.Fatal("timed rotation", result, err)
	}
	seal := readLineagePumpSeal(t, path)
	if seal.Reason != "rotation" || seal.Chunks != 1 || seal.Records != 1 || seal.CoverageComplete {
		t.Fatal("rotation seal", seal)
	}
}

func TestLineagePumpTimedRotationClosesEmptyGeneration(t *testing.T) {
	generation, _, _, _, path := lineagePumpFixture(t)
	config := lineagePumpTestConfig(100)
	config.MaximumDuration = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := runLineagePump(ctx, generation, config)
	if err != nil || !result.Sealed || result.Reason != "rotation" || result.Records != 0 {
		t.Fatal(result, err)
	}
	if seal := readLineagePumpSeal(t, path); seal.Chunks != 0 || seal.Reason != "rotation" {
		t.Fatal(seal)
	}
}
