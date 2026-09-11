package sensoradapter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizerRetainedIdentityPreservesSupportedTimestampPrecision(t *testing.T) {
	for _, stamp := range []string{"2026-08-20T12:00:00.100Z", "2026-08-20T12:00:00.123400Z", "2026-08-20T12:00:00.123456700Z"} {
		t.Run(stamp, func(t *testing.T) {
			normalizer, _ := NewNormalizer(4)
			exec := strings.ReplaceAll(tetragonExecFixture(), "2026-08-20T12:00:00.000Z", stamp)
			if _, err := normalizer.Normalize([]byte(exec)); err != nil {
				t.Fatal(err)
			}
			partial := strings.Replace(tetragonFileFixture(), tetragonProcess(), `{"pid":42,"flags":"unknown","start_time":"`+stamp+`"}`, 1)
			if _, err := normalizer.Normalize([]byte(partial)); err != nil {
				t.Fatal("retained precision could not be correlated", err)
			}
		})
	}
}

func TestNormalizerCheckpointRetainsOrderAndOnlySanitizedIdentity(t *testing.T) {
	normalizer, _ := NewNormalizer(2)
	for _, id := range []string{"42", "43"} {
		line := strings.ReplaceAll(tetragonExecFixture(), `"pid":42`, `"pid":`+id)
		line = strings.ReplaceAll(line, "exec-1", "exec-"+id)
		if _, err := normalizer.Normalize([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := normalizer.checkpoint()
	if err != nil || len(snapshot) != 2 {
		t.Fatal("cache snapshot", err)
	}
	body, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(body), "arguments") || strings.Contains(string(body), "binary") || strings.Contains(string(body), "credentials") || strings.Contains(string(body), "cwd") {
		t.Fatal("checkpoint retained provider content", err)
	}
	restored, _ := NewNormalizer(2)
	if err := restored.restoreCheckpoint(snapshot); err != nil {
		t.Fatal(err)
	}
	if again, err := restored.checkpoint(); err != nil || !reflect.DeepEqual(snapshot, again) {
		t.Fatal("checkpoint order changed", err)
	}
	line := strings.ReplaceAll(tetragonExecFixture(), `"pid":42`, `"pid":44`)
	if _, err := restored.Normalize([]byte(line)); err != nil {
		t.Fatal(err)
	}
	again, _ := restored.checkpoint()
	if len(again) != 2 || again[0].PID != 43 || again[1].PID != 44 {
		t.Fatal("restore changed eviction order")
	}
	before := append([]cachedProcessIdentity(nil), again...)
	for _, invalid := range [][]cachedProcessIdentity{append(again, again[0]), {again[0], again[0]}} {
		if err := restored.restoreCheckpoint(invalid); err == nil {
			t.Fatal("invalid cache accepted")
		}
		if current, _ := restored.checkpoint(); !reflect.DeepEqual(current, before) {
			t.Fatal("failed restore mutated cache")
		}
	}
	reduced, _ := NewNormalizer(1)
	if reduced.restoreCheckpoint(before) == nil {
		t.Fatal("lowered cache limit silently evicted retained identity")
	}
}
