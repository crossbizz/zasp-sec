package sensoradapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

func lineageSourceFixture() LineageSource {
	observation := adapterLineageFixture()
	return LineageSource{Profile: "tetragon-local-stream-v1", GenerationID: "12345678-1234-1234-1234-123456789005", EnrollmentBinding: strings.Repeat("a", 64), NodeName: "node-a", ClusterUID: observation.ClusterUID, NodeUID: observation.NodeUID, BootID: observation.BootID}
}

func qualifiedTetragonFixture(line string) string {
	// Replace provider fixture IDs with the full observed IDs required by the
	// profile. Neither abbreviated process.docker nor names are used as IDs.
	var root map[string]any
	if err := json.Unmarshal([]byte(line), &root); err != nil {
		panic(err)
	}
	for _, kind := range []string{"process_exec", "process_exit", "process_kprobe"} {
		if body, ok := root[kind].(map[string]any); ok {
			process := body["process"].(map[string]any)
			pod := process["pod"].(map[string]any)
			pod["uid"] = adapterLineageFixture().PodUID
			pod["container"].(map[string]any)["id"] = adapterLineageFixture().ContainerID
		}
	}
	result, err := json.Marshal(root)
	if err != nil {
		panic(err)
	}
	return string(result)
}

func TestLineageSourceQualificationAndPrecision(t *testing.T) {
	for name, line := range map[string]string{
		"exec":                     qualifiedTetragonFixture(tetragonExecFixture()),
		"file":                     qualifiedTetragonFixture(tetragonFileFixture()),
		"network":                  qualifiedTetragonFixture(tetragonNetworkFixture()),
		"submillisecond start":     strings.ReplaceAll(qualifiedTetragonFixture(tetragonExecFixture()), ".000Z", ".123456789Z"),
		"existing running process": strings.Replace(qualifiedTetragonFixture(tetragonFileFixture()), `"start_time":"2026-08-20T12:00:00.000Z"`, `"start_time":"2026-08-19T12:00:00.000Z"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			source := lineageSourceFixture()
			normalizer, err := NewLineageNormalizer(8, source)
			if err != nil {
				t.Fatal(err)
			}
			source.BootID = "12345678-1234-1234-1234-123456789099"
			plain, err := NormalizeTetragonLine([]byte(line))
			if err != nil {
				t.Fatal(err)
			}
			event, err := normalizer.Normalize([]byte(line))
			if err != nil {
				t.Fatal(err)
			}
			want := adapterLineageFixture()
			want.CgroupID = "" // The supported source has no numeric cgroup ID.
			want.ProcessStartTime = "2026-08-20T12:00:00Z"
			if name == "existing running process" {
				want.ProcessStartTime = "2026-08-19T12:00:00Z"
			}
			if name == "submillisecond start" {
				want.ProcessID, want.ProcessStartTime = "", ""
			}
			if event.ObservedLineage != want {
				t.Fatal("wrong qualifier or process precision", event.ObservedLineage)
			}
			event.ObservedLineage = runtimelineage.Observation{}
			gotBytes, _ := json.Marshal(event)
			plainBytes, _ := json.Marshal(plain)
			if !bytes.Equal(gotBytes, plainBytes) {
				t.Fatal("qualification changed existing event identity/time/content")
			}
		})
	}
}

func TestLineageSourceIncompleteEventRemainsUnqualified(t *testing.T) {
	valid := qualifiedTetragonFixture(tetragonExecFixture())
	for name, line := range map[string]string{
		"old provider IDs": strings.Replace(valid, adapterLineageFixture().PodUID, "legacy-pod-identity", 1),
		"foreign node":     strings.Replace(valid, `"node_name":"node-a"`, `"node_name":"node-b"`, 1),
		"short container":  strings.ReplaceAll(valid, adapterLineageFixture().ContainerID, "abcdef012345678"),
		"pod name as ID":   strings.Replace(valid, adapterLineageFixture().PodUID, "pod-a", 1),
	} {
		t.Run(name, func(t *testing.T) {
			normalizer, err := NewLineageNormalizer(8, lineageSourceFixture())
			if err != nil {
				t.Fatal(err)
			}
			event, err := normalizer.Normalize([]byte(line))
			if err != nil || event.ObservedLineage != (runtimelineage.Observation{}) {
				t.Fatal("unqualified source gained lineage or was dropped", err)
			}
		})
	}
}

func TestLineageSourceRejectsMalformedConfiguration(t *testing.T) {
	for name, change := range map[string]func(*LineageSource){
		"empty":           func(v *LineageSource) { *v = LineageSource{} },
		"profile":         func(v *LineageSource) { v.Profile = "exporter-existing-file" },
		"generation":      func(v *LineageSource) { v.GenerationID = "new" },
		"zero generation": func(v *LineageSource) { v.GenerationID = "00000000-0000-0000-0000-000000000000" },
		"enrollment":      func(v *LineageSource) { v.EnrollmentBinding = "" },
		"node name":       func(v *LineageSource) { v.NodeName = "" },
		"cluster UID":     func(v *LineageSource) { v.ClusterUID = "cluster-a" },
		"node UID":        func(v *LineageSource) { v.NodeUID = "node-a" },
		"boot ID":         func(v *LineageSource) { v.BootID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			source := lineageSourceFixture()
			change(&source)
			if normalizer, err := NewLineageNormalizer(8, source); err != ErrAdapter || normalizer != nil {
				t.Fatal("invalid source accepted", err)
			}
		})
	}
}

func TestLineageSourceStreamRequiresMatchingBoundClient(t *testing.T) {
	for _, binding := range []string{"", strings.Repeat("b", 64)} {
		directory := t.TempDir()
		normalizer, err := NewLineageNormalizer(8, lineageSourceFixture())
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: binding, Now: time.Now, Token: func() ([]byte, error) { t.Fatal("credential read"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) { t.Fatal("transport called"); return nil, nil }})
		if err != nil {
			t.Fatal(err)
		}
		processor, err := NewFileProcessor(FileProcessorConfig{LogPath: filepath.Join(directory, "tetragon.log"), CursorPath: filepath.Join(directory, "cursor.json"), Normalizer: normalizer, Sink: client, MaximumLines: 1})
		if processor != nil {
			processor.Close()
		}
		if err != ErrStream {
			t.Fatal("unbound or different enrollment accepted", err)
		}
		if _, err := os.Lstat(filepath.Join(directory, "cursor.json.lock")); !os.IsNotExist(err) {
			t.Fatal("rejected context created lock", err)
		}
	}
}

func TestLineageSourceRejectsLegacyCursorAdoption(t *testing.T) {
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, qualifiedTetragonFixture(tetragonExecFixture())+"\n")
	legacy := []byte(`{"version":"tetragon-cursor-v1","device":1,"inode":1,"offset":0,"dropped":0}` + "\n")
	if err := os.WriteFile(cursorPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	normalizer, err := NewLineageNormalizer(8, lineageSourceFixture())
	if err != nil {
		t.Fatal(err)
	}
	client, _ := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: time.Now, Token: func() ([]byte, error) { t.Fatal("credential read"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) { t.Fatal("transport called"); return nil, nil }})
	processor, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: client, MaximumLines: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	if _, err := processor.ProcessAvailable(context.Background()); err != ErrStream {
		t.Fatal("qualified generation adopted legacy cursor", err)
	}
	after, err := os.ReadFile(cursorPath)
	if err != nil || !bytes.Equal(after, legacy) {
		t.Fatal("legacy state changed", err)
	}
}

func TestLineageSourceHashIncludesEveryProvenanceDimension(t *testing.T) {
	source := lineageSourceFixture()
	legacy := strings.Repeat("b", 64)
	if (LineageSource{}).bindStream(legacy) != legacy {
		t.Fatal("absent source changed legacy hash")
	}
	initial := source.bindStream(legacy)
	for name, change := range map[string]func(*LineageSource){
		"profile":     func(v *LineageSource) { v.Profile += "-next" },
		"generation":  func(v *LineageSource) { v.GenerationID = "12345678-1234-1234-1234-123456789099" },
		"enrollment":  func(v *LineageSource) { v.EnrollmentBinding = strings.Repeat("c", 64) },
		"node name":   func(v *LineageSource) { v.NodeName = "node-b" },
		"cluster UID": func(v *LineageSource) { v.ClusterUID = "12345678-1234-1234-1234-123456789099" },
		"node UID":    func(v *LineageSource) { v.NodeUID = "12345678-1234-1234-1234-123456789099" },
		"boot ID":     func(v *LineageSource) { v.BootID = "12345678-1234-1234-1234-123456789099" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := source
			change(&changed)
			if changed.bindStream(legacy) == initial {
				t.Fatal("source hash omitted provenance")
			}
		})
	}
	if source.bindStream(strings.Repeat("c", 64)) == initial {
		t.Fatal("source hash omitted file binding")
	}
}

func TestLineageSourceCacheRestartAndGenerationDrift(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)
	var requests []runtimeEnvelopeBody
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) { return []byte(envelopeCredential(t, 96)), nil }, Do: func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var decoded runtimeEnvelopeBody
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, decoded)
		return envelopeAccepted(), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	firstLine := qualifiedTetragonFixture(tetragonExecFixture()) + "\n"
	writeFixtureLog(t, logPath, firstLine)
	newProcessor := func(source LineageSource) *FileProcessor {
		t.Helper()
		normalizer, err := NewLineageNormalizer(8, source)
		if err != nil {
			t.Fatal(err)
		}
		processor, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: client, MaximumLines: 2})
		if err != nil {
			t.Fatal(err)
		}
		return processor
	}
	source := lineageSourceFixture()
	first := newProcessor(source)
	if result, err := first.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 {
		t.Fatal("initial qualified exec", result, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	var partial map[string]any
	if err := json.Unmarshal([]byte(qualifiedTetragonFixture(tetragonFileFixture())), &partial); err != nil {
		t.Fatal(err)
	}
	partial["process_kprobe"].(map[string]any)["process"] = map[string]any{"pid": 42, "flags": "unknown", "start_time": "2026-08-20T12:00:00.000Z"}
	partial["time"] = "2026-08-20T12:00:01.000Z"
	partialBytes, err := json.Marshal(partial)
	if err != nil {
		t.Fatal(err)
	}
	appendFixtureLog(t, logPath, string(partialBytes)+"\n")
	before, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*LineageSource){
		"reboot reused node and process": func(v *LineageSource) { v.BootID = "12345678-1234-1234-1234-123456789099" },
		"node recreation":                func(v *LineageSource) { v.NodeUID = "12345678-1234-1234-1234-123456789099" },
		"new stream generation":          func(v *LineageSource) { v.GenerationID = "12345678-1234-1234-1234-123456789099" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := source
			change(&changed)
			processor := newProcessor(changed)
			if _, err := processor.ProcessAvailable(context.Background()); err != ErrStream {
				t.Fatal("changed generation adopted old process cache", err)
			}
			if err := processor.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(cursorPath)
			if err != nil || !bytes.Equal(before, after) || len(requests) != 1 {
				t.Fatal("rejected generation changed state or sent work", err)
			}
		})
	}
	restored := newProcessor(source)
	defer restored.Close()
	if result, err := restored.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || result.Dropped != 0 {
		t.Fatal("same generation didn't restore qualified cache", result, err)
	}
	if len(requests) != 2 || requests[1].Events[0].Class != "file" || requests[1].Events[0].ObservedLineage != requests[0].Events[0].ObservedLineage || requests[0].Events[0].ObservedLineage == (runtimelineage.Observation{}) {
		t.Fatal("partial process lost original lineage")
	}
}

func TestLineageSourceCannotImportUnqualifiedCheckpointCache(t *testing.T) {
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, qualifiedTetragonFixture(tetragonExecFixture())+"\n")
	attempts := 0
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }, Token: func() ([]byte, error) { return []byte(envelopeCredential(t, 97)), nil }, Do: func(*http.Request) (*http.Response, error) { attempts++; return envelopeAccepted(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	unqualified := newFixtureFileProcessor(t, logPath, cursorPath, client)
	if result, err := unqualified.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 {
		t.Fatal("unqualified input", result, err)
	}
	if err := unqualified.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatal(err)
	}
	normalizer, err := NewLineageNormalizer(8, lineageSourceFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(normalizer.values) != 0 {
		t.Fatal("new generation imported existing cache")
	}
	qualified, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: client, MaximumLines: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer qualified.Close()
	if _, err := qualified.ProcessAvailable(context.Background()); err != ErrStream {
		t.Fatal("new generation adopted unqualified cache", err)
	}
	after, err := os.ReadFile(cursorPath)
	if err != nil || !bytes.Equal(before, after) || attempts != 1 || len(qualified.normalizer.values) != 0 {
		t.Fatal("unqualified cache was imported or changed", err)
	}
}
