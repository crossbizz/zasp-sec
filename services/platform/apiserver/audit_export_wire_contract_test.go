package apiserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

// Explicit regeneration only. Normal runs compare the committed cross-language
// vectors to Go's real canonical codec and the HTTP handler's public encoder.
func TestAuditExportReadBrowserWireGolden(t *testing.T) {
	id := func(n int) string { return fmt.Sprintf("pid_%08x-0000-4000-8000-000000000001", n) }
	binding := audit.ExportBinding{OrganizationID: id(1), WorkspaceID: id(2), EnvironmentID: id(3), ExportID: id(4), CaptureID: id(5)}
	event := audit.ExportEvent{Ordinal: 1, ID: id(10000), OrganizationID: id(1), WorkspaceID: id(20), EnvironmentID: id(30), ActorID: id(6), Action: "identity_provider.createSSOConnection", TargetID: "<>&\"\\", Outcome: "succeeded", Metadata: map[string]string{"10": "ten", "2": "two", "message": "<>&\"\\\u2028\u2029 café", "\ue000": "BMP", "😀": "non-BMP", "TOKEN": "[REDACTED]"}, OccurredAt: "2026-09-12T08:09:10.123456Z"}
	chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: 1, FirstEvent: 1, EventCount: 1, PreviousDigest: audit.ExportZeroDigest, Events: []audit.ExportEvent{event}}
	digest := func(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
	write := func(name string, body []byte) {
		t.Helper()
		path := filepath.Join("../../../apps/web/api/testdata", name)
		if os.Getenv("ZASP_UPDATE_AUDIT_EXPORT_WIRE") == "1" {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0644); err != nil {
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("Go wire fixture differs: %s (%v)", path, err)
		}
		t.Logf("%s bytes=%d sha256=%s", name, len(body), digest(body))
	}
	eventBytes, err := audit.EncodeExportEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	write("audit-export-event.json", eventBytes)
	// Go's simple Unicode lowercase maps dotted capital I to plain i; JS full
	// lowercase adds a combining dot. The same sensitive-key refusal must hold.
	dotted := event
	dotted.Metadata = map[string]string{"CREDENTİAL": "secret"}
	if _, err := audit.EncodeExportEvent(dotted); err == nil {
		t.Fatal("Go accepted unredacted dotted-I credential")
	}
	chunkBytes, err := audit.EncodeExportChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	write("audit-export-chunk.json", chunkBytes)
	manifest := audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: 1, ChunkCount: 1, ChunkBytes: int64(len(chunkBytes)), ChainRoot: digest(chunkBytes)}
	manifestBytes, err := audit.EncodeExportManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write("audit-export-manifest.json", manifestBytes)
	public := func(c audit.ExportChunk, m audit.ExportManifest, cursor any) []byte {
		t.Helper()
		cb, err := audit.EncodeExportChunk(c)
		if err != nil {
			t.Fatal(err)
		}
		mb, err := audit.EncodeExportManifest(m)
		if err != nil {
			t.Fatal(err)
		}
		d := audit.ExportDescriptor{ID: id(4), OrganizationID: id(1), WorkspaceID: id(2), EnvironmentID: id(3), CreatedAt: "9999-12-31T23:59:59.999999Z", AuditCorrelationID: id(6), Status: "ready", EventCount: &m.EventCount, CapturedAt: "9999-12-31T23:59:59.999999Z", ChunkCount: &m.ChunkCount, ChunkBytes: &m.ChunkBytes, ManifestSHA256: digest(mb)}
		encoded, _ := json.Marshal(d)
		if _, err := audit.DecodeExportDescriptor(encoded); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		writeJSONValue(response, httptest.NewRequest(http.MethodGet, "/api/v1/audit-exports/"+id(4), nil), http.StatusOK, map[string]any{"export": d, "contents": map[string]any{"manifest": m, "chunk": c, "chunk_sha256": digest(cb), "page_info": map[string]any{"next_cursor": cursor, "has_more": cursor != nil}}}, nil)
		if response.Code != 200 || !bytes.Contains(response.Body.Bytes(), cb) || !bytes.Contains(response.Body.Bytes(), mb) {
			t.Fatal("public encoder changed canonical object bytes")
		}
		return response.Body.Bytes()
	}
	write("audit-export-read.json", public(chunk, manifest, nil))
	second := chunk
	second.Ordinal = 2
	second.FirstEvent = 2
	second.PreviousDigest = digest(chunkBytes)
	event2 := event
	event2.Ordinal = 2
	event2.ID = id(9999)
	second.Events = []audit.ExportEvent{event2}
	secondBytes, err := audit.EncodeExportChunk(second)
	if err != nil {
		t.Fatal(err)
	}
	two := manifest
	two.EventCount = 2
	two.ChunkCount = 2
	two.ChunkBytes += int64(len(secondBytes))
	two.ChainRoot = digest(secondBytes)
	write("audit-export-page-one.json", public(chunk, two, "next_2"))
	write("audit-export-page-two.json", public(second, two, nil))
	empty := audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, ChainRoot: audit.ExportZeroDigest}
	emptyBytes, err := audit.EncodeExportManifest(empty)
	if err != nil {
		t.Fatal(err)
	}
	emptyDescriptor := audit.ExportDescriptor{ID: id(4), OrganizationID: id(1), WorkspaceID: id(2), EnvironmentID: id(3), CreatedAt: "2026-09-12T08:09:10.123456Z", AuditCorrelationID: id(6), Status: "ready", EventCount: &empty.EventCount, CapturedAt: "2026-09-12T08:09:11.123456Z", ChunkCount: &empty.ChunkCount, ChunkBytes: &empty.ChunkBytes, ManifestSHA256: digest(emptyBytes)}
	emptyResponse := httptest.NewRecorder()
	writeJSONValue(emptyResponse, httptest.NewRequest(http.MethodGet, "/api/v1/audit-exports/"+id(4), nil), http.StatusOK, map[string]any{"export": emptyDescriptor, "contents": map[string]any{"manifest": empty, "chunk": nil, "chunk_sha256": nil, "page_info": map[string]any{"next_cursor": nil, "has_more": false}}}, nil)
	write("audit-export-empty.json", emptyResponse.Body.Bytes())
	chunk.Events = nil
	for n := 0; n < 1000; n++ {
		e := event
		e.Ordinal = int64(n + 1)
		e.ID = id(10000 - n)
		e.TargetID = strings.Repeat("t", 128)
		e.Metadata = map[string]string{"payload": strings.Repeat("x", 300)}
		chunk.Events = append(chunk.Events, e)
	}
	chunk.EventCount = 1000
	base, err := audit.EncodeExportChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	remaining := audit.ExportMaximumChunkBytes - len(base)
	for n := range chunk.Events {
		add := min(212, remaining)
		chunk.Events[n].Metadata["payload"] += strings.Repeat("x", add)
		remaining -= add
	}
	near, err := audit.EncodeExportChunk(chunk)
	if err != nil || remaining != 0 || len(near) != audit.ExportMaximumChunkBytes {
		t.Fatalf("near-bound fixture size=%d remaining=%d err=%v", len(near), remaining, err)
	}
	manifest.EventCount = 9007199254740991
	manifest.ChunkCount = 9007199254740991
	manifest.ChunkBytes = 9007199254740991
	// Non-final first page: later chunks own the actual terminal root. This vector
	// tests legal local wire bounds, not a fabricated complete multi-petabyte save.
	manifest.ChainRoot = strings.Repeat("a", 64)
	wire := public(chunk, manifest, strings.Repeat("A", 1024))
	if len(wire) <= 1048576 || len(wire) > 1064960 {
		t.Fatalf("public envelope outside client contract: %d", len(wire))
	}
	write("audit-export-near-bound.json", wire)
}
