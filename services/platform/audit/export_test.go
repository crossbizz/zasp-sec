package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func exportTestID(n int) string { return fmt.Sprintf("pid_%08x-0000-4000-8000-000000000001", n) }
func exportTestBinding() ExportBinding {
	return ExportBinding{exportTestID(1), exportTestID(2), exportTestID(3), exportTestID(4), exportTestID(5)}
}
func exportTestEvent(n int) ExportEvent {
	return ExportEvent{Ordinal: int64(n), ID: exportTestID(10000 - n), OrganizationID: exportTestID(1), WorkspaceID: exportTestID(2), EnvironmentID: exportTestID(3), ActorID: exportTestID(6), Action: "policy.update", TargetID: "policy:external-reference", Outcome: "succeeded", Metadata: map[string]string{"z": "last", "a": "first"}, OccurredAt: "2026-09-12T08:09:10.123456Z"}
}
func exportTestChunk() ExportChunk {
	return ExportChunk{ExportChunkSchema, exportTestBinding(), 1, 1, 2, ExportZeroDigest, []ExportEvent{exportTestEvent(1), exportTestEvent(2)}}
}
func exportDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func exportExpected(c ExportChunk, body []byte) ExportChunkExpectation {
	return ExportChunkExpectation{c.Binding, c.Ordinal, c.FirstEvent, c.EventCount, c.PreviousDigest, exportDigest(body)}
}

func TestExportRetainedIdentityActionsPreserveBytes(t *testing.T) {
	actions := []string{"identity_provider.createSSOConnection", "identity_provider.deleteSSOConnection", "identity_provider.testSSOConnection", "identity_provider.createSCIMConnection", "identity_provider.deleteSCIMConnection", "policy.update", "identity_provider.createssoconnection", strings.Repeat("a", 127)}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			e := exportTestEvent(1)
			e.Action = action
			projected, err := ProjectExportEvent(e)
			if err != nil {
				t.Fatal("retained action projection", err)
			}
			body, err := EncodeExportEvent(projected)
			if err != nil || !bytes.Contains(body, []byte(`"action":"`+action+`"`)) {
				t.Fatal("action bytes changed", err)
			}
			decoded, err := DecodeExportEvent(body)
			if err != nil || decoded.Action != action {
				t.Fatal("retained action decode", err)
			}
			chunk := exportTestChunk()
			chunk.Events = []ExportEvent{decoded}
			chunk.EventCount = 1
			wire, err := EncodeExportChunk(chunk)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyExportChunk(wire, exportExpected(chunk, wire))
			if err != nil || verified.Events[0].Action != action {
				t.Fatal("chunk changed retained action", err)
			}
			manifest := ExportManifest{ExportManifestSchema, chunk.Binding, 1, 1, int64(len(wire)), exportDigest(wire)}
			manifestBytes, err := EncodeExportManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyExportManifest(manifestBytes, manifest, exportDigest(manifestBytes)); err != nil {
				t.Fatal("retained action manifest chain", err)
			}
			if strings.ContainsAny(action, "SC") && validAction(action) {
				t.Fatal("generic emitter action grammar widened")
			}
		})
	}
}

func TestExportRetainedIdentityActionsRejectNearMisses(t *testing.T) {
	for _, action := range []string{"Identity_provider.createSSOConnection", "identity_provider.CreateSSOConnection", "identity_provider.createSsoConnection", "identity_provider.createSSOConnectionX", "identity_provider.unknownOperation", "identity_provider.createSSOConnection.", "identity_provider.createSSOConnection ", "identity_provider.createSSOConnection\n", "identity_provider.createSSOConnection\x00", "identity_provider.créateSSOConnection", "identity_provider..createSSOConnection", strings.Repeat("a", 128)} {
		t.Run(action, func(t *testing.T) {
			e := exportTestEvent(1)
			e.Action = action
			if _, err := ProjectExportEvent(e); err == nil {
				t.Fatal("projected invalid action")
			}
			if _, err := EncodeExportEvent(e); err == nil {
				t.Fatal("encoded invalid action")
			}
			body, _ := json.Marshal(e)
			if _, err := DecodeExportEvent(body); err == nil {
				t.Fatal("decoded invalid action")
			}
		})
	}
}

// Removing projection/redaction, byte stability or deep copying breaks this test.
func TestExportEventProjectionCanonicalFrozenBytes(t *testing.T) {
	e := exportTestEvent(1)
	e.Outcome = "rejected"
	e.Metadata = map[string]string{"TOKEN": "private-fixture", "message": "<>&\u2028\u2029 café \"quoted\" \\ path"}
	p, err := ProjectExportEvent(e)
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	if p.Outcome != "denied" || p.Metadata["TOKEN"] != "[REDACTED]" {
		t.Fatal("projection did not redact/map outcome")
	}
	e.Metadata["message"] = "mutated"
	body, err := EncodeExportEvent(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ordinal":1,"id":"pid_0000270f-0000-4000-8000-000000000001","organization_id":"pid_00000001-0000-4000-8000-000000000001","workspace_id":"pid_00000002-0000-4000-8000-000000000001","environment_id":"pid_00000003-0000-4000-8000-000000000001","actor_id":"pid_00000006-0000-4000-8000-000000000001","action":"policy.update","target_id":"policy:external-reference","outcome":"denied","metadata":{"TOKEN":"[REDACTED]","message":"\u003c\u003e\u0026\u2028\u2029 café \"quoted\" \\ path"},"occurred_at":"2026-09-12T08:09:10.123456Z"}`
	if string(body) != want {
		t.Fatal("canonical projection differs from independent wire fixture")
	}
	decoded, err := DecodeExportEvent(body)
	if err != nil || decoded.Metadata["message"] != "<>&\u2028\u2029 café \"quoted\" \\ path" {
		t.Fatal("frozen event did not round trip")
	}
	if bytes.Contains(body, []byte("private-fixture")) {
		t.Fatal("sensitive metadata escaped redaction")
	}
}

func TestExportChunkBoundAuthorityAndDeterministicRetry(t *testing.T) {
	c := exportTestChunk()
	body, err := EncodeExportChunk(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := VerifyExportChunk(body, exportExpected(c, body))
	if err != nil || len(decoded.Events) != 2 || decoded.Events[1].ID != exportTestID(9998) {
		t.Fatal("bound chunk did not verify")
	}
	again, err := EncodeExportChunk(decoded)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("retry changed immutable bytes")
	}
	for _, field := range []string{"org", "workspace", "environment", "export", "capture", "ordinal", "first", "count", "previous", "digest"} {
		t.Run(field, func(t *testing.T) {
			expected := exportExpected(c, body)
			switch field {
			case "org":
				expected.Binding.OrganizationID = exportTestID(20)
			case "workspace":
				expected.Binding.WorkspaceID = exportTestID(20)
			case "environment":
				expected.Binding.EnvironmentID = exportTestID(20)
			case "export":
				expected.Binding.ExportID = exportTestID(20)
			case "capture":
				expected.Binding.CaptureID = exportTestID(20)
			case "ordinal":
				expected.Ordinal++
			case "first":
				expected.FirstEvent++
			case "count":
				expected.EventCount--
			case "previous":
				expected.PreviousDigest = strings.Repeat("1", 64)
			case "digest":
				expected.SHA256 = strings.Repeat("1", 64)
			}
			if _, err := VerifyExportChunk(body, expected); err == nil {
				t.Fatal("accepted mismatched persisted authority")
			}
		})
	}
}

func TestExportChunkRejectsInvalidEventsAndRanges(t *testing.T) {
	changes := map[string]func(*ExportChunk){
		"schema":               func(c *ExportChunk) { c.Schema = "audit-export-chunk-v2" },
		"foreign organization": func(c *ExportChunk) { c.Events[0].OrganizationID = exportTestID(30) },
		"invalid scope":        func(c *ExportChunk) { c.Events[0].WorkspaceID = c.Events[0].EnvironmentID },
		"bad id":               func(c *ExportChunk) { c.Events[0].ID = "pid_invalid" },
		"uppercase id":         func(c *ExportChunk) { c.Events[0].ID = strings.ToUpper(c.Events[0].ID) },
		"reordered":            func(c *ExportChunk) { c.Events[0], c.Events[1] = c.Events[1], c.Events[0] },
		"duplicate":            func(c *ExportChunk) { c.Events[1].ID = c.Events[0].ID },
		"gap":                  func(c *ExportChunk) { c.Events[1].Ordinal++ },
		"missing":              func(c *ExportChunk) { c.Events = c.Events[:1] },
		"nil events":           func(c *ExportChunk) { c.Events = nil },
		"zero ordinal":         func(c *ExportChunk) { c.Ordinal = 0 },
		"first range":          func(c *ExportChunk) { c.FirstEvent = 2 },
		"zero previous on later": func(c *ExportChunk) {
			c.Ordinal = 2
			c.FirstEvent = 3
			c.Events[0].Ordinal = 3
			c.Events[1].Ordinal = 4
		},
		"nonzero previous on first": func(c *ExportChunk) { c.PreviousDigest = strings.Repeat("1", 64) },
		"time ascending":            func(c *ExportChunk) { c.Events[1].OccurredAt = "2026-09-13T08:09:10.123456Z" },
		"time offset":               func(c *ExportChunk) { c.Events[0].OccurredAt = "2026-09-12T08:09:10.123456+00:00" },
		"time nanos":                func(c *ExportChunk) { c.Events[0].OccurredAt = "2026-09-12T08:09:10.123456789Z" },
		"time no fraction":          func(c *ExportChunk) { c.Events[0].OccurredAt = "2026-09-12T08:09:10Z" },
		"nil metadata":              func(c *ExportChunk) { c.Events[0].Metadata = nil },
		"unredacted":                func(c *ExportChunk) { c.Events[0].Metadata["token"] = "private-fixture" },
		"bad outcome":               func(c *ExportChunk) { c.Events[0].Outcome = "rejected" },
		"bad action":                func(c *ExportChunk) { c.Events[0].Action = "Policy.update" },
		"invalid utf8":              func(c *ExportChunk) { c.Events[0].Metadata["a"] = string([]byte{255}) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c := exportTestChunk()
			change(&c)
			if _, err := EncodeExportChunk(c); err == nil {
				t.Fatal("accepted invalid chunk")
			}
			body, _ := json.Marshal(c)
			if _, err := DecodeExportChunk(body); err == nil {
				t.Fatal("decoded invalid chunk")
			}
		})
	}
	// Audit exports are org-wide, not incorrectly restricted to artifact workspace.
	c := exportTestChunk()
	c.Events[1].WorkspaceID = exportTestID(90)
	c.Events[1].EnvironmentID = exportTestID(91)
	if _, err := EncodeExportChunk(c); err != nil {
		t.Fatal("rejected authorized organization-wide event")
	}
}

func TestExportClosedCanonicalJSON(t *testing.T) {
	body, err := EncodeExportChunk(exportTestChunk())
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{
		"whitespace": append([]byte(" "), body...), "trailing": append(bytes.Clone(body), '\n'),
		"duplicate":        bytes.Replace(body, []byte(`"ordinal":1`), []byte(`"ordinal":1,"ordinal":1`), 1),
		"alias root":       bytes.Replace(body, []byte(`"schema"`), []byte(`"Schema"`), 1),
		"alias binding":    bytes.Replace(body, []byte(`"organization_id"`), []byte(`"Organization_id"`), 1),
		"alias nested":     bytes.Replace(body, []byte(`"actor_id"`), []byte(`"Actor_id"`), 1),
		"alias overwrite":  bytes.Replace(body, []byte(`"event_count":2`), []byte(`"event_count":1,"Event_count":2`), 1),
		"unknown":          bytes.Replace(body, []byte(`"schema":`), []byte(`"unknown":1,"schema":`), 1),
		"alternate escape": bytes.Replace(body, []byte(`"policy.update"`), []byte(`"\u0070olicy.update"`), 1),
		"second value":     append(bytes.Clone(body), []byte(`{}`)...),
	}
	for name, bad := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExportChunk(bad); err == nil {
				t.Fatal("accepted noncanonical wire")
			}
		})
	}
}

func TestExportManifestEmptyAndBoundChain(t *testing.T) {
	empty := ExportManifest{ExportManifestSchema, exportTestBinding(), 0, 0, 0, ExportZeroDigest}
	body, err := EncodeExportManifest(empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyExportManifest(body, empty, exportDigest(body)); err != nil {
		t.Fatal(err)
	}
	c := exportTestChunk()
	chunk, err := EncodeExportChunk(c)
	if err != nil {
		t.Fatal(err)
	}
	m := ExportManifest{ExportManifestSchema, c.Binding, 2, 1, int64(len(chunk)), exportDigest(chunk)}
	body, err = EncodeExportManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyExportManifest(body, m, exportDigest(body)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"scope", "root", "count", "bytes", "digest"} {
		t.Run(field, func(t *testing.T) {
			expected := m
			digest := exportDigest(body)
			switch field {
			case "scope":
				expected.Binding.OrganizationID = exportTestID(90)
			case "root":
				expected.ChainRoot = strings.Repeat("1", 64)
			case "count":
				expected.EventCount++
			case "bytes":
				expected.ChunkBytes++
			case "digest":
				digest = strings.Repeat("1", 64)
			}
			if _, err := VerifyExportManifest(body, expected, digest); err == nil {
				t.Fatal("accepted manifest authority tamper")
			}
		})
	}
	for _, bad := range []ExportManifest{
		{ExportManifestSchema, m.Binding, 1, 0, 0, ExportZeroDigest},
		{ExportManifestSchema, m.Binding, 0, 1, 1, m.ChainRoot},
		{ExportManifestSchema, m.Binding, 1001, 1, 1000, m.ChainRoot},
		{ExportManifestSchema, m.Binding, 2, 1, ExportMaximumChunkBytes + 1, m.ChainRoot},
		{ExportManifestSchema, m.Binding, 2, 1, 1000, ExportZeroDigest},
	} {
		if _, err := EncodeExportManifest(bad); err == nil {
			t.Fatal("accepted inconsistent manifest")
		}
	}
}

func TestExportChunkBoundsBeforeDecodeAndAtExactByteLimit(t *testing.T) {
	c := exportTestChunk()
	c.Events = nil
	for n := 1; n <= 1000; n++ {
		c.Events = append(c.Events, exportTestEvent(n))
	}
	c.EventCount = 1000
	if _, err := EncodeExportChunk(c); err != nil {
		t.Fatalf("1000 bounded events: %v", err)
	}
	c.Events = append(c.Events, exportTestEvent(1001))
	c.EventCount = 1001
	if _, err := EncodeExportChunk(c); err == nil {
		t.Fatal("accepted 1001 events")
	}
	c.Events = c.Events[:70]
	c.EventCount = 70
	var exact []byte
	for n := range c.Events {
		c.Events[n].Metadata = map[string]string{}
		for key := 0; key < 32; key++ {
			k := fmt.Sprintf("field%02d", key)
			c.Events[n].Metadata[k] = strings.Repeat("x", 512)
			body, _ := json.Marshal(c)
			if len(body) >= 1<<20 {
				over := len(body) - (1 << 20)
				if over >= 512 {
					t.Fatal("invalid test fixture sizing")
				}
				c.Events[n].Metadata[k] = strings.Repeat("x", 512-over)
				exact, _ = json.Marshal(c)
				break
			}
		}
		if exact != nil {
			break
		}
	}
	if len(exact) != 1<<20 {
		t.Fatal("failed to construct exact boundary")
	}
	encoded, err := EncodeExportChunk(c)
	if err != nil || !bytes.Equal(encoded, exact) {
		t.Fatal("rejected exact byte bound")
	}
	if _, err := DecodeExportChunk(exact); err != nil {
		t.Fatal("failed to decode exact bound")
	}
	if _, err := DecodeExportChunk(append(exact, ' ')); err == nil {
		t.Fatal("accepted oversized body")
	}
	// A valid extra byte, not only trailing whitespace, must exceed the encoder cap.
	c.Events[69].TargetID += "x"
	if _, err := EncodeExportChunk(c); err == nil {
		t.Fatal("encoded oversized chunk")
	}
}

// A decoder ceiling must cover the encoder's legal JSON escaping expansion.
func TestExportEventEscapedMetadataStillRoundTrips(t *testing.T) {
	e := exportTestEvent(1)
	e.Metadata = map[string]string{}
	for n := 0; n < 32; n++ {
		e.Metadata[fmt.Sprintf("field%02d", n)] = strings.Repeat("<", 512)
	}
	body, err := EncodeExportEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 32768 {
		t.Fatal("fixture did not exercise escaping expansion")
	}
	if _, err := DecodeExportEvent(body); err != nil {
		t.Fatal("encoder produced event rejected by decoder")
	}
}

func TestExportProjectionRejectsMalformedSecretBeforeRedaction(t *testing.T) {
	e := exportTestEvent(1)
	e.Metadata["token"] = string([]byte{255})
	if _, err := ProjectExportEvent(e); err == nil {
		t.Fatal("redaction concealed malformed source UTF-8")
	}
}

func TestExportTwoChunkChainRejectsRewrittenSubset(t *testing.T) {
	first := exportTestChunk()
	firstBody, err := EncodeExportChunk(first)
	if err != nil {
		t.Fatal(err)
	}
	second := ExportChunk{ExportChunkSchema, first.Binding, 2, 3, 2, exportDigest(firstBody), []ExportEvent{exportTestEvent(3), exportTestEvent(4)}}
	secondBody, err := EncodeExportChunk(second)
	if err != nil {
		t.Fatal(err)
	}
	expected := exportExpected(second, secondBody)
	if _, err := VerifyExportChunk(secondBody, expected); err != nil {
		t.Fatal(err)
	}
	manifest := ExportManifest{ExportManifestSchema, first.Binding, 4, 2, int64(len(firstBody) + len(secondBody)), exportDigest(secondBody)}
	mBody, err := EncodeExportManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyExportManifest(mBody, manifest, exportDigest(mBody)); err != nil {
		t.Fatal(err)
	}
	// Even a self-consistent rewritten count/range/chain must fail persisted pins.
	for _, kind := range []string{"missing", "changed event", "changed predecessor"} {
		t.Run(kind, func(t *testing.T) {
			var changed ExportChunk
			if err := json.Unmarshal(secondBody, &changed); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				changed.Events = changed.Events[:1]
				changed.EventCount = 1
			case "changed event":
				changed.Events[0].TargetID = "different-target"
			case "changed predecessor":
				changed.PreviousDigest = strings.Repeat("a", 64)
			}
			body, err := EncodeExportChunk(changed)
			if err != nil {
				t.Fatal("tampered fixture should be structurally valid")
			}
			if _, err := VerifyExportChunk(body, expected); err == nil {
				t.Fatal("accepted rewritten immutable content")
			}
		})
	}
}

func TestExportEventAndManifestClosedWire(t *testing.T) {
	e := exportTestEvent(1)
	e.Metadata = map[string]string{"schema": "literal", "Schema": "also literal"}
	eBody, err := EncodeExportEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeExportEvent(eBody); err != nil {
		t.Fatal("opaque metadata keys were treated as wire aliases")
	}
	m := ExportManifest{ExportManifestSchema, exportTestBinding(), 0, 0, 0, ExportZeroDigest}
	mBody, err := EncodeExportManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		body   []byte
		decode func([]byte) error
	}{
		{"event", eBody, func(b []byte) error { _, err := DecodeExportEvent(b); return err }},
		{"manifest", mBody, func(b []byte) error { _, err := DecodeExportManifest(b); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for name, body := range map[string][]byte{
				"alias":           bytes.Replace(test.body, []byte(`"organization_id"`), []byte(`"Organization_id"`), 1),
				"duplicate":       bytes.Replace(test.body, []byte(`"organization_id":`), []byte(`"organization_id":"ignored","organization_id":`), 1),
				"alias overwrite": bytes.Replace(test.body, []byte(`"organization_id":`), []byte(`"organization_id":"ignored","Organization_id":`), 1),
				"unknown":         append([]byte(`{"unknown":true,`), test.body[1:]...),
				"missing":         []byte(`{}`), "null": []byte(`null`),
				"extra": append(bytes.Clone(test.body), []byte(` null`)...),
			} {
				t.Run(name, func(t *testing.T) {
					if test.decode(body) == nil {
						t.Fatal("accepted noncanonical closed wire")
					}
				})
			}
		})
	}
}

func TestExportRejectsInvalidScalarAndBindingContracts(t *testing.T) {
	for name, change := range map[string]func(*ExportEvent){
		"actor":                  func(e *ExportEvent) { e.ActorID = "external-actor" },
		"target empty":           func(e *ExportEvent) { e.TargetID = "" },
		"target oversized":       func(e *ExportEvent) { e.TargetID = strings.Repeat("x", 129) },
		"target control":         func(e *ExportEvent) { e.TargetID = "a\nb" },
		"metadata oversized":     func(e *ExportEvent) { e.Metadata["a"] = strings.Repeat("x", 513) },
		"metadata key oversized": func(e *ExportEvent) { e.Metadata[strings.Repeat("k", 65)] = "x" },
		"metadata count": func(e *ExportEvent) {
			for i := 0; i < 33; i++ {
				e.Metadata[fmt.Sprintf("key%d", i)] = "x"
			}
		},
		"metadata control": func(e *ExportEvent) { e.Metadata["a"] = "tab\tvalue" },
		"date impossible":  func(e *ExportEvent) { e.OccurredAt = "2026-02-30T08:09:10.123456Z" },
		"date year zero":   func(e *ExportEvent) { e.OccurredAt = "0000-09-12T08:09:10.123456Z" },
		"ordinal unsafe":   func(e *ExportEvent) { e.Ordinal = 1 << 53 },
	} {
		t.Run(name, func(t *testing.T) {
			e := exportTestEvent(1)
			change(&e)
			if _, err := EncodeExportEvent(e); err == nil {
				t.Fatal("accepted invalid public projection")
			}
		})
	}
	for name, change := range map[string]func(*ExportChunk){
		"bad export":       func(c *ExportChunk) { c.Binding.ExportID = "other" },
		"bad capture":      func(c *ExportChunk) { c.Binding.CaptureID = "other" },
		"aliased identity": func(c *ExportChunk) { c.Binding.CaptureID = c.Binding.ExportID },
		"scope alias":      func(c *ExportChunk) { c.Binding.EnvironmentID = c.Binding.WorkspaceID },
		"digest uppercase": func(c *ExportChunk) { c.PreviousDigest = strings.Repeat("A", 64) },
		"digest short":     func(c *ExportChunk) { c.PreviousDigest = "00" },
		"unsafe range":     func(c *ExportChunk) { c.FirstEvent = 1 << 53 },
		"impossible predecessor range": func(c *ExportChunk) {
			c.Ordinal = 2
			c.FirstEvent = 1002
			c.Events[0].Ordinal = 1002
			c.Events[1].Ordinal = 1003
			c.PreviousDigest = strings.Repeat("a", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := exportTestChunk()
			change(&c)
			if _, err := EncodeExportChunk(c); err == nil {
				t.Fatal("accepted invalid binding or range")
			}
		})
	}
}

func TestExportChunkRejectsOversizedEventArrayBeforeAllocation(t *testing.T) {
	// A short wire array of nulls must not allocate tens of thousands of large
	// ExportEvent structs before the 1000-event contract rejects it.
	body := []byte(`{"events":[` + strings.Repeat("null,", 49999) + `null]}`)
	measurement := testing.Benchmark(func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			if _, err := DecodeExportChunk(body); err == nil {
				b.Fatal("accepted oversized array")
			}
		}
	})
	if measurement.AllocedBytesPerOp() > 4<<20 {
		t.Fatalf("oversized event array allocated %d bytes before rejection", measurement.AllocedBytesPerOp())
	}
}
