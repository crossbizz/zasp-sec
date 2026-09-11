package main

import (
	"bytes"
	"encoding/json"
)

// The private namespace authenticates pre-source startup state. Once any
// enrollment bytes exist, a scoped controller must match every present byte.
func lineageReservationEnrollmentMatches(raw []byte, id, enrollment string) bool {
	prefix := []byte(`{"version":"tetragon-spool-v1","record_format":"zasp-tetragon-record-v1","source":{"profile":"tetragon-local-stream-v1","generation_id":"` + id + `","enrollment_binding":"` + enrollment + `"`)
	n := min(len(raw), len(prefix))
	return enrollmentBindingPattern.MatchString(enrollment) && bytes.Equal(raw[:n], prefix[:n])
}

// Only prefixes of this exact canonical manifest grammar are startup scratch.
// The UUID is fixed by the private directory name, even when partly written.
// All accepted source fields are ASCII and need no JSON string escapes.
func validLineageReservationMetadata(name string, raw []byte, id string) bool {
	if len(raw) > 4096 {
		return false
	}
	if name == "manifest.json" || json.Valid(raw) {
		var manifest lineageSpoolManifest
		if !lineageDecodeCanonical(raw, &manifest) || manifest.Source.GenerationID != id {
			return false
		}
		expected, err := lineageManifestBytes(manifest.Source)
		return err == nil && bytes.Equal(raw, expected)
	}
	if name != ".pending" {
		return false
	}
	p := lineageManifestPrefix{raw: raw}
	if !p.literal(`{"version":"tetragon-spool-v1","record_format":"zasp-tetragon-record-v1","source":{"profile":"tetragon-local-stream-v1","generation_id":"` + id + `","enrollment_binding":"`) {
		return false
	}
	if p.done {
		return true
	}
	fields := []struct {
		next string
		kind string
	}{
		{`","node_name":"`, "binding"},
		{`","cluster_uid":"`, "node"},
		{`","node_uid":"`, "uuid"},
		{`","boot_id":"`, "uuid"},
		{`"}}`, "uuid"},
	}
	for _, field := range fields {
		if !p.value(field.kind) {
			return false
		}
		if p.done {
			return true
		}
		if !p.literal(field.next) {
			return false
		}
		if p.done {
			return true
		}
	}
	return p.offset == len(raw)
}

type lineageManifestPrefix struct {
	raw    []byte
	offset int
	done   bool
}

func (p *lineageManifestPrefix) literal(expected string) bool {
	remaining := p.raw[p.offset:]
	n := min(len(remaining), len(expected))
	if !bytes.Equal(remaining[:n], []byte(expected)[:n]) {
		return false
	}
	p.offset += n
	p.done = p.offset == len(p.raw)
	return n == len(expected) || p.done
}
func (p *lineageManifestPrefix) value(kind string) bool {
	remaining := p.raw[p.offset:]
	n := bytes.IndexByte(remaining, '"')
	complete := n >= 0
	if !complete {
		n = len(remaining)
	}
	value := remaining[:n]
	if !validLineageManifestValuePrefix(value, kind, complete) {
		return false
	}
	p.offset += n
	p.done = !complete
	return true
}
func validLineageManifestValuePrefix(raw []byte, kind string, complete bool) bool {
	maximum := 36
	if kind == "binding" {
		maximum = 64
	}
	if kind == "node" {
		maximum = 253
	}
	if len(raw) > maximum {
		return false
	}
	for index, char := range raw {
		if kind == "node" {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || index > 0 && (char == '-' || char == '.')) {
				return false
			}
		} else if kind == "uuid" && (index == 8 || index == 13 || index == 18 || index == 23) {
			if char != '-' {
				return false
			}
		} else if !(char >= 'a' && char <= 'f' || char >= '0' && char <= '9') {
			return false
		}
	}
	if kind == "node" {
		return !complete && len(raw) < maximum || validKubernetesName(string(raw))
	}
	if !complete && len(raw) < maximum {
		return true
	}
	if kind == "binding" {
		return len(raw) == 64
	}
	return validLineageUUID(string(raw))
}
