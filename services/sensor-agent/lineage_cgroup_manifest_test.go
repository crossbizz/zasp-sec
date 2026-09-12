package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLineageCgroupVersionedManifestAndEveryStartupPrefix(t *testing.T) {
	for _, version := range []string{"1", "2", "3"} {
		source := lineageSpoolSource()
		source.Profile = "tetragon-local-stream-v" + version
		manifest, err := lineageManifestBytes(source)
		if err != nil || !bytes.Contains(manifest, []byte(`"record_format":"zasp-tetragon-record-v`+version+`"`)) {
			t.Fatal("source profile wasn't bound to its record format", err)
		}
		for length := 0; length <= len(manifest); length++ {
			prefix := manifest[:length]
			if !validLineageReservationMetadata(".pending", prefix, source.GenerationID) || !lineageReservationEnrollmentMatches(prefix, source.GenerationID, source.EnrollmentBinding) {
				t.Fatalf("version %s startup prefix %d isn't recoverable", version, length)
			}
		}
		if lineageReservationEnrollmentMatches(manifest, source.GenerationID, strings.Repeat("c", 64)) {
			t.Fatal("new manifest lost enrollment binding")
		}
		other := "1"
		if version == "1" {
			other = "2"
		}
		mixed := bytes.Replace(manifest, []byte(`zasp-tetragon-record-v`+version), []byte(`zasp-tetragon-record-v`+other), 1)
		if validLineageReservationMetadata("manifest.json", mixed, source.GenerationID) {
			t.Fatal("source/format mismatch accepted")
		}
	}
}

func TestLineageCgroupActualSpoolReaderBindsNewFormat(t *testing.T) {
	root := t.TempDir()
	spool, err := newLineageSpool(root, uint32(os.Getuid()))
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
	line, err := sanitizeLineageEvent(lineageCgroupProviderFixture(^uint64(0)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal(err)
	}
	generation.Close()
	path := filepath.Join(root, "generation-"+source.GenerationID)
	before := recoveryEvidence(t, path)
	reader, err := newLineageSpoolReader(path, source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if reader.Source() != source {
		t.Fatal("reader changed immutable generation profile")
	}
	reader.Close()
	if !bytes.Equal(before, recoveryEvidence(t, path)) {
		t.Fatal("opening reader changed evidence")
	}
}
