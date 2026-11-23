package addons

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

type bundleEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func zipped(t *testing.T, entries ...bundleEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, entry := range entries {
		h := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode != 0 {
			h.SetMode(entry.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func archiveScan(body []byte) Report {
	sum := sha256.Sum256(body)
	return ScanArchive(bytes.NewReader(body), int64(len(body)), "sha256:"+hex.EncodeToString(sum[:]))
}

func TestArchiveMatchesCompleteOnDiskBundle(t *testing.T) {
	r := skill(t)
	guide := []byte("reference")
	write(t, r, "docs/guide.txt", string(guide))
	input := zipped(t, bundleEntry{"docs/guide.txt", guide, 0600}, bundleEntry{"SKILL.md", []byte("# Ticket helper\n"), 0600})
	got := archiveScan(input)
	local := Scan(r)
	if got.Status != "complete" || got.ManifestDigest != local.ManifestDigest {
		t.Fatalf("archive %+v local %+v", got, local)
	}
	bad := ScanArchive(bytes.NewReader(input), int64(len(input)), "sha256:"+string(bytes.Repeat([]byte{'0'}, 64)))
	requirePartial(t, bad, "archive_digest_mismatch")
	bad = ScanArchive(bytes.NewReader(input), int64(len(input)-1), "sha256:"+string(bytes.Repeat([]byte{'0'}, 64)))
	requirePartial(t, bad, "archive_size_mismatch")
}
func TestArchiveRejectsAmbiguityAndNeverReadsSkippedMembers(t *testing.T) {
	base := bundleEntry{"SKILL.md", []byte("local"), 0600}
	for _, tc := range []struct {
		extra bundleEntry
		want  string
	}{
		{bundleEntry{"../elsewhere", []byte("outside"), 0600}, "nonportable_name"},
		{bundleEntry{"local/.env", []byte("private"), 0600}, "excluded_private"},
		{bundleEntry{"link", []byte("elsewhere"), os.ModeSymlink | 0777}, "unsupported_file_type"},
		{bundleEntry{"SKILL.md", []byte("duplicate"), 0600}, "path_collision"},
		{bundleEntry{"skill.md", []byte("case alias"), 0600}, "path_collision"},
		{bundleEntry{"large", bytes.Repeat([]byte{'0'}, maxFileBytes+1), 0600}, "file_size_limit"},
	} {
		t.Run(tc.want+tc.extra.name, func(t *testing.T) {
			r := archiveScan(zipped(t, base, tc.extra))
			requirePartial(t, r, tc.want)
			if len(r.Files) != 1 {
				t.Fatal("unexpected members")
			}
		})
	}
	input := zipped(t, base, bundleEntry{"guide", []byte("legal fixture"), 0600})
	end := len(input) - 22
	for _, count := range []uint16{1, maxEntries + 1} {
		binary.LittleEndian.PutUint16(input[end+10:end+12], count)
		binary.LittleEndian.PutUint16(input[end+8:end+10], count)
		requirePartial(t, archiveScan(input), "unsupported_archive_directory")
	}
}
