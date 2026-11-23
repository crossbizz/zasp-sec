package addons

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	"io/fs"
	"slices"
	"strings"
)

// MaxArchiveBytes is the compressed transfer limit for a private static scan.
const MaxArchiveBytes int64 = 8 << 20

// ScanArchive binds the upload to its expected size and archive digest before
// opening any member. The worker enumerates in memory and never extracts files,
// executes scripts, follows links or resolves external dependencies.
func ScanArchive(input io.Reader, size int64, expectedDigest string) Report {
	s := newScanner()
	if input == nil || size <= 0 || size > MaxArchiveBytes || len(expectedDigest) != 71 || !strings.HasPrefix(expectedDigest, "sha256:") {
		s.skip(".", "invalid_archive_binding")
		return s.report
	}
	body, err := io.ReadAll(io.LimitReader(input, size+1))
	if err != nil || int64(len(body)) != size {
		s.skip(".", "archive_size_mismatch")
		return s.report
	}
	sum := sha256.Sum256(body)
	actual := "sha256:" + hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expectedDigest)) != 1 {
		s.skip(".", "archive_digest_mismatch")
		return s.report
	}
	if !boundedZIPDirectory(body) {
		s.skip(".", "unsupported_archive_directory")
		return s.report
	}
	archive, err := zip.NewReader(bytes.NewReader(body), size)
	if err != nil || len(archive.File) > maxEntries {
		s.skip(".", "invalid_archive")
		return s.report
	}
	entries := slices.Clone(archive.File)
	slices.SortFunc(entries, func(a, b *zip.File) int { return strings.Compare(a.Name, b.Name) })
	// Track implicit directories as well as explicitly listed members. Two
	// differently cased paths or a file/directory alias cannot form a version.
	paths := map[string]string{}
	files := map[string]bool{}
	explicit := map[string]bool{}
	found := false
	for _, entry := range entries {
		if !s.withinTime() {
			break
		}
		dir := strings.HasSuffix(entry.Name, "/")
		name := strings.TrimSuffix(entry.Name, "/")
		parts := strings.Split(name, "/")
		if !fs.ValidPath(name) || name == "." || len(parts) > maxDepth+1 || len(name) > 4096 || slices.ContainsFunc(parts, func(v string) bool { return !portableName(v) }) {
			s.skip(".", "nonportable_name")
			continue
		}
		ambiguous := explicit[name]
		explicit[name] = true
		for i := range parts {
			p := strings.Join(parts[:i+1], "/")
			folded := foldName(p)
			if previous, ok := paths[folded]; ok && previous != p {
				ambiguous = true
			}
			if i < len(parts)-1 && files[p] {
				ambiguous = true
			}
			paths[folded] = p
		}
		if len(paths) > maxEntries {
			s.stop(".", "entry_limit")
			break
		}
		if ambiguous {
			s.skip(name, "path_collision")
			continue
		}
		if slices.ContainsFunc(parts, excluded) {
			s.skip(name, "excluded_private")
			continue
		}
		if !dir {
			files[name] = true
		}
		if entry.Flags&1 != 0 {
			s.skip(name, "encrypted_member")
			continue
		}
		if dir {
			if !entry.Mode().IsDir() || entry.UncompressedSize64 != 0 {
				s.skip(name, "unsupported_file_type")
			}
			continue
		}
		if !entry.Mode().IsRegular() {
			s.skip(name, "unsupported_file_type")
			continue
		}
		if entry.UncompressedSize64 > maxFileBytes {
			s.skip(name, "file_size_limit")
			continue
		}
		if entry.UncompressedSize64 > uint64(maxBundleBytes-s.used) {
			s.stop(name, "byte_limit")
			break
		}
		r, err := entry.Open()
		if err != nil {
			s.skip(name, "unreadable_member")
			continue
		}
		member, err := io.ReadAll(io.LimitReader(r, int64(entry.UncompressedSize64)+1))
		r.Close()
		if err != nil || uint64(len(member)) != entry.UncompressedSize64 {
			s.skip(name, "unreadable_member")
			continue
		}
		s.used += int64(len(member))
		hash := sha256.Sum256(member)
		s.report.Files = append(s.report.Files, File{name, int64(len(member)), hex.EncodeToString(hash[:]), entry.Mode()&0111 != 0})
		s.inspect(name, member)
		found = found || name == "SKILL.md"
	}
	if !found {
		s.skip("SKILL.md", "missing_entry")
	}
	s.finish()
	return s.report
}

// ZIP directory metadata itself is untrusted. archive/zip can enumerate more
// headers than the trailing count claims. Bound both before constructing it.
func boundedZIPDirectory(b []byte) bool {
	const endHeader = 22
	const memberHeader = 46
	if len(b) < endHeader {
		return false
	}
	last := len(b) - endHeader
	for end := last; end >= max(0, last-65535); end-- {
		if !bytes.HasPrefix(b[end:], []byte{'P', 'K', 5, 6}) {
			continue
		}
		info := b[end:]
		if int(binary.LittleEndian.Uint16(info[20:22])) != last-end {
			continue
		}
		count := int(binary.LittleEndian.Uint16(info[10:12]))
		if binary.LittleEndian.Uint32(info[4:8]) != 0 || binary.LittleEndian.Uint16(info[8:10]) != uint16(count) || count < 1 || count > maxEntries {
			return false
		}
		size := int64(binary.LittleEndian.Uint32(info[12:16]))
		start := int64(binary.LittleEndian.Uint32(info[16:20]))
		if start+size != int64(end) {
			return false
		}
		tail := b[start:end]
		for range count {
			if len(tail) < memberHeader || !bytes.HasPrefix(tail, []byte{'P', 'K', 1, 2}) {
				return false
			}
			width := memberHeader + int(binary.LittleEndian.Uint16(tail[28:30])) + int(binary.LittleEndian.Uint16(tail[30:32])) + int(binary.LittleEndian.Uint16(tail[32:34]))
			if width > len(tail) {
				return false
			}
			tail = tail[width:]
		}
		return len(tail) == 0
	}
	return false
}

// PrivateSummary is the only report returned across a private worker boundary.
// Rule and coverage-reason identifiers come from the scanner's closed catalog.
type PrivateSummary struct {
	Schema   string         `json:"schema_version"`
	Status   string         `json:"status"`
	Rules    string         `json:"ruleset"`
	Method   string         `json:"manifest_method"`
	Digest   string         `json:"manifest_digest,omitempty"`
	Counts   map[string]int `json:"rule_counts"`
	Skipped  map[string]int `json:"skipped_counts"`
	Advisory string         `json:"advisory_status"`
}

func (r Report) PrivateSummary() PrivateSummary {
	out := PrivateSummary{"zasp-private-scan.v1", r.Status, r.Ruleset, r.ManifestMethod, r.ManifestDigest, map[string]int{}, map[string]int{}, r.AdvisoryStatus}
	for _, finding := range r.Findings {
		out.Counts[finding.RuleID]++
	}
	for _, skip := range r.Skipped {
		out.Skipped[skip.Reason]++
	}
	return out
}
