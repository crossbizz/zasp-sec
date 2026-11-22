// Package addons inspects a selected add-on without running it or contacting a service.
package addons

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	manifestVersion = "addon-manifest.v1"
	maxEntries      = 1024
	maxDepth        = 20
	maxFileBytes    = 2 << 20
	maxBundleBytes  = 12 << 20
	maxScanTime     = 5 * time.Second
)

type Report struct {
	SchemaVersion    string            `json:"schema_version"`
	Status           string            `json:"status"`
	ManifestMethod   string            `json:"manifest_method"`
	ManifestDigest   string            `json:"manifest_digest,omitempty"`
	Ruleset          string            `json:"ruleset"`
	Usage            string            `json:"usage"`
	AdvisoryCoverage *AdvisoryCoverage `json:"advisory_coverage,omitempty"`
	AdvisoryStatus   string            `json:"advisory_status"`
	Files            []File            `json:"files"`
	Findings         []Finding         `json:"findings"`
	Skipped          []Skip            `json:"skipped"`
	Dependencies     []Dependency      `json:"dependencies"`
}

type File struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}
type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}
type Dependency struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	// Version is populated only when the declaration pins a recognized literal.
	Version string `json:"version,omitempty"`
	Path    string `json:"path"`
}

type observedEntry struct {
	path string
	info fs.FileInfo
}

type scanner struct {
	observations []observedEntry
	issues       map[Skip]bool
	report       Report
	seen         int
	used         int64
	deadline     time.Time
	stopped      bool
}

func newScanner() *scanner {
	return &scanner{issues: make(map[Skip]bool), deadline: time.Now().Add(maxScanTime), report: Report{
		SchemaVersion: "zasp-addon-scan.v1", Status: "complete", ManifestMethod: manifestVersion,
		Ruleset: "zasp-static.v1", Usage: "unknown", AdvisoryStatus: "not_evaluated_no_offline_snapshot",
		Files: []File{}, Findings: []Finding{}, Skipped: []Skip{}, Dependencies: []Dependency{},
	}}
}

// Scan accepts a skill directory, its SKILL.md, or a supported MCP declaration.
func Scan(path string) Report {
	s := newScanner()
	if path == "" {
		s.skip(".", "invalid_path")
		return s.report
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		s.skip(".", "invalid_path")
		return s.report
	}
	base := filepath.VolumeName(absolute) + string(filepath.Separator)
	r, err := os.OpenRoot(base)
	if err != nil {
		s.skip(".", reason(err))
		return s.report
	}
	defer r.Close()
	rel, err := filepath.Rel(base, absolute)
	if err != nil {
		s.skip(".", "invalid_path")
		return s.report
	}
	return ScanIn(r, rel)
}

// ScanIn preserves the caller's pinned trust boundary. Every directory component
// is opened and checked before being used to enumerate or read any contents.
func ScanIn(root *os.Root, rel string) Report {
	s := newScanner()
	if root == nil || !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		s.skip(".", "invalid_path")
		return s.report
	}
	components := strings.Split(rel, string(filepath.Separator))
	for _, component := range components[:len(components)-1] {
		next, why := OpenDirectory(root, component)
		if why != "" {
			s.skip(".", why)
			return s.report
		}
		defer next.Close()
		root = next
	}
	name := components[len(components)-1]
	info, err := root.Lstat(name)
	if err != nil {
		s.skip(".", reason(err))
		return s.report
	}
	switch {
	case IsLink(info):
		s.skip(".", "symlink")
	case info.IsDir():
		dir, why := OpenDirectory(root, name)
		if why != "" {
			s.skip(".", why)
			break
		}
		defer dir.Close()
		s.skill(dir)
		if !sameEntry(root, name, info) {
			s.skip(".", "changed_during_scan")
		}
	case info.Mode().IsRegular() && name == "SKILL.md":
		s.skill(root)
	case info.Mode().IsRegular() && isMCP(name):
		s.file(root, name, name, info)
	default:
		s.skip(".", "unsupported_bundle")
	}
	s.finish()
	return s.report
}

func reason(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "missing"
	}
	return "unreadable"
}

// OpenDirectory pins one non-link child of parent and verifies its identity.
func OpenDirectory(parent *os.Root, name string) (*os.Root, string) {
	if parent == nil || !filepath.IsLocal(name) || filepath.Base(name) != name {
		return nil, "invalid_path"
	}
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, reason(err)
	}
	if IsLink(before) {
		return nil, "symlink"
	}
	if !before.IsDir() {
		return nil, "not_directory"
	}
	// The trailing separator requires a directory during pathname resolution.
	dir, err := parent.OpenRoot(name + string(filepath.Separator) + ".")
	if err != nil {
		return nil, reason(err)
	}
	pinned, pinErr := dir.Stat(".")
	current, linkErr := parent.Lstat(name)
	// Ancestors can gain an unrelated sibling while being pinned. The
	// directory identity and link checks establish this handle's boundary.
	// Enumeration of a selected directory still checks its own revision.
	if pinErr != nil || linkErr != nil || IsLink(current) || !current.IsDir() ||
		!os.SameFile(before, pinned) || !os.SameFile(before, current) {
		dir.Close()
		return nil, "changed_during_scan"
	}
	return dir, ""
}

func sameEntry(root *os.Root, name string, was fs.FileInfo) bool {
	info, err := root.Lstat(name)
	return err == nil && sameInfo(was, info)
}
func sameInfo(a, b fs.FileInfo) bool {
	return !IsLink(b) && os.SameFile(a, b) && a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime())
}

func (s *scanner) skill(dir *os.Root) {
	entry, err := dir.Lstat("SKILL.md")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.skip("SKILL.md", "missing_entry")
		} else {
			s.skip("SKILL.md", reason(err))
		}
		return
	}
	if IsLink(entry) || !entry.Mode().IsRegular() {
		s.skip("SKILL.md", "unsupported_entry")
		return
	}
	s.walk(dir, "", 0)
	// Recheck the entire bounded tree. Changes to an older nested file can leave
	// the modification times of all ancestor directories untouched.
	for _, observed := range s.observations {
		if !s.withinTime() {
			break
		}
		if !sameEntry(dir, filepath.FromSlash(observed.path), observed.info) {
			s.skip(observed.path, "changed_during_scan")
		}
	}
}

func (s *scanner) skip(path, reason string) {
	s.report.Status = "partial"
	issue := Skip{path, reason}
	if !s.issues[issue] {
		s.issues[issue] = true
		s.report.Skipped = append(s.report.Skipped, issue)
	}
}

func (s *scanner) stop(path, why string) {
	if !s.stopped {
		s.skip(path, why)
		s.stopped = true
	}
}

func (s *scanner) withinTime() bool {
	if !s.stopped && time.Now().After(s.deadline) {
		s.stop(".", "time_limit")
	}
	return !s.stopped
}

func (s *scanner) walk(root *os.Root, prefix string, depth int) {
	if !s.withinTime() {
		return
	}
	before, err := root.Stat(".")
	if err != nil {
		s.skip(display(prefix), reason(err))
		return
	}
	d, err := root.Open(".")
	if err != nil {
		s.skip(display(prefix), reason(err))
		return
	}
	defer d.Close()
	// Read at most the remaining allowance plus one entry, even on a huge directory.
	remaining := maxEntries - s.seen
	items, err := d.ReadDir(remaining + 1)
	if err != nil && err != io.EOF {
		s.skip(display(prefix), reason(err))
		return
	}
	if len(items) > remaining {
		s.stop(display(prefix), "entry_limit")
		return
	}
	s.seen += len(items)
	slices.SortFunc(items, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	keys := map[string]bool{}
	s.observations = append(s.observations, observedEntry{display(prefix), before})
	for _, item := range items {
		if !s.withinTime() {
			break
		}
		name := item.Name()
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		if !portableName(name) {
			s.skip(display(prefix), "nonportable_name")
			continue
		}
		key := foldName(name)
		if keys[key] {
			s.skip(path, "path_collision")
			continue
		}
		keys[key] = true
		if excluded(name) {
			s.skip(path, "excluded_private")
			continue
		}
		info, err := root.Lstat(name)
		if err != nil {
			s.skip(path, reason(err))
			continue
		}

		switch {
		case IsLink(info):
			s.skip(path, "symlink")
		case info.IsDir():
			if depth >= maxDepth {
				s.skip(path, "depth_limit")
				continue
			}
			dir, why := OpenDirectory(root, name)
			if why != "" {
				s.skip(path, why)
				continue
			}
			s.walk(dir, path, depth+1)
			dir.Close()
		case info.Mode().IsRegular():
			s.file(root, name, path, info)
		default:
			s.skip(path, "unsupported_file_type")
		}
	}

	if !sameEntry(root, ".", before) {
		s.skip(display(prefix), "changed_during_scan")
	}
}

func display(p string) string {
	if p == "" {
		return "."
	}
	return p
}

func portableName(n string) bool {
	base, _, _ := strings.Cut(strings.ToUpper(n), ".")
	switch base {
	case "NUL", "AUX", "CON", "PRN", "CLOCK$":
		return false
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
		return false
	}
	if !utf8.ValidString(n) || strings.ContainsAny(n, "\\:<>|\"*?") || strings.HasSuffix(n, ".") || strings.HasSuffix(n, " ") {
		return false
	}
	for _, r := range n {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.M, r) {
			return false
		}
	}
	return true
}

// Fold each Unicode case-equivalence class to one representative. Combining
// characters are reported as unsupported until a versioned normalization policy exists.
func foldName(value string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < smallest {
				smallest = next
			}
		}
		return smallest
	}, value)
}

func excluded(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case ".env", ".git", ".ssh", ".aws", ".gnupg", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".kube", ".docker", "credentials.json", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "node_modules", ".venv":
		return true
	}
	return strings.HasPrefix(n, ".env.") || strings.HasSuffix(n, ".pem") || strings.HasSuffix(n, ".key") || strings.HasSuffix(n, ".p12") || strings.HasSuffix(n, ".pfx")
}

func (s *scanner) file(root *os.Root, name, path string, before fs.FileInfo) {
	if before.Size() > maxFileBytes {
		s.skip(path, "file_size_limit")
		return
	}
	if before.Size() > maxBundleBytes-s.used {
		s.stop(path, "byte_limit")
		return
	}
	data, why := readPinnedFile(root, name, before)
	s.used += int64(len(data))
	if why != "" {
		s.skip(path, why)
		return
	}
	if !s.withinTime() {
		return
	}
	sum := sha256.Sum256(data)
	s.report.Files = append(s.report.Files, File{path, int64(len(data)), hex.EncodeToString(sum[:]), before.Mode()&0111 != 0})
	s.observations = append(s.observations, observedEntry{path, before})
	s.inspect(path, data)
}

// Callers validate a bounded, regular, non-link entry before opening it.
func readPinnedFile(root *os.Root, name string, before fs.FileInfo) ([]byte, string) {
	// Nonblocking open avoids hanging if a regular file has become a FIFO.
	f, err := root.OpenFile(name, os.O_RDONLY|nonblockingFlag, 0)
	if err != nil {
		return nil, reason(err)
	}
	defer f.Close()
	pinned, err := f.Stat()
	if err != nil || !sameInfo(before, pinned) || !sameEntry(root, name, before) {
		return nil, "changed_during_scan"
	}
	if !unaliasedRegularFile(f, pinned) {
		return nil, "unverified_link_count"
	}
	data, err := io.ReadAll(io.LimitReader(f, before.Size()+1))
	if err != nil {
		return nil, "unreadable"
	}
	after, err := f.Stat()
	if err != nil || int64(len(data)) != before.Size() || !sameInfo(before, after) || !sameEntry(root, name, before) {
		return data, "changed_during_scan"
	}
	return data, ""
}

func (s *scanner) finish() {
	slices.SortFunc(s.report.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	slices.SortFunc(s.report.Findings, func(a, b Finding) int {
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})
	slices.SortFunc(s.report.Dependencies, func(a, b Dependency) int {
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		return strings.Compare(a.Name, b.Name)
	})
	if !s.withinTime() || s.report.Status != "complete" {
		return
	}
	h := sha256.New()
	h.Write([]byte(manifestVersion + "\x00"))
	for _, file := range s.report.Files {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(file.Path))))
		h.Write([]byte(file.Path))
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(file.Size)))
		raw, _ := hex.DecodeString(file.SHA256)
		h.Write(raw)
	}
	s.report.ManifestDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func isMCP(name string) bool { return name == ".mcp.json" || name == "managed-mcp.json" }
