package addons

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineAdvisoriesDistinguishMatchClearAndUnknown(t *testing.T) {
	data := []byte(`{"schema_version":"zasp-advisories.v1","generated_at":"2026-01-01T00:00:00Z","packages":[{"ecosystem":"pypi","name":"Demo_Pkg","version":"1.0","advisories":[{"id":"OSV-DEMO-1","severity":"high"}]},{"ecosystem":"npm","name":"ok","version":"2.0.0","advisories":[]}]}`)
	dir := t.TempDir()
	filename := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	now := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	r := Report{Dependencies: []Dependency{{"demo-pkg", "pypi", "1.0", "req.txt"}, {"ok", "npm", "2.0.0", "package.json"}, {"unknown", "npm", "", "package.json"}}}
	if err := ApplyAdvisories(&r, filename, digest, now); err != nil {
		t.Fatal(err)
	}
	a := r.AdvisoryCoverage
	if a.AgeDays != 2 || a.Evaluated != 2 || a.Unknown != 1 || len(a.Matches) != 1 || a.Matches[0].ID != "OSV-DEMO-1" || r.AdvisoryStatus != "partial_exact_release_coverage" {
		t.Fatalf("coverage %#v", r)
	}
	r.Dependencies = r.Dependencies[:2]
	if ApplyAdvisories(&r, filename, digest, now) != nil || r.AdvisoryStatus != "evaluated_exact_releases" {
		t.Fatal("fully represented releases should be evaluated")
	}
	if ApplyAdvisories(&r, filename, digest, now.Add(31*24*time.Hour)) != nil || r.AdvisoryStatus != "stale_snapshot" || len(r.AdvisoryCoverage.Matches) != 1 {
		t.Fatal("stale data must retain known matches")
	}
	if ApplyAdvisories(&r, filename, "wrong", now) == nil || ApplyAdvisories(&r, filename, digest, now.Add(-90*24*time.Hour)) == nil {
		t.Fatal("accepted invalid provenance")
	}
	if err := os.Symlink(filename, filepath.Join(dir, "link")); err == nil && ApplyAdvisories(&r, filepath.Join(dir, "link"), digest, now) == nil {
		t.Fatal("accepted a linked snapshot")
	}
}
