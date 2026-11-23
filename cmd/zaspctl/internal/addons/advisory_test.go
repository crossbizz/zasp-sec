package addons

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestSignedCatalogPinsSourceSignerAndVersions(t *testing.T) {
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "feed.json")
	signature := filepath.Join(dir, "feed.sig")
	anchor := filepath.Join(dir, "feed.pem")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, body []byte) {
		t.Helper()
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(anchor, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	data := []byte(`{"schema_version":"zasp-advisories.v2","generated_at":"2026-01-01T00:00:00Z","source":"https://github.com/github/advisory-database","source_revision":"1111111111111111111111111111111111111111","packages":[{"ecosystem":"npm","name":"demo","version":"1.0.0","advisories":[{"id":"GHSA-TEST-active","severity":"high","fixed_version":"1.0.1"},{"id":"GHSA-TEST-old","severity":"high","withdrawn":true}]},{"ecosystem":"npm","name":"demo","version":"1.0.1","advisories":[]},{"ecosystem":"pypi","name":"demo","version":"1.0","advisories":[]}]}`)
	write(snapshot, data)
	write(signature, ed25519.Sign(priv, data))
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	report := Report{Dependencies: []Dependency{{"demo", "npm", "1.0.0", "package.json"}, {"demo", "npm", "1.0.1", "package.json"}, {"demo", "pypi", "1.0", "requirements.txt"}, {"demo", "npm", "", "package.json"}, {"absent", "npm", "1.2.3", "package.json"}}}
	if err := ApplySignedAdvisories(&report, snapshot, "", anchor, signature, now); err != nil {
		t.Fatal(err)
	}
	a := report.AdvisoryCoverage
	if a.Authentication != "ed25519" || a.SignerSHA256 != fmt.Sprintf("sha256:%x", sha256.Sum256(spki)) || a.SourceRevision != strings.Repeat("1", 40) || len(a.Matches) != 1 || a.Matches[0].FixedVersion != "1.0.1" || a.Evaluated != 3 || a.Unresolved != 1 || a.MissingReleases != 1 || a.Withdrawn != 1 {
		t.Fatalf("bad provenance or matches: %+v", a)
	}
	if err := ApplySignedAdvisories(&report, snapshot, "", anchor, signature, now.Add(31*24*time.Hour)); err != nil || report.AdvisoryStatus != "stale_snapshot" {
		t.Fatal("stale signed catalog treated as fresh", err)
	}
	// A v2 catalog with a caller-supplied hash cannot impersonate its signer.
	if err := ApplyAdvisories(&report, snapshot, fmt.Sprintf("sha256:%x", sha256.Sum256(data)), now); err == nil {
		t.Fatal("signed-catalog downgrade")
	}
	write(snapshot, append(append([]byte{}, data...), ' '))
	if err := ApplySignedAdvisories(&report, snapshot, "", anchor, signature, now); err == nil {
		t.Fatal("tampered bytes accepted")
	}
	write(snapshot, data)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	write(anchor, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err := ApplySignedAdvisories(&report, snapshot, "", anchor, signature, now); err == nil {
		t.Fatal("wrong signer accepted")
	}
}

func TestAdvisoryExactVersionsExcludeRangesAndInvalidReleases(t *testing.T) {
	for _, tc := range []struct {
		ecosystem, version string
		exact              bool
	}{
		{"npm", "1.2.3-alpha.1+build.12", true}, {"npm", "1.02.3", false}, {"npm", "1.0.0-01", false}, {"npm", "^1.2.3", false},
		{"pypi", "1!2.0rc1.post2.dev3+cpu", true}, {"pypi", "1.2.*", false}, {"pypi", "1notarelease", false}, {"pypi", ">=1.2", false},
	} {
		if validAdvisoryRelease(tc.ecosystem, tc.version) != tc.exact {
			t.Errorf("incorrect advisory version classification for %s %q", tc.ecosystem, tc.version)
		}
	}
}
