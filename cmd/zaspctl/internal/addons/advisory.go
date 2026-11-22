// Package addons inspects local add-on bundles without executing them.
package addons

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

const maxAdvisoryBytes = 8 << 20

var errAdvisory = errors.New("invalid advisory snapshot or checksum")
var advisoryID = regexp.MustCompile("^[A-Z][A-Za-z0-9.-]{1,99}$")
var advisoryName = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,150}$")
var pepNameSeparator = regexp.MustCompile("[-_.]+")

type Advisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

type advisoryPackage struct {
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Advisories []Advisory `json:"advisories"`
}

type AdvisoryMatch struct {
	Dependency Dependency `json:"dependency"`
	Advisory
}

type AdvisoryCoverage struct {
	Digest      string          `json:"snapshot_digest"`
	GeneratedAt time.Time       `json:"generated_at"`
	AgeDays     int             `json:"age_days"`
	Evaluated   int             `json:"evaluated_declarations"`
	Unknown     int             `json:"unevaluated_declarations"`
	Matches     []AdvisoryMatch `json:"matches"`
}

// ApplyAdvisories uses an explicitly pinned catalog of reviewed exact releases.
// Presence of a row with an empty advisory list is an evaluated release. Absence
// of a row, or a declaration without a resolved version, is unknown.
func ApplyAdvisories(report *Report, filename, digest string, now time.Time) error {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxAdvisoryBytes {
		return errAdvisory
	}
	f, err := os.Open(filename)
	if err != nil {
		return errAdvisory
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errAdvisory
	}
	data, err := io.ReadAll(io.LimitReader(f, maxAdvisoryBytes+1))
	hash := sha256.Sum256(data)
	if err != nil || len(data) > maxAdvisoryBytes || digest != "sha256:"+hex.EncodeToString(hash[:]) {
		return errAdvisory
	}
	var snapshot struct {
		Schema      string            `json:"schema_version"`
		GeneratedAt time.Time         `json:"generated_at"`
		Packages    []advisoryPackage `json:"packages"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&snapshot) != nil || dec.Decode(&struct{}{}) != io.EOF || snapshot.Schema != "zasp-advisories.v1" || snapshot.GeneratedAt.IsZero() || now.Before(snapshot.GeneratedAt) || snapshot.Packages == nil || len(snapshot.Packages) > 50000 {
		return errAdvisory
	}
	type release struct{ ecosystem, name, version string }
	normalize := func(eco, name string) string {
		if eco == "pypi" {
			return pepNameSeparator.ReplaceAllString(strings.ToLower(name), "-")
		}
		return name
	}
	releases := make(map[release][]Advisory, len(snapshot.Packages))
	for _, p := range snapshot.Packages {
		valid := (p.Ecosystem == "pypi" && advisoryName.MatchString(p.Name) && pythonVersion.MatchString("=="+p.Version)) || (p.Ecosystem == "npm" && npmName.MatchString(p.Name) && jsVersion.MatchString(p.Version))
		k := release{p.Ecosystem, normalize(p.Ecosystem, p.Name), p.Version}
		if _, exists := releases[k]; exists || !valid || p.Advisories == nil || len(p.Advisories) > 128 {
			return errAdvisory
		}
		seen := map[string]bool{}
		for _, a := range p.Advisories {
			if !advisoryID.MatchString(a.ID) || seen[a.ID] {
				return errAdvisory
			}
			switch a.Severity {
			case "low", "medium", "high", "critical":
			default:
				return errAdvisory
			}
			seen[a.ID] = true
		}
		releases[k] = p.Advisories
	}
	coverage := AdvisoryCoverage{Digest: digest, GeneratedAt: snapshot.GeneratedAt, AgeDays: int(now.Sub(snapshot.GeneratedAt) / (24 * time.Hour)), Matches: []AdvisoryMatch{}}
	for _, dep := range report.Dependencies {
		list, ok := releases[release{dep.Ecosystem, normalize(dep.Ecosystem, dep.Name), dep.Version}]
		if !ok {
			coverage.Unknown++
			continue
		}
		coverage.Evaluated++
		for _, a := range list {
			// The dependency limit and this cap bound report size independently of the catalog.
			if len(coverage.Matches) >= 4096 {
				return errAdvisory
			}
			coverage.Matches = append(coverage.Matches, AdvisoryMatch{dep, a})
		}
	}
	switch {
	case now.Sub(snapshot.GeneratedAt) > 30*24*time.Hour:
		report.AdvisoryStatus = "stale_snapshot"
	case coverage.Unknown > 0:
		report.AdvisoryStatus = "partial_exact_release_coverage"
	default:
		report.AdvisoryStatus = "evaluated_exact_releases"
	}
	report.AdvisoryCoverage = &coverage
	return nil
}
