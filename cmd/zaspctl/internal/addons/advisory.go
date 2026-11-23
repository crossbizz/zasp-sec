// Package addons inspects local add-on bundles without executing them.
package addons

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const maxAdvisoryBytes = 8 << 20

var errAdvisory = errors.New("invalid advisory snapshot or checksum")
var advisoryID = regexp.MustCompile("^[A-Z][A-Za-z0-9.-]{1,99}$")
var advisoryName = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,150}$")
var pepNameSeparator = regexp.MustCompile("[-_.]+")

// Advisory matching only accepts literal package release versions. Preserve
// the published static ruleset's separate classification of declaration text.
const semverNumber = "(?:0|[1-9][0-9]*)"
const semverPreID = "(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"

var exactNPMRelease = regexp.MustCompile("^" + semverNumber + "\\." + semverNumber + "\\." + semverNumber + "(?:-" + semverPreID + "(?:\\." + semverPreID + ")*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$")
var exactPyPIRelease = regexp.MustCompile(`(?i)^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(?:alpha|beta|preview|pre|rc|a|b|c)[-_.]?[0-9]*)?(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

func validAdvisoryRelease(ecosystem, version string) bool {
	if len(version) > 128 {
		return false
	}
	switch ecosystem {
	case "npm":
		return exactNPMRelease.MatchString(version)
	case "pypi":
		return exactPyPIRelease.MatchString(version)
	default:
		return false
	}
}

type Advisory struct {
	ID           string `json:"id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version,omitempty"`
	Withdrawn    bool   `json:"withdrawn,omitempty"`
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
	Authentication  string          `json:"authentication"`
	SignerSHA256    string          `json:"signer_sha256,omitempty"`
	Source          string          `json:"source,omitempty"`
	SourceRevision  string          `json:"source_revision,omitempty"`
	Unresolved      int             `json:"unresolved_versions"`
	MissingReleases int             `json:"releases_absent_from_snapshot"`
	Unrated         int             `json:"unrated_matches"`
	Withdrawn       int             `json:"withdrawn_matches_excluded"`
	Digest          string          `json:"snapshot_digest"`
	GeneratedAt     time.Time       `json:"generated_at"`
	AgeDays         int             `json:"age_days"`
	Evaluated       int             `json:"evaluated_declarations"`
	Unknown         int             `json:"unevaluated_declarations"`
	Matches         []AdvisoryMatch `json:"matches"`
}

// ApplyAdvisories uses an explicitly pinned catalog of reviewed exact releases.
// Presence of a row with an empty advisory list is an evaluated release. Absence
// of a row, or a declaration without a resolved version, is unknown.
func ApplyAdvisories(report *Report, filename, digest string, now time.Time) error {
	return applyAdvisories(report, filename, digest, "", "", now)
}

// ApplySignedAdvisories verifies the exact bytes with a separately distributed
// operator trust anchor. The signature format is raw Ed25519, compatible with
// openssl pkeyutl -sign -rawin. The key is an Ed25519 PKIX PUBLIC KEY PEM.
func ApplySignedAdvisories(report *Report, filename, digest, keyFile, signatureFile string, now time.Time) error {
	if keyFile == "" || signatureFile == "" {
		return errAdvisory
	}
	return applyAdvisories(report, filename, digest, keyFile, signatureFile, now)
}

func advisoryFile(filename string, limit int64) ([]byte, error) {
	dir, err := os.OpenRoot(filepath.Dir(filename))
	if err != nil {
		return nil, errAdvisory
	}
	defer dir.Close()
	name := filepath.Base(filename)
	info, err := dir.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errAdvisory
	}
	f, err := dir.OpenFile(name, os.O_RDONLY|nonblockingFlag, 0)
	if err != nil {
		return nil, errAdvisory
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameInfo(info, opened) {
		return nil, errAdvisory
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != info.Size() || !sameEntry(dir, name, opened) {
		return nil, errAdvisory
	}
	return data, nil
}

func snapshotSigner(data []byte, keyFile, signatureFile string) (string, error) {
	encoded, err := advisoryFile(keyFile, 4096)
	if err != nil {
		return "", errAdvisory
	}
	block, tail := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(tail)) != 0 {
		return "", errAdvisory
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return "", errAdvisory
	}
	sig, err := advisoryFile(signatureFile, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, data, sig) {
		return "", errAdvisory
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

var advisoryRevision = regexp.MustCompile("^[a-f0-9]{40}$")

func applyAdvisories(report *Report, filename, digest, keyFile, signatureFile string, now time.Time) error {
	if report == nil {
		return errAdvisory
	}
	data, err := advisoryFile(filename, maxAdvisoryBytes)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	actual := "sha256:" + hex.EncodeToString(hash[:])
	if digest != "" && digest != actual {
		return errAdvisory
	}
	auth, signer := "operator_pinned_sha256", ""
	if keyFile != "" {
		signer, err = snapshotSigner(data, keyFile, signatureFile)
		if err != nil {
			return err
		}
		auth = "ed25519"
	} else if digest == "" {
		return errAdvisory
	}
	var snapshot struct {
		Schema      string            `json:"schema_version"`
		GeneratedAt time.Time         `json:"generated_at"`
		Source      string            `json:"source,omitempty"`
		Revision    string            `json:"source_revision,omitempty"`
		Packages    []advisoryPackage `json:"packages"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&snapshot) != nil || dec.Decode(&struct{}{}) != io.EOF || snapshot.GeneratedAt.IsZero() || now.Before(snapshot.GeneratedAt) || snapshot.Packages == nil || len(snapshot.Packages) > 50000 {
		return errAdvisory
	}
	switch snapshot.Schema {
	case "zasp-advisories.v1":
		if snapshot.Source != "" || snapshot.Revision != "" || signer != "" {
			return errAdvisory
		}
	case "zasp-advisories.v2":
		// A signature authenticates the reviewer's claim about this upstream
		// revision. A catalog never proves installation on the scanned device.
		if signer == "" || snapshot.Source != "https://github.com/github/advisory-database" || !advisoryRevision.MatchString(snapshot.Revision) {
			return errAdvisory
		}
	default:
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
		valid := validAdvisoryRelease(p.Ecosystem, p.Version) && (p.Ecosystem == "pypi" && advisoryName.MatchString(p.Name) || p.Ecosystem == "npm" && npmName.MatchString(p.Name))
		k := release{p.Ecosystem, normalize(p.Ecosystem, p.Name), p.Version}
		if _, exists := releases[k]; exists || !valid || p.Advisories == nil || len(p.Advisories) > 128 {
			return errAdvisory
		}
		seen := map[string]bool{}
		for _, a := range p.Advisories {
			if !advisoryID.MatchString(a.ID) || seen[a.ID] {
				return errAdvisory
			}
			if a.FixedVersion != "" && !validAdvisoryRelease(p.Ecosystem, a.FixedVersion) {
				return errAdvisory
			}
			switch a.Severity {
			case "low", "medium", "high", "critical", "unknown":
			default:
				return errAdvisory
			}
			seen[a.ID] = true
		}
		releases[k] = p.Advisories
	}
	coverage := AdvisoryCoverage{Digest: actual, Authentication: auth, SignerSHA256: signer, Source: snapshot.Source, SourceRevision: snapshot.Revision, GeneratedAt: snapshot.GeneratedAt, AgeDays: int(now.Sub(snapshot.GeneratedAt) / (24 * time.Hour)), Matches: []AdvisoryMatch{}}
	for _, dep := range report.Dependencies {
		list, ok := releases[release{dep.Ecosystem, normalize(dep.Ecosystem, dep.Name), dep.Version}]
		if !ok {
			if !validAdvisoryRelease(dep.Ecosystem, dep.Version) {
				coverage.Unresolved++
			} else {
				coverage.MissingReleases++
			}
			coverage.Unknown++
			continue
		}
		coverage.Evaluated++
		for _, a := range list {
			if a.Withdrawn {
				coverage.Withdrawn++
				continue
			}
			// The dependency limit and this cap bound report size independently of the catalog.
			if len(coverage.Matches) >= 4096 {
				return errAdvisory
			}
			if a.Severity == "unknown" {
				coverage.Unrated++
			}
			coverage.Matches = append(coverage.Matches, AdvisoryMatch{dep, a})
		}
	}
	switch {
	case now.Sub(snapshot.GeneratedAt) > 30*24*time.Hour:
		report.AdvisoryStatus = "stale_snapshot"
	case coverage.Unrated > 0:
		report.AdvisoryStatus = "unrated_exact_release_match"
	case coverage.Unknown > 0:
		report.AdvisoryStatus = "partial_exact_release_coverage"
	default:
		report.AdvisoryStatus = "evaluated_exact_releases"
	}
	report.Notices = slices.DeleteFunc(report.Notices, func(n Notice) bool { return n.ID == "advisory.not_evaluated" })
	report.AdvisoryCoverage = &coverage
	return nil
}
