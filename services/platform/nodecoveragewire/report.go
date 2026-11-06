package nodecoveragewire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

const NodeCoverageSchema = "zasp-node-coverage-v2"

var coverageUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var coverageName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
var coverageBinding = regexp.MustCompile(`^[0-9a-f]{64}$`)
var coverageLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`)

func validCoverageUUID(s string) bool {
	return coverageUUID.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func (s NodeCoverageSelection) Validate() error {
	if s.SourceProfile != "tetragon-local-stream-v2" && s.SourceProfile != "tetragon-local-stream-v3" {
		return ErrInvalid
	}
	if !validCoverageUUID(s.ClusterUID) || !coverageBinding.MatchString(s.EnrollmentBinding) || len(s.MatchLabels) < 1 || len(s.MatchLabels) > 8 {
		return ErrInvalid
	}
	for k, v := range s.MatchLabels {
		parts := strings.Split(k, "/")
		if len(parts) > 2 || len(k) > 253 || !coverageLabel.MatchString(parts[len(parts)-1]) || !coverageLabel.MatchString(v) {
			return ErrInvalid
		}
		if len(parts) == 2 && !coverageName.MatchString(parts[0]) {
			return ErrInvalid
		}
	}
	for _, t := range []CoverageTarget{s.Sensor, s.Tetragon} {
		if !coverageName.MatchString(t.Namespace) || !coverageName.MatchString(t.Name) || !coverageName.MatchString(t.Release) || t.ReleaseNamespace != t.Namespace || !coverageName.MatchString(t.ServiceAccount) || !coverageName.MatchString(t.Container) || len(t.Image) > 512 || !regexp.MustCompile(`^[-A-Za-z0-9./:]+@sha256:[0-9a-f]{64}$`).MatchString(t.Image) {
			return ErrInvalid
		}
	}
	if s.Sensor.Namespace == s.Tetragon.Namespace && s.Sensor.Name == s.Tetragon.Name {
		return ErrInvalid
	}
	return nil
}
func (r NodeCoverageV2) Validate() error {
	if r.Schema != NodeCoverageSchema || !coverageBinding.MatchString(r.EnrollmentBinding) || !validCoverageUUID(r.ClusterUID) || !validCoverageUUID(r.NodeUID) || !validCoverageUUID(r.BootID) || !validCoverageUUID(r.ReporterPodUID) || !validCoverageUUID(r.TetragonPodUID) || !validCoverageUUID(r.GenerationID) || !coverageName.MatchString(r.NodeName) || !coverageName.MatchString(r.ReporterPodName) || !coverageName.MatchString(r.TetragonPodName) || r.IdentityObservedAt.IsZero() || r.MeasuredAt.IsZero() || r.SourceProfile != "tetragon-local-stream-v2" && r.SourceProfile != "tetragon-local-stream-v3" || r.Status != "healthy" && r.Status != "degraded" || len(r.Kernel) < 1 || len(r.Kernel) > 128 || len(r.Capabilities) < 1 || len(r.Capabilities) > 3 || r.EventRate > 1_000_000_000 || r.Drops > 1_000_000_000 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, c := range r.Capabilities {
		if c != "process" && c != "file" && c != "network" || seen[c] {
			return ErrInvalid
		}
		seen[c] = true
	}
	return nil
}
func EncodeNodeCoverage(r NodeCoverageV2) (string, error) {
	if r.Validate() != nil {
		return "", ErrInvalid
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > 8192 {
		return "", ErrInvalid
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func DecodeNodeCoverage(v string) (NodeCoverageV2, error) {
	var r NodeCoverageV2
	b, e := base64.RawURLEncoding.DecodeString(v)
	if e != nil || len(b) > 8192 || base64.RawURLEncoding.EncodeToString(b) != v {
		return r, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Validate() != nil {
		return NodeCoverageV2{}, ErrInvalid
	}
	canonical, e := EncodeNodeCoverage(r)
	if e != nil || canonical != v {
		return NodeCoverageV2{}, ErrInvalid
	}
	return r, nil
}
