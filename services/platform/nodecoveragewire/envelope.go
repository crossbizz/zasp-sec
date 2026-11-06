package nodecoveragewire

import (
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

var capabilityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,95}$`)

func ParseEnvelope(raw []byte) (Envelope, error) {
	var v Envelope
	if strictDecode(raw, &v, MaxEnvelopeBytes) != nil || ValidateEnvelope(v) != nil {
		return Envelope{}, ErrInvalid
	}
	return v, nil
}
func MarshalEnvelope(v Envelope) ([]byte, error) {
	if ValidateEnvelope(v) != nil {
		return nil, ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > MaxEnvelopeBytes {
		return nil, ErrInvalid
	}
	return b, nil
}
func validInstant(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1 && t.Year() <= 9999
}
func validHeartbeat(v Heartbeat) bool {
	if v.Sequence < 1 || (v.Status != "healthy" && v.Status != "degraded") || len(v.Kernel) < 1 || len(v.Kernel) > 128 || strings.TrimSpace(v.Kernel) != v.Kernel || strings.ContainsFunc(v.Kernel, unicode.IsControl) || len(v.Capabilities) < 1 || len(v.Capabilities) > 32 || v.EventRate > 1000000000 || v.Drops > 1000000000 {
		return false
	}
	for i, c := range v.Capabilities {
		if !capabilityPattern.MatchString(c) || (i > 0 && v.Capabilities[i-1] >= c) {
			return false
		}
	}
	return true
}
func ValidateEnvelope(v Envelope) error {
	if !validHeartbeat(v.Heartbeat) || v.CoverageSchema != CoverageSchema || !validCoverageUUID(v.StateUID) || v.StorageEpoch < 1 || v.Selection.Validate() != nil || !coverageBinding.MatchString(v.TargetDigest) || !validInstant(v.InventoryObservedAt) || !validInstant(v.SourceObservedAt) || v.TTLSeconds < 6 || v.TTLSeconds > 300 || !validCoverageUUID(v.SensorDaemonSetUID) || !validCoverageUUID(v.TetragonDaemonSetUID) || v.SensorDaemonSetUID == v.TetragonDaemonSetUID || len(v.SelectedNodes) < 1 || len(v.SelectedNodes) > MaxSelectedNodes || v.Reports == nil || len(v.Reports) > MaxReports {
		return ErrInvalid
	}
	selection, e := json.Marshal(v.Selection)
	if e != nil || len(selection) > 65536 {
		return ErrInvalid
	}
	selected := map[string]SelectedNode{}
	names := map[string]bool{}
	uids := map[string]bool{}
	last := ""
	for _, n := range v.SelectedNodes {
		key := n.NodeUID + "/" + n.BootID
		if !coverageName.MatchString(n.NodeName) || !validCoverageUUID(n.NodeUID) || !validCoverageUUID(n.BootID) || key <= last || names[n.NodeName] || uids[n.NodeUID] {
			return ErrInvalid
		}
		b, _ := json.Marshal(n)
		if len(b) > 1024 {
			return ErrInvalid
		}
		selected[key] = n
		names[n.NodeName] = true
		uids[n.NodeUID] = true
		last = key
	}
	source := v.InventoryObservedAt
	caps := map[string]bool{"file": true, "network": true, "process": true}
	kernel := "unknown"
	last = ""
	var rate, drops uint64
	allHealthy := len(v.Reports) == len(v.SelectedNodes)
	allBTF := true
	for _, r := range v.Reports {
		key := r.NodeUID + "/" + r.BootID
		n, ok := selected[key]
		if !ok || n.NodeName != r.NodeName || key <= last || r.Validate() != nil || r.ClusterUID != v.Selection.ClusterUID || r.EnrollmentBinding != v.Selection.EnrollmentBinding || r.SourceProfile != v.Selection.SourceProfile || !validInstant(r.IdentityObservedAt) || !validInstant(r.MeasuredAt) || r.IdentityObservedAt.After(r.MeasuredAt.Add(5*time.Second)) {
			return ErrInvalid
		}
		last = key
		b, e := json.Marshal(r)
		if e != nil || len(b) > MaxReportBytes {
			return ErrInvalid
		}
		if r.IdentityObservedAt.Before(source) {
			source = r.IdentityObservedAt
		}
		if r.MeasuredAt.Before(source) {
			source = r.MeasuredAt
		}
		if kernel == "unknown" {
			kernel = r.Kernel
		} else if kernel != r.Kernel {
			kernel = "mixed"
		}
		rate = min(uint64(1000000000), rate+r.EventRate)
		drops = min(uint64(1000000000), drops+r.Drops)
		for c := range caps {
			found := false
			for _, value := range r.Capabilities {
				found = found || c == value
			}
			if !found {
				delete(caps, c)
			}
		}
		allBTF = allBTF && r.BTF
		allHealthy = allHealthy && r.Status == "healthy" && r.BTF && r.Drops == 0 && len(r.Capabilities) == 3
	}
	if !source.Equal(v.SourceObservedAt) || v.Kernel != kernel || v.EventRate != rate || v.Drops != drops {
		return ErrInvalid
	}
	values := make([]string, 0, len(caps))
	for c := range caps {
		values = append(values, c)
	}
	sort.Strings(values)
	fallback := len(values) == 0 || len(v.Reports) == 0
	if fallback {
		values = []string{"process"}
	}
	if !reflect.DeepEqual(values, v.Capabilities) || (v.BTF && (!allBTF || !allHealthy)) || (v.Status == "healthy" && (!allHealthy || !v.BTF || kernel == "mixed" || fallback)) || (fallback && (v.Status != "degraded" || v.BTF)) {
		return ErrInvalid
	}
	return nil
}

// Structural parsing remains possible after expiry for exact durable resolution.
// This forward-only guard must not replace legacy freshness/observation checks.
func ValidateFreshEnvelope(v Envelope, now time.Time) error {
	if ValidateEnvelope(v) != nil || !validInstant(now) || now.Before(v.SourceObservedAt.Add(-5*time.Second)) || !now.Before(v.SourceObservedAt.Add(time.Duration(v.TTLSeconds)*time.Second)) || v.InventoryObservedAt.After(now.Add(5*time.Second)) {
		return ErrInvalid
	}
	for _, r := range v.Reports {
		if r.IdentityObservedAt.After(now.Add(5*time.Second)) || r.MeasuredAt.After(now.Add(5*time.Second)) {
			return ErrInvalid
		}
	}
	return nil
}
