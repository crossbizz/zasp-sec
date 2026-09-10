// Package runtimelineage validates source-observed runtime qualifiers. These
// values are not host attestation, tenant identity, or correlation authority.
package runtimelineage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrInput = errors.New("runtime lineage observation rejected")

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var containerPattern = regexp.MustCompile(`^(containerd|docker|cri-o)://[0-9a-f]{64}$`)

// Observation's first profile requires UUID-shaped Kubernetes identifiers,
// node boot identity, and the full runtime-qualified container ID. Names and
// Tetragon's abbreviated process.docker field do not satisfy this profile.
// Process identity, when present, always includes its start time to prevent
// bare PID reuse. A zero value means no observation; an explicit empty JSON
// object or null is invalid. New profiles require an explicit version change.
type Observation struct {
	Profile          string `json:"profile"`
	ClusterUID       string `json:"cluster_uid"`
	NodeUID          string `json:"node_uid"`
	BootID           string `json:"boot_id"`
	PodUID           string `json:"pod_uid"`
	ContainerID      string `json:"container_id"`
	ProcessID        string `json:"process_id,omitempty"`
	ProcessStartTime string `json:"process_start_time,omitempty"`
	CgroupID         string `json:"cgroup_id,omitempty"`
}

func (value Observation) Valid() bool {
	if value == (Observation{}) {
		return true
	}
	if value.Profile != "kubernetes-container-v1" {
		return false
	}
	for _, id := range []string{value.ClusterUID, value.NodeUID, value.BootID, value.PodUID} {
		if !uuidPattern.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" {
			return false
		}
	}
	if !containerPattern.MatchString(value.ContainerID) || strings.HasSuffix(value.ContainerID, "://"+strings.Repeat("0", 64)) {
		return false
	}
	if (value.ProcessID == "") != (value.ProcessStartTime == "") {
		return false
	}
	if value.ProcessID != "" {
		if !positiveDecimal(value.ProcessID, 32) {
			return false
		}
		if _, ok := processStart(value.ProcessStartTime); !ok {
			return false
		}
	}
	return value.CgroupID == "" || positiveDecimal(value.CgroupID, 64)
}

func (value Observation) ValidAt(eventTime time.Time) bool {
	if !value.Valid() || eventTime.IsZero() || eventTime.Location() != time.UTC {
		return false
	}
	if value.ProcessStartTime == "" {
		return true
	}
	start, ok := processStart(value.ProcessStartTime)
	return ok && !start.After(eventTime)
}

func positiveDecimal(value string, bits int) bool {
	if len(value) < 1 || len(value) > 20 || value[0] < '1' || value[0] > '9' {
		return false
	}
	parsed, err := strconv.ParseUint(value, 10, bits)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}

func processStart(value string) (time.Time, bool) {
	if len(value) < 20 || len(value) > 30 {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil && parsed.Unix() > 0 && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}

// UnmarshalJSON rejects duplicate and case-variant keys even outside the
// production ingest decoder, and never maps explicit null to absent lineage.
func (value *Observation) UnmarshalJSON(body []byte) error {
	if value == nil || len(body) == 0 || len(body) > 1024 {
		return ErrInput
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return ErrInput
	}
	var result Observation
	fields := map[string]*string{
		"profile": &result.Profile, "cluster_uid": &result.ClusterUID, "node_uid": &result.NodeUID,
		"boot_id": &result.BootID, "pod_uid": &result.PodUID, "container_id": &result.ContainerID,
		"process_id": &result.ProcessID, "process_start_time": &result.ProcessStartTime, "cgroup_id": &result.CgroupID,
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] == nil || seen[key] {
			return ErrInput
		}
		seen[key] = true
		token, err = decoder.Token()
		text, ok := token.(string)
		if err != nil || !ok || text == "" {
			return ErrInput
		}
		*fields[key] = text
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF || result == (Observation{}) || !result.Valid() {
		return ErrInput
	}
	*value = result
	return nil
}
