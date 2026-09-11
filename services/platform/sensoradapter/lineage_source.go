package sensoradapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

var lineageUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// LineageSource is an immutable provenance contract for a newly created,
// exclusively owned local stream generation. Its producer must establish the
// local Tetragon endpoint's current boot, match host/Kubernetes boot identity,
// and bind the generation before writing records. A UUID or current boot read
// alone is not that proof. Existing exporter files MUST NOT be adopted.
//
// These fields contain no credential and grant no tenant or correlation
// authority. No production configuration creates this contract yet.
type LineageSource struct {
	Profile           string `json:"profile"`
	GenerationID      string `json:"generation_id"`
	EnrollmentBinding string `json:"enrollment_binding"`
	NodeName          string `json:"node_name"`
	ClusterUID        string `json:"cluster_uid"`
	NodeUID           string `json:"node_uid"`
	BootID            string `json:"boot_id"`
}

func (source LineageSource) valid() bool {
	if source.Profile != "tetragon-local-stream-v1" || !enrollmentBindingPattern.MatchString(source.EnrollmentBinding) || !boundedText(source.NodeName, 253) || strings.TrimSpace(source.NodeName) != source.NodeName {
		return false
	}
	for _, id := range []string{source.GenerationID, source.ClusterUID, source.NodeUID, source.BootID} {
		if !lineageUUIDPattern.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" {
			return false
		}
	}
	return true
}

// NewLineageNormalizer starts with an empty cache. There is deliberately no API
// to attach new provenance to an existing unqualified normalizer or cache.
// The trusted generation owner must supply only that generation's records.
func NewLineageNormalizer(maximumProcesses int, source LineageSource) (*Normalizer, error) {
	if !source.valid() {
		return nil, ErrAdapter
	}
	normalizer, err := NewNormalizer(maximumProcesses)
	if err != nil {
		return nil, err
	}
	normalizer.lineageSource = source
	return normalizer, nil
}

func (source LineageSource) qualify(node string, process providerProcess, when string) runtimelineage.Observation {
	if source == (LineageSource{}) || node != source.NodeName {
		return runtimelineage.Observation{}
	}
	observation := runtimelineage.Observation{Profile: "kubernetes-container-v1", ClusterUID: source.ClusterUID, NodeUID: source.NodeUID, BootID: source.BootID, PodUID: process.Pod.UID, ContainerID: process.Pod.Container.ID}
	eventTime, err := time.Parse(timestampLayout, when)
	if err != nil || !observation.ValidAt(eventTime) {
		return runtimelineage.Observation{}
	}
	// Never round an execution start down to fit the millisecond wire time.
	// Omit the optional process pair together when its precision doesn't fit.
	// Numeric cgroup identity is not supplied by this provider surface.
	if started, ok := parseProviderTimestamp(process.StartTime); ok && process.PID > 0 && !started.After(eventTime) {
		withProcess := observation
		withProcess.ProcessID = strconv.FormatUint(uint64(process.PID), 10)
		withProcess.ProcessStartTime = started.Format(time.RFC3339Nano)
		if withProcess.ValidAt(eventTime) {
			return withProcess
		}
	}
	return observation
}

func (source LineageSource) bindStream(legacyBinding string) string {
	if source == (LineageSource{}) {
		return legacyBinding
	}
	encoded, _ := json.Marshal(source) // Fixed string-only struct; no callbacks.
	digest := sha256.Sum256(append([]byte("zasp.stream-lineage.v1\x00"+legacyBinding+"\x00"), encoded...))
	return hex.EncodeToString(digest[:])
}
