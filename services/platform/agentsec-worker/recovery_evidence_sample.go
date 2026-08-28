package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const recoveryEvidenceSampleLimit = 32

var recoveryEvidenceMediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)
var recoveryEvidenceSchemaPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type recoveryEvidenceSample struct {
	ArtifactKey       string `json:"artifact_key"`
	ArtifactReference string `json:"artifact_reference"`
	ArtifactVersionID string `json:"artifact_version_id"`
	Checksum          string `json:"checksum"`
	CollectedAt       string `json:"collected_at"`
	ID                string `json:"id"`
	MediaType         string `json:"media_type"`
	ObjectReference   string `json:"object_reference"`
	SchemaVersion     string `json:"schema_version"`
	SizeBytes         int64  `json:"size_bytes"`
}

func recoveryEvidenceDigestFromArtifacts(bodies [][]byte) ([sha256.Size]byte, error) {
	items := make([]recoveryEvidenceSample, 0, recoveryEvidenceSampleLimit)
	for _, body := range bodies {
		var err error
		items, err = mergeRecoveryEvidenceArtifactSample(items, body)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
	}
	return recoveryEvidenceSampleDigest(items)
}

func mergeRecoveryEvidenceArtifactSample(items []recoveryEvidenceSample, body []byte) ([]recoveryEvidenceSample, error) {
	var rawItems []json.RawMessage
	if len(items) > recoveryEvidenceSampleLimit || len(body) < 2 || len(body) > recoveryMaximumCapturedBytes || decodeStrictWorkerJSON(body, &rawItems) != nil {
		return nil, errRecoveryManifestInvalid
	}
	for _, raw := range rawItems {
		var item recoveryEvidenceSample
		if decodeStrictWorkerJSON(raw, &item) != nil || !validRecoveryEvidenceSample(item) {
			return nil, errRecoveryManifestInvalid
		}
		items = append(items, item)
		sort.Slice(items, func(left, right int) bool { return items[left].ID < items[right].ID })
		if len(items) > recoveryEvidenceSampleLimit {
			items = items[:recoveryEvidenceSampleLimit]
		}
	}
	return items, nil
}

func recoveryEvidenceSampleDigest(items []recoveryEvidenceSample) ([sha256.Size]byte, error) {
	if len(items) > recoveryEvidenceSampleLimit {
		return [sha256.Size]byte{}, errWorkerExecution
	}
	return canonicalRecoveryEvidenceSampleDigest(items)
}

func canonicalRecoveryEvidenceSampleDigest(items []recoveryEvidenceSample) ([sha256.Size]byte, error) {
	copyItems := make([]recoveryEvidenceSample, len(items))
	copy(copyItems, items)
	sort.Slice(copyItems, func(left, right int) bool { return copyItems[left].ID < copyItems[right].ID })
	previous := ""
	for _, item := range copyItems {
		if !validRecoveryEvidenceSample(item) || item.ID <= previous {
			return [sha256.Size]byte{}, errWorkerExecution
		}
		previous = item.ID
	}
	encoded, err := json.Marshal(copyItems)
	if err != nil || len(encoded) < 2 || len(encoded) > 1<<20 {
		return [sha256.Size]byte{}, errWorkerExecution
	}
	return sha256.Sum256(encoded), nil
}

func validRecoveryEvidenceSample(item recoveryEvidenceSample) bool {
	checksum, checksumErr := hex.DecodeString(item.Checksum)
	collected, collectedErr := time.Parse(time.RFC3339Nano, item.CollectedAt)
	_, offset := collected.Zone()
	objectParts := recoveryEvidenceReferencePattern.FindStringSubmatch(item.ObjectReference)
	return validRecoveryProjectionProductID(item.ID) && validRecoveryProjectionProductID(item.ArtifactReference) &&
		len(item.ArtifactKey) >= 1 && len(item.ArtifactKey) <= 2048 && validRecoveryEvidenceText(item.ArtifactKey) &&
		len(item.ArtifactVersionID) >= 1 && len(item.ArtifactVersionID) <= 1024 && validRecoveryEvidenceText(item.ArtifactVersionID) &&
		checksumErr == nil && len(checksum) == sha256.Size && !bytes.Equal(checksum, make([]byte, sha256.Size)) &&
		collectedErr == nil && offset == 0 && item.CollectedAt == strings.TrimSpace(item.CollectedAt) &&
		recoveryEvidenceMediaTypePattern.MatchString(item.MediaType) && recoveryEvidenceSchemaPattern.MatchString(item.SchemaVersion) &&
		item.SizeBytes >= 1 && item.SizeBytes <= 512<<20 && len(objectParts) == 3 && objectParts[2] == item.ArtifactKey
}

func validRecoveryEvidenceText(value string) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
