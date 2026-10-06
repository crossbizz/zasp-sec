package migrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

// The imported checkpoint publishes different development bytes from the older
// unavailable capture. This explicit source-only reader pins that checkpoint;
// it does not recover the original identities or authorize installation.
const orderedCheckpointDevelopmentManifestFileSHA256 = "bc6cdb5b0abe421e22c6592a69a31ef7ca9c9246c66d1fec1db6b2fb7eceabea"
const orderedCheckpointDevelopmentModuleFileSHA256 = "837329121fb7122477decdcfa590ba694dabda4f9189d0b9b49be8f8d20cb52b"

func decodeOrderedCheckpointDevelopment(raw []byte) (orderedCurrentDevelopmentArtifact, error) {
	var artifact orderedCurrentDevelopmentArtifact
	fileSHA := sha256.Sum256(raw)
	if hex.EncodeToString(fileSHA[:]) != orderedCheckpointDevelopmentManifestFileSHA256 {
		return artifact, errors.New("ordered current development file identity changed")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&artifact); err != nil {
		return artifact, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return artifact, errors.New("ordered current development artifact has trailing content")
	}
	if artifact.Format != 1 || artifact.Installable || len(artifact.Facts) == 0 {
		return artifact, errors.New("ordered current development artifact shape changed")
	}
	payloadSHA := sha256.Sum256(artifact.Payload)
	if hex.EncodeToString(payloadSHA[:]) != artifact.PayloadSHA256 {
		return artifact, errors.New("ordered current canonical payload identity changed")
	}
	return artifact, nil
}

func checkOrderedCheckpointDevelopmentModule(raw string) error {
	digest := sha256.Sum256([]byte(raw))
	if hex.EncodeToString(digest[:]) != orderedCheckpointDevelopmentModuleFileSHA256 {
		return errors.New("ordered checkpoint development module identity changed")
	}
	return nil
}

func authorizationWorkerOrderedCheckpointSource() (string, error) {
	if _, err := decodeOrderedCheckpointDevelopment(authorizationWorkerOrderedCurrentManifest); err != nil {
		return "", err
	}
	if err := checkOrderedCheckpointDevelopmentModule(authorizationWorkerOrderedCurrentModule); err != nil {
		return "", err
	}
	// All original native/independent lowering obligations remain outstanding.
	return "", errors.New("ordered checkpoint development is not installable")
}

func admitOrderedCheckpointPrivate(actual []byte) error {
	artifact, err := decodeOrderedCheckpointDevelopment(authorizationWorkerOrderedCurrentManifest)
	if err != nil {
		return err
	}
	expected := make(map[string]orderedCurrentPrivateFact)
	for _, raw := range artifact.Facts {
		rows, err := decodeOrderedCurrentPrivateRows(append(append([]byte{'['}, raw...), ']'))
		if err != nil {
			return err
		}
		row := rows[0]
		var key []string
		if json.Unmarshal([]byte(row.Identity), &key) != nil || len(key) != 2 || key[0] != "private-routines" {
			continue
		}
		config := []any{"search_path=pg_catalog"}
		switch key[1] {
		case "zasp_authorization80_ordered_current.function_definition_public(oid)", "zasp_authorization80_ordered_current.function_identity_arguments_public(oid)", "zasp_authorization80_ordered_current.function_identity_public(oid)":
			config = []any{"search_path=pg_catalog, public", "TimeZone=UTC"}
		}
		if row.Kind != "routine" || len(row.Fact) != 26 || !reflect.DeepEqual(row.Fact["config"], config) {
			return errors.New("private source expectation shape changed")
		}
		if _, duplicate := expected[row.Identity]; duplicate {
			return errors.New("duplicate private source expectation")
		}
		expected[row.Identity] = row
	}
	if len(expected) != 7 {
		return errors.New("private source expectation closure incomplete")
	}
	rows, err := decodeOrderedCurrentPrivateRows(actual)
	if err != nil {
		return err
	}
	if len(rows) != len(expected) {
		return errors.New("private admission cardinality changed")
	}
	seen := make(map[string]bool)
	for _, row := range rows {
		want, exists := expected[row.Identity]
		if !exists || seen[row.Identity] || !reflect.DeepEqual(row, want) {
			return errors.New("private evaluator body or frame changed")
		}
		seen[row.Identity] = true
	}
	return nil
}
