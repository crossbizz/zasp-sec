package migrations

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

// These inputs are deliberately absent from authorizationWorkerOrderedSource.
// A development checkpoint cannot be installed or selected as a runtime gate.
//
//go:embed ordered_current/development-manifest.json
var authorizationWorkerOrderedCurrentManifest []byte

//go:embed ordered_current/development-module.sql
var authorizationWorkerOrderedCurrentModule string

//go:embed ordered_current/development-admission.sql
var orderedCurrentPrivateAdmissionSQL string

const orderedCurrentPrivateAdmissionSHA256 = "f99a5cff70e24093e05c79391fca0735f8dbbafad35cad52664cce09242fa7d5"

const orderedCurrentDevelopmentManifestFileSHA256 = "f78003bb5827232f7f603da7490d1fd840818e5c62c18c3b3f85588fcda6b4cd"
const orderedCurrentDevelopmentModuleFileSHA256 = "921fe1a2c6fc30e4d66c9ad0b2455376b5bb1afc001ee40bcef35665cfa02208"

type orderedCurrentDevelopmentArtifact struct {
	Format        int               `json:"format"`
	Installable   bool              `json:"installable"`
	PayloadSHA256 string            `json:"payloadSHA256"`
	Payload       json.RawMessage   `json:"payload"`
	Entries       []json.RawMessage `json:"entries"`
	Facts         []json.RawMessage `json:"facts"`
}

func decodeOrderedCurrentDevelopment(raw []byte) (orderedCurrentDevelopmentArtifact, error) {
	var artifact orderedCurrentDevelopmentArtifact
	fileSHA := sha256.Sum256(raw)
	if hex.EncodeToString(fileSHA[:]) != orderedCurrentDevelopmentManifestFileSHA256 {
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

func authorizationWorkerOrderedCurrentSource() (string, error) {
	if _, err := decodeOrderedCurrentDevelopment(authorizationWorkerOrderedCurrentManifest); err != nil {
		return "", err
	}
	moduleSHA := sha256.Sum256([]byte(authorizationWorkerOrderedCurrentModule))
	if hex.EncodeToString(moduleSHA[:]) != orderedCurrentDevelopmentModuleFileSHA256 {
		return "", errors.New("ordered current development module identity changed")
	}
	// Removing this refusal requires a complete reviewed source-selector lowering,
	// independently generated private closure, two fresh-build equality evidence,
	// and native truth/drift/frame checks. Merely flipping JSON cannot activate it.
	return "", errors.New("ordered current development checkpoint is not installable")
}

// This client-side admission reads only pg_catalog through a separately pinned
// query. No answer from the evaluator or mutable expected table is trusted.
// Routing remains disabled; callers must use a transaction with the query's
// exact discovery-authority/pg_catalog frame before attempting an integrity call.
func orderedCurrentPrivateAdmissionQuery() (string, error) {
	sum := sha256.Sum256([]byte(orderedCurrentPrivateAdmissionSQL))
	if hex.EncodeToString(sum[:]) != orderedCurrentPrivateAdmissionSHA256 {
		return "", errors.New("ordered current private admission query changed")
	}
	return orderedCurrentPrivateAdmissionSQL, nil
}

type orderedCurrentPrivateFact struct {
	Kind     string         `json:"kind"`
	Identity string         `json:"identity"`
	Fact     map[string]any `json:"fact"`
}

func decodeOrderedCurrentPrivateRows(raw []byte) ([]orderedCurrentPrivateFact, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var rows []orderedCurrentPrivateFact
	if err := decoder.Decode(&rows); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("private admission trailing data")
	}
	return rows, nil
}

func admitOrderedCurrentPrivate(actual []byte) error {
	artifact, err := decodeOrderedCurrentDevelopment(authorizationWorkerOrderedCurrentManifest)
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
