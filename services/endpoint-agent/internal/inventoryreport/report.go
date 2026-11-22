// Package inventoryreport converts a user-context scanner report to device-keyed metadata.
package inventoryreport

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"io"
	"path/filepath"
	"strings"
)

var errInvalid = errors.New("invalid inventory report")

func OpaqueID(secret []byte, namespace string, parts ...string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(namespace))
	for _, part := range parts {
		mac.Write([]byte{0})
		mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func UniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		kind, isContainer := token.(json.Delim)
		if !isContainer {
			return true
		}
		seen := map[string]bool{}
		for d.More() {
			if kind == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
			}
			if !value(depth + 1) {
				return false
			}
		}
		_, err = d.Token()
		return err == nil
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func Parse(raw []byte, project string, seed []byte, sequence uint64) ([]endpointprotocol.Inventory, uint64, error) {
	var r struct {
		Schema   string `json:"schema_version"`
		Command  string `json:"command"`
		Status   string `json:"status"`
		Coverage struct {
			Mode  string                                 `json:"mode"`
			Roots []struct{ Scope, Root, Status string } `json:"roots"`
		} `json:"coverage"`
		Items []struct {
			Path, Scope string
			Digest      string `json:"manifest_digest"`
		} `json:"items"`
	}
	if !UniqueJSON(raw) || json.Unmarshal(raw, &r) != nil || r.Schema != "zaspctl.local.v1" || r.Command != "inventory" || (r.Status != "complete" && r.Status != "partial") || r.Coverage.Mode != "local_only" || len(r.Coverage.Roots) == 0 || len(r.Coverage.Roots) > 128 || len(r.Items) > 2048 {
		return nil, sequence, errInvalid
	}
	var snapshots []endpointprotocol.Inventory
	matched := make([]bool, len(r.Items))
	seen := make(map[string]bool, len(r.Coverage.Roots))
	for _, root := range r.Coverage.Roots {
		root.Root = filepath.FromSlash(root.Root)
		if !filepath.IsLocal(root.Root) || filepath.Clean(root.Root) != root.Root || (root.Scope != "managed" && root.Scope != "project" && root.Scope != "personal") || (root.Status != "complete" && root.Status != "partial" && root.Status != "absent") {
			return nil, sequence, errInvalid
		}
		context := "default"
		if root.Scope == "project" {
			if !filepath.IsAbs(project) || filepath.Clean(project) != project {
				return nil, sequence, errInvalid
			}
			context = project
		}
		partition := OpaqueID(seed, "partition", root.Scope, context, root.Root)
		if seen[partition] {
			return nil, sequence, errInvalid
		}
		seen[partition] = true
		complete := root.Status == "complete"
		// A missing optional root can be evidence of removal only when the
		// original collector explicitly records a complete observation.
		sequence++
		v := endpointprotocol.Inventory{Partition: partition, Generation: sequence, Complete: &complete, Items: []endpointprotocol.Installation{}}
		for index, item := range r.Items {
			item.Path = filepath.FromSlash(item.Path)
			if item.Scope != root.Scope || !filepath.IsLocal(item.Path) || filepath.Clean(item.Path) != item.Path {
				continue
			}
			rel, err := filepath.Rel(root.Root, item.Path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			if matched[index] || root.Status == "absent" {
				return nil, sequence, errInvalid
			}
			matched[index] = true
			if len(v.Items) == 128 {
				complete = false
				continue
			}
			v.Items = append(v.Items, endpointprotocol.Installation{ID: OpaqueID(seed, "install", partition, rel), Digest: item.Digest})
		}
		if !v.Valid() {
			return nil, sequence, errInvalid
		}
		snapshots = append(snapshots, v)
	}
	for _, found := range matched {
		if !found {
			return nil, sequence, errInvalid
		}
	}
	return snapshots, sequence, nil
}
