package migrations

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

func orderedCurrentDollarBody(raw string) (string, bool) {
	tagMatch := regexp.MustCompile(`\sAS (\$[A-Za-z0-9_]*\$)`).FindStringSubmatch(raw)
	if len(tagMatch) != 2 {
		return "", false
	}
	tag := tagMatch[1]
	bodyStart := strings.Index(raw, tag)
	if bodyStart < 0 {
		return "", false
	}
	bodyEnd := strings.Index(raw[bodyStart+len(tag):], tag)
	if bodyEnd < 0 {
		return "", false
	}
	return raw[bodyStart+len(tag) : bodyStart+len(tag)+bodyEnd], true
}

func TestOrderedCurrentWorkerTailExpectedFactsMatchGoExportSource(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	raw, err := os.ReadFile("ordered_current/development-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Facts []struct { Identity string `json:"identity"`; Fact struct { Definition string `json:"definition"`; Owner string `json:"owner"`; ACL string `json:"acl"` } `json:"fact"` } `json:"facts"` }
	if err := json.Unmarshal(raw, &manifest); err != nil { t.Fatal(err) }
	for _, identity := range []string{"zasp_authorization80_worker.test74_effect_source(text,jsonb)", "zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)"} {
		wantIdentity, _ := json.Marshal([]string{"worker-line-5", identity})
		var got string
		for _, row := range manifest.Facts { if row.Identity == string(wantIdentity) { got = row.Fact.Definition; if row.Fact.Owner != "zasp_discovery_authority" || row.Fact.ACL == "" { t.Fatalf("worker tail frame missing: %s", identity) }; break } }
		if got == "" { t.Fatalf("worker tail expected fact missing: %s", identity) }
		functionName := identity[:strings.Index(identity, "(")]
		marker := "CREATE FUNCTION " + functionName + "("
		start := strings.Index(source, marker); if start < 0 { t.Fatalf("Go export missing worker tail: %s", identity) }
		sourceBody, sourceOK := orderedCurrentDollarBody(source[start:])
		expectedBody, expectedOK := orderedCurrentDollarBody(got)
		if !sourceOK || !expectedOK {
			t.Fatalf("worker tail delimiters missing: %s", identity)
		}
		if sourceBody != expectedBody {
			t.Fatalf("Go export/expected worker tail bytes differ: %s", identity)
		}
	}
}

func TestOrderedCurrentIndependentPrivateAdmission(t *testing.T) {
	artifact, err := decodeOrderedCurrentDevelopment(authorizationWorkerOrderedCurrentManifest)
	if err != nil {
		t.Fatal(err)
	}
	var private []map[string]any
	for _, raw := range artifact.Facts {
		var row map[string]any
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatal(err)
		}
		var key []string
		if json.Unmarshal([]byte(row["identity"].(string)), &key) == nil && len(key) == 2 && key[0] == "private-routines" {
			private = append(private, row)
		}
	}
	if len(private) != 7 {
		t.Fatal("private source closure missing")
	}
	encode := func(rows []map[string]any) []byte {
		raw, e := json.Marshal(rows)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	if err := admitOrderedCurrentPrivate(encode(private)); err != nil {
		t.Fatal(err)
	}
	for index := range private {
		for _, field := range []string{"acl", "config", "argument_names"} {
			var changed []map[string]any
			if err := json.Unmarshal(encode(private), &changed); err != nil {
				t.Fatal(err)
			}
			changed[index]["fact"].(map[string]any)[field] = nil
			if admitOrderedCurrentPrivate(encode(changed)) == nil {
				t.Fatalf("accepted NULL %s at routine %d", field, index)
			}
		}
	}
	for field, value := range map[string]any{"source": "RETURN true", "owner": "executor", "acl": nil, "argument_defaults": "tampered", "default_count": 1, "result_type": "tampered", "config": []string{"search_path=pg_catalog, public"}, "sql_body": "parsed"} {
		var changed []map[string]any
		if err := json.Unmarshal(encode(private), &changed); err != nil {
			t.Fatal(err)
		}
		changed[0]["fact"].(map[string]any)[field] = value
		if admitOrderedCurrentPrivate(encode(changed)) == nil {
			t.Fatalf("accepted %s mutation", field)
		}
	}
	if admitOrderedCurrentPrivate(encode(private[:3])) == nil {
		t.Fatal("accepted missing evaluator")
	}
	if admitOrderedCurrentPrivate(encode(append(private, private[0]))) == nil {
		t.Fatal("accepted duplicate evaluator")
	}
	if query, err := orderedCurrentPrivateAdmissionQuery(); err != nil || !bytes.Contains([]byte(query), []byte("current_setting('search_path')='pg_catalog'")) {
		t.Fatal("missing independently pinned admission frame", err)
	}
}

func TestOrderedCurrentDevelopmentArtifactPinsAndInstallationRefusal(t *testing.T) {
	artifact, err := decodeOrderedCurrentDevelopment(authorizationWorkerOrderedCurrentManifest)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Installable || artifact.Format != 1 || len(artifact.Payload) == 0 {
		t.Fatal("development artifact lost its non-installable typed boundary")
	}
	if source, err := authorizationWorkerOrderedCurrentSource(); err == nil || source != "" {
		t.Fatal("incomplete development integrity was admitted into a migration")
	}
	for _, replacement := range [][2][]byte{
		{[]byte(`"installable":false`), []byte(`"installable":true`)},
		{[]byte(`"purpose":"development-only"`), []byte(`"purpose":"release"`)},
		{[]byte(`"owner":"zasp_discovery_authority"`), []byte(`"owner":"executor"`)},
	} {
		changed := bytes.Replace(authorizationWorkerOrderedCurrentManifest, replacement[0], replacement[1], 1)
		if bytes.Equal(changed, authorizationWorkerOrderedCurrentManifest) {
			t.Fatal("mutation did not change its intended field")
		}
		if _, err := decodeOrderedCurrentDevelopment(changed); err == nil {
			t.Fatal("changed artifact passed the independent compiled file pin")
		}
	}
}
