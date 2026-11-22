package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkloadContextReceiptsPreserveUnknownAndRequireScopedReferences(t *testing.T) {
	base := map[string]any{"kind": "retrieval", "version": 1, "record_ref": strings.Repeat("c", 64),
		"collection_ref": strings.Repeat("a", 64), "digest": strings.Repeat("b", 64), "result": "allowed"}
	for _, test := range []struct {
		name, key string
		value     any
		status    string
		accepted  bool
	}{
		{"read", "", "", "returned", true}, {"normal return with refusal", "result", "rejected", "returned", false},
		{"missing version", "version", nil, "returned", false}, {"unhashed identifier", "record_ref", "private-document", "returned", false},
		{"unknown operation", "kind", "unverified_claim", "returned", false}, {"unknown digest", "digest", "doc", "returned", false},
		{"not dispatched", "", "", "not_dispatched", false}, {"claimed result", "result", "independently_verified", "returned", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			clone := map[string]any{}
			for k, v := range base {
				clone[k] = v
			}
			if test.key != "" {
				if test.value == nil {
					delete(clone, test.key)
				} else {
					clone[test.key] = test.value
				}
			}
			raw, _ := json.Marshal(clone)
			var evidence workloadContextEvidence
			if err := json.Unmarshal(raw, &evidence); err != nil {
				t.Fatal(err)
			}
			if got := evidence.valid(test.status); got != test.accepted {
				t.Fatalf("accepted = %v", got)
			}
		})
	}
}
