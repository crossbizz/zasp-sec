package probes

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
)

var identifierPattern = regexp.MustCompile(`^zasp(\.[a-z][a-z_]{2,40}){4}\.v1$`)

func TestCatalogInvariants(t *testing.T) {
	probes := All()
	if len(probes) < 1000 {
		t.Fatalf("catalog holds %d probes, want at least 1000", len(probes))
	}
	ids, inputs, perCategory := map[string]bool{}, map[string]string{}, map[string]int{}
	for _, probe := range probes {
		if !identifierPattern.MatchString(probe.ID) || len(probe.ID) > 128 || ids[probe.ID] {
			t.Fatalf("identifier %q is malformed or repeated", probe.ID)
		}
		ids[probe.ID] = true
		if other, repeated := inputs[probe.Input]; repeated {
			t.Fatalf("%s and %s have the same input", probe.ID, other)
		}
		inputs[probe.Input] = probe.ID
		perCategory[probe.Category]++
		if probe.Canary != Canary(probe.Category) || probe.Detection != DetectionRule || !ValidCategory(probe.Category) {
			t.Fatalf("%s: canary, detection rule or category is wrong", probe.ID)
		}
		visible := probe.Input
		if probe.Technique == "encoding_obfuscation" {
			encoded := probe.Input[strings.LastIndex(probe.Input, " ")+1:]
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("%s: %v", probe.ID, err)
			}
			visible = string(decoded)
		}
		if strings.Count(visible, probe.Canary) < 1 {
			t.Fatalf("%s does not hold its canary", probe.ID)
		}
		if len(probe.Input) < 60 || len(probe.Input) > 4096 || strings.TrimSpace(probe.Input) != probe.Input || strings.Contains(probe.Input, "CANARY ") || strings.ContainsAny(probe.Input, "\"\\{}") {
			t.Fatalf("%s: input is not a bounded, self-contained line: %q", probe.ID, probe.Input)
		}
		for _, character := range probe.Input {
			if unicode.IsControl(character) {
				t.Fatalf("%s holds a control character", probe.ID)
			}
		}
		frameworks := map[string]bool{}
		for _, tag := range probe.Tags {
			if tag.Control == "" || tag.Title == "" {
				t.Fatalf("%s has an empty tag", probe.ID)
			}
			frameworks[tag.Framework] = true
		}
		if len(probe.Tags) < 2 || !(frameworks[compliancemap.OWASPLLM] || frameworks[compliancemap.OWASPAgentic]) {
			t.Fatalf("%s lacks an OWASP tag: %+v", probe.ID, probe.Tags)
		}
		if found, ok := Lookup(probe.ID); !ok || found.Input != probe.Input {
			t.Fatalf("%s is not found by its identifier", probe.ID)
		}
	}
	if len(perCategory) != len(Categories()) || len(Summaries()) != len(perCategory) {
		t.Fatalf("categories = %v", perCategory)
	}
	total := 0
	for _, summary := range Summaries() {
		if summary.ProbeCount < 20 || summary.ProbeCount != perCategory[summary.Category] || len(summary.Techniques) != len(techniques) || len(summary.Frameworks) < 2 || summary.Title == "" {
			t.Fatalf("summary %+v", summary)
		}
		total += summary.ProbeCount
	}
	if total != len(probes) || len(Digest()) != 64 {
		t.Fatalf("total=%d digest=%q", total, Digest())
	}
	for _, name := range []string{"indirect_injection", "poisoned_resource", "cross_agent_delegation", "prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information"} {
		if perCategory[name] < 20 {
			t.Fatalf("category %s holds %d probes", name, perCategory[name])
		}
	}
	if ValidCategory("tool_misuse") {
		t.Fatal("tool_misuse must stay covered by tool_abuse, not duplicated")
	}
}

func TestSampleIsDeterministicBoundedAndSeedDependent(t *testing.T) {
	const run = "pid_95000003-0000-4000-8000-000000000003"
	first, second := Sample("indirect_injection", run, DefaultSampleSize), Sample("indirect_injection", run, DefaultSampleSize)
	if len(first) != DefaultSampleSize {
		t.Fatalf("sample holds %d probes", len(first))
	}
	seen := map[string]bool{}
	for index := range first {
		if first[index].ID != second[index].ID || first[index].Category != "indirect_injection" || seen[first[index].ID] {
			t.Fatalf("sample is not deterministic and distinct at %d", index)
		}
		seen[first[index].ID] = true
	}
	other := Sample("indirect_injection", "pid_95000003-0000-4000-8000-000000000004", DefaultSampleSize)
	same := 0
	for index := range other {
		if other[index].ID == first[index].ID {
			same++
		}
	}
	if same == len(first) {
		t.Fatal("a different run selected the same probes in the same order")
	}
	if prefix := Sample("indirect_injection", run, 5); len(prefix) != 5 || prefix[4].ID != first[4].ID {
		t.Fatal("a smaller sample is not a prefix of a larger one")
	}
	for _, rejected := range [][]Probe{Sample("unknown", run, 5), Sample("tool_abuse", "", 5), Sample("tool_abuse", run, 0), Sample("tool_abuse", run, MaximumSampleSize+1)} {
		if rejected != nil {
			t.Fatal("an invalid sample request selected probes")
		}
	}
}
