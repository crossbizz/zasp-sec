package sensoradapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func cgroupProbeFixture(t *testing.T, data string, partial bool) []byte {
	t.Helper()
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(qualifiedTetragonFixture(tetragonFileFixture())), &root); err != nil {
		t.Fatal(err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(root["process_kprobe"], &probe); err != nil {
		t.Fatal(err)
	}
	probe["policy_name"] = json.RawMessage(`"zasp-sensitive-file"`)
	if data != "" {
		probe["data"] = json.RawMessage(data)
	}
	if partial {
		probe["process"] = json.RawMessage(`{"pid":42,"start_time":"2026-08-20T12:00:00.000Z"}`)
	}
	encoded, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	root["process_kprobe"] = encoded
	encoded, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestCgroupProbeMembershipIsEventLocalAcrossExecutionCache(t *testing.T) {
	source := lineageSourceFixture()
	source.Profile = "tetragon-local-stream-v2"
	normalizer, err := NewLineageNormalizer(8, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normalizer.Normalize([]byte(qualifiedTetragonFixture(tetragonExecFixture()))); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"12345", "18446744073709551615", ""} {
		data := ""
		if value != "" {
			data = `[{"label":"zasp_cgroup_v2_id","size_arg":"` + value + `"}]`
		}
		line := cgroupProbeFixture(t, data, true)
		event, err := normalizer.Normalize(line)
		if err != nil || event.ObservedLineage.ProcessID != "42" || event.ObservedLineage.CgroupID != value {
			t.Fatal("file membership was lost or inherited from another event", err)
		}
	}
	for _, line := range []string{qualifiedTetragonFixture(tetragonNetworkFixture()), qualifiedTetragonFixture(tetragonExecFixture())} {
		event, err := normalizer.Normalize([]byte(line))
		if err != nil || event.ObservedLineage.CgroupID != "" {
			t.Fatal("non-file event inherited membership", err)
		}
	}
}

func TestCgroupProbeRejectsMalformedJSONPresence(t *testing.T) {
	for _, data := range []string{
		`null`, `[]`, `{}`, `[null]`,
		`[{"label":"zasp_cgroup_v2_id","size_arg":12345}]`,
		`[{"label":"zasp_cgroup_v2_id","size_arg":"0"}]`,
		`[{"label":"zasp_cgroup_v2_id","size_arg":"18446744073709551616"}]`,
		`[{"label":"zasp_cgroup_v2_id","size_arg":"012345"}]`,
		`[{"label":"zasp_cgroup_v2_id","size_arg":"+12345"}]`,
		`[{"label":"zasp_cgroup_v2_id","size_arg":null}]`,
		`[{"Label":"zasp_cgroup_v2_id","size_arg":"12345"}]`,
		`[{"label":"zasp_cgroup_v2_id","SIZE_ARG":"12345"}]`,
		`[{"label":"zasp_cgroup_v2_id","size_arg":"12345","extra":"x"}]`,
		`[{"label":"zasp_cgroup_v2_id","size_arg":"12345"},{"label":"zasp_cgroup_v2_id","size_arg":"12345"}]`,
	} {
		t.Run(data, func(t *testing.T) {
			source := lineageSourceFixture()
			source.Profile = "tetragon-local-stream-v2"
			normalizer, err := NewLineageNormalizer(8, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizer.Normalize(cgroupProbeFixture(t, data, false)); err != ErrAdapter {
				t.Fatal("malformed presence became a valid file event", err)
			}
		})
	}
}

func TestCgroupProbeRequiresQualifiedFileSource(t *testing.T) {
	line := cgroupProbeFixture(t, `[{"label":"zasp_cgroup_v2_id","size_arg":"12345"}]`, false)
	if _, err := NormalizeTetragonLine(line); err != ErrAdapter {
		t.Fatal("stateless input gained cgroup authority", err)
	}
	for _, change := range []func(*LineageSource){
		func(s *LineageSource) { s.NodeName = "another-node" },
	} {
		source := lineageSourceFixture()
		source.Profile = "tetragon-local-stream-v2"
		change(&source)
		normalizer, err := NewLineageNormalizer(8, source)
		if err != nil {
			t.Fatal(err)
		}
		event, err := normalizer.Normalize(line)
		if err != nil || event.ObservedLineage.CgroupID != "" || event.ObservedLineage.Profile != "" {
			t.Fatal("cgroup escaped required physical qualifiers", err)
		}
	}
	for _, bad := range []string{"another-policy", "zasp-sensitive-file-v2"} {
		source := lineageSourceFixture()
		source.Profile = "tetragon-local-stream-v2"
		normalizer, _ := NewLineageNormalizer(8, source)
		if _, err := normalizer.Normalize([]byte(strings.Replace(string(line), "zasp-sensitive-file", bad, 1))); err != ErrAdapter {
			t.Fatal("unrecognized policy supplied membership", err)
		}
	}
}

func TestCgroupProbeRejectsOuterFieldAliasesAndOverwrites(t *testing.T) {
	line := string(cgroupProbeFixture(t, `[{"label":"zasp_cgroup_v2_id","size_arg":"12345"}]`, false))
	for _, replacement := range []string{`"DATA":`, `"Data":`, `"data":null,"DATA":`, `"DATA":null,"data":`, `"data":null,"data":`} {
		source := lineageSourceFixture()
		source.Profile = "tetragon-local-stream-v2"
		normalizer, err := NewLineageNormalizer(8, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := normalizer.Normalize([]byte(strings.Replace(line, `"data":`, replacement, 1))); err != ErrAdapter {
			t.Fatal("outer alias overwrote cgroup presence", replacement, err)
		}
	}
}
