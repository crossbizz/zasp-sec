package runtimelineage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixtureObservation() Observation {
	return Observation{Profile: "kubernetes-container-v1", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64)}
}

func TestObservationRoundTripAndOptionalQualifiedProcess(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	for _, runtime := range []string{"containerd", "docker", "cri-o"} {
		value := fixtureObservation()
		value.ContainerID = runtime + "://" + strings.Repeat("b", 64)
		value.ProcessID, value.ProcessStartTime, value.CgroupID = "4294967295", "2026-09-09T11:59:59.123456789Z", "18446744073709551615"
		if !value.ValidAt(now) || !value.Valid() {
			t.Fatalf("qualified observation rejected: %s", runtime)
		}
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Observation
		if err := json.Unmarshal(body, &decoded); err != nil || decoded != value {
			t.Fatalf("round trip: %v", err)
		}
		if decoded.ValidAt(now.Add(-time.Second)) {
			t.Fatal("future process start accepted")
		}
	}
	if !(Observation{}).Valid() || !(Observation{}).ValidAt(now) {
		t.Fatal("absent observation rejected")
	}
	if fixtureObservation().ValidAt(time.Time{}) {
		t.Fatal("missing event time accepted")
	}
}

func TestObservationRejectsUnqualifiedOrNoncanonicalIdentifiers(t *testing.T) {
	mutations := map[string]func(*Observation){
		"missing profile":           func(o *Observation) { o.Profile = "" },
		"unknown profile":           func(o *Observation) { o.Profile = "kubernetes-container-v2" },
		"missing node":              func(o *Observation) { o.NodeUID = "" },
		"node name":                 func(o *Observation) { o.NodeUID = "worker-1" },
		"zero boot":                 func(o *Observation) { o.BootID = "00000000-0000-0000-0000-000000000000" },
		"uppercase uid":             func(o *Observation) { o.PodUID = "AAAAAAAA-1234-1234-1234-123456789004" },
		"uid whitespace":            func(o *Observation) { o.ClusterUID += " " },
		"short docker":              func(o *Observation) { o.ContainerID = "containerd://" + strings.Repeat("a", 15) },
		"bare container":            func(o *Observation) { o.ContainerID = strings.Repeat("a", 64) },
		"unknown runtime":           func(o *Observation) { o.ContainerID = "unknown://" + strings.Repeat("a", 64) },
		"uppercase container":       func(o *Observation) { o.ContainerID = "docker://" + strings.Repeat("A", 64) },
		"container controls":        func(o *Observation) { o.ContainerID += "\n" },
		"zero container":            func(o *Observation) { o.ContainerID = "docker://" + strings.Repeat("0", 64) },
		"bare pid":                  func(o *Observation) { o.ProcessID = "42" },
		"bare start":                func(o *Observation) { o.ProcessStartTime = "2026-09-09T11:00:00Z" },
		"pid overflow":              func(o *Observation) { o.ProcessID = "4294967296"; o.ProcessStartTime = "2026-09-09T11:00:00Z" },
		"cgroup overflow":           func(o *Observation) { o.CgroupID = "18446744073709551616" },
		"cgroup leading zero":       func(o *Observation) { o.CgroupID = "01" },
		"cgroup zero":               func(o *Observation) { o.CgroupID = "0" },
		"cgroup sign":               func(o *Observation) { o.CgroupID = "+1" },
		"cgroup negative":           func(o *Observation) { o.CgroupID = "-1" },
		"timestamp offset":          func(o *Observation) { o.ProcessID = "42"; o.ProcessStartTime = "2026-09-09T11:00:00+00:00" },
		"timestamp redundant zeros": func(o *Observation) { o.ProcessID = "42"; o.ProcessStartTime = "2026-09-09T11:00:00.000Z" },
		"timestamp epoch":           func(o *Observation) { o.ProcessID = "42"; o.ProcessStartTime = "1970-01-01T00:00:00Z" },
		"timestamp unbounded":       func(o *Observation) { o.ProcessID = "42"; o.ProcessStartTime = strings.Repeat("1", 1000) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := fixtureObservation()
			mutate(&value)
			if value.Valid() {
				t.Fatal("invalid observed lineage accepted")
			}
		})
	}
}

func TestObservationJSONIsClosedAndExplicitlyVersioned(t *testing.T) {
	body, err := json.Marshal(fixtureObservation())
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		`null`, `{}`, `[]`, `"lineage"`, string(body) + ` {}`,
		strings.Replace(string(body), `"profile":`, `"profile":"kubernetes-container-v1","profile":`, 1),
		strings.Replace(string(body), `"profile":`, `"domain_id":"forged","profile":`, 1),
		strings.Replace(string(body), `"profile":`, `"sensor_id":"forged","profile":`, 1),
		strings.Replace(string(body), `"profile":`, `"agent_id":"forged","profile":`, 1),
		strings.Replace(string(body), `"profile":`, `"organization_id":"forged","profile":`, 1),
		strings.Replace(string(body), `"profile":`, `"Profile":"kubernetes-container-v1","profile":`, 1),
		strings.Replace(string(body), `"profile":`, `"process_id":null,"profile":`, 1),
		strings.Replace(string(body), `"profile":`, `"cgroup_id":42,"profile":`, 1),
	} {
		var decoded Observation
		if json.Unmarshal([]byte(invalid), &decoded) == nil {
			t.Fatalf("malformed lineage accepted: %.180s", invalid)
		}
	}
}
