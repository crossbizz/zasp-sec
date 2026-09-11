package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"google.golang.org/protobuf/encoding/protowire"
)

func lineageCgroupProviderFixture(value uint64) *tetragon.GetEventsResponse {
	event := lineageProviderFixture("file")
	probe := event.GetProcessKprobe()
	probe.PolicyName = "zasp-sensitive-file"
	probe.Data = []*tetragon.KprobeArgument{{Label: "zasp_cgroup_v2_id", Arg: &tetragon.KprobeArgument_SizeArg{SizeArg: value}}}
	return event
}

func TestLineageCgroupFileObservationReachesNormalizerLosslessly(t *testing.T) {
	for _, value := range []uint64{12345, 9007199254740993, ^uint64(0)} {
		provider := lineageCgroupProviderFixture(value)
		line, err := sanitizeLineageEvent(provider)
		if err != nil {
			t.Fatal(err)
		}
		// The owned spool uses decimal strings for uint64, like protobuf JSON.
		var wire struct {
			Probe struct {
				Data []struct {
					Label string `json:"label"`
					Size  string `json:"size_arg"`
				} `json:"data"`
			} `json:"process_kprobe"`
		}
		if json.Unmarshal(line, &wire) != nil || len(wire.Probe.Data) != 1 || wire.Probe.Data[0].Label != "zasp_cgroup_v2_id" || wire.Probe.Data[0].Size != strconv.FormatUint(value, 10) {
			t.Fatal("observed cgroup was discarded before the spool")
		}
		source := lineageSpoolSource()
		source.Profile = "tetragon-local-stream-v2"
		normalizer, err := sensoradapter.NewLineageNormalizer(8, source)
		if err != nil {
			t.Fatal(err)
		}
		event, err := normalizer.Normalize(line)
		if err != nil || event.ObservedLineage.CgroupID != wire.Probe.Data[0].Size || event.ObservedLineage.ProcessID != "42" {
			t.Fatal("observed file membership did not reach normalization", err)
		}
		if bytes.Contains(line, []byte("secret-")) {
			t.Fatal("provider-private data escaped the allowlist")
		}
		// Historical profiles cannot interpret a new record as an ordinary event.
		source.Profile = "tetragon-local-stream-v1"
		oldProfile, _ := sensoradapter.NewLineageNormalizer(8, source)
		if _, err := oldProfile.Normalize(line); err == nil {
			t.Fatal("new record accepted under historical generation")
		}
	}
}

func TestLineageCgroupRejectsMalformedPresence(t *testing.T) {
	for name, change := range map[string]func(*tetragon.ProcessKprobe){
		"zero":           func(p *tetragon.ProcessKprobe) { p.Data[0].Arg = &tetragon.KprobeArgument_SizeArg{} },
		"signed":         func(p *tetragon.ProcessKprobe) { p.Data[0].Arg = &tetragon.KprobeArgument_LongArg{LongArg: 12345} },
		"nil entry":      func(p *tetragon.ProcessKprobe) { p.Data[0] = nil },
		"nil variant":    func(p *tetragon.ProcessKprobe) { p.Data[0].Arg = nil },
		"typed nil":      func(p *tetragon.ProcessKprobe) { p.Data[0].Arg = (*tetragon.KprobeArgument_SizeArg)(nil) },
		"duplicate":      func(p *tetragon.ProcessKprobe) { p.Data = append(p.Data, p.Data[0]) },
		"unknown label":  func(p *tetragon.ProcessKprobe) { p.Data[0].Label = "cgroup_namespace" },
		"foreign policy": func(p *tetragon.ProcessKprobe) { p.PolicyName = "another-policy" },
		"socket owner":   func(p *tetragon.ProcessKprobe) { p.FunctionName = "tcp_connect" },
		"unknown oneof": func(p *tetragon.ProcessKprobe) {
			p.Data[0].ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 999, protowire.VarintType), 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider := lineageCgroupProviderFixture(12345)
			change(provider.GetProcessKprobe())
			if line, err := sanitizeLineageEvent(provider); err != errLineageEvent || len(line) != 0 {
				t.Fatal("malformed cgroup became a valid event", err)
			}
		})
	}
}

func TestLineageCgroupHistoricalRecordBytesStayUnchanged(t *testing.T) {
	for _, kind := range []string{"exec", "exit", "file", "network", "accept"} {
		line, err := sanitizeLineageEvent(lineageProviderFixture(kind))
		if err != nil || strings.Contains(string(line), `"data"`) {
			t.Fatal("absent cgroup changed historical record shape", err)
		}
		old := lineageSpoolSource()
		modern := old
		modern.Profile = "tetragon-local-stream-v2"
		previous, err := sensoradapter.NewLineageNormalizer(8, old)
		if err != nil {
			t.Fatal(err)
		}
		next, err := sensoradapter.NewLineageNormalizer(8, modern)
		if err != nil {
			t.Fatal(err)
		}
		before, err := previous.Normalize(line)
		if err != nil {
			t.Fatal(err)
		}
		after, err := next.Normalize(line)
		if err != nil {
			t.Fatal(err)
		}
		beforeBytes, _ := json.Marshal(before)
		afterBytes, _ := json.Marshal(after)
		if !bytes.Equal(beforeBytes, afterBytes) {
			t.Fatal("historical normalization changed on reader upgrade")
		}
	}
}
