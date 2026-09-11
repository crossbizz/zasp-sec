package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func lineageProviderFixture(kind string) *tetragon.GetEventsResponse {
	stamp := timestamppb.New(time.Date(2026, 9, 10, 12, 0, 0, 123000000, time.UTC))
	process := &tetragon.Process{ExecId: "exec-42", Pid: wrapperspb.UInt32(42), Binary: "/usr/bin/agent", StartTime: stamp,
		Arguments: "secret-arguments", Cwd: "/secret-cwd", ParentExecId: "secret-parent",
		Pod: &tetragon.Pod{Namespace: "customer", Name: "agent-pod", Uid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			PodLabels: map[string]string{"secret-label": "secret-value"}, PodAnnotations: map[string]string{"secret-annotation": "secret-value"},
			Container: &tetragon.Container{Id: "containerd://" + strings.Repeat("a", 64), Name: "agent", Image: &tetragon.Image{Name: "secret-image"}}}}
	response := &tetragon.GetEventsResponse{NodeName: "node-a", ClusterName: "cluster-a", Time: stamp, NodeLabels: map[string]string{"secret-node-label": "secret-value"}}
	switch kind {
	case "exec":
		response.Event = &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{Process: process, Parent: process, Ancestors: []*tetragon.Process{process}}}
	case "exit":
		response.Event = &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{Process: process, Parent: process, Time: stamp, Signal: "secret-signal"}}
	case "file":
		response.Event = &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{Process: process, FunctionName: "security_file_permission", PolicyName: "zasp-files", Action: tetragon.KprobeAction_KPROBE_ACTION_POST,
			Args: []*tetragon.KprobeArgument{{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/shadow", Mount: "secret-mount", Flags: "secret-flags"}}}, {Arg: &tetragon.KprobeArgument_IntArg{IntArg: 2}}}, Message: "secret-message", Tags: []string{"secret-tag"}}}
	case "network", "accept":
		function := "tcp_connect"
		if kind == "accept" {
			function = "inet_csk_accept"
		}
		response.Event = &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{Process: process, FunctionName: function, PolicyName: "zasp-network", Action: tetragon.KprobeAction_KPROBE_ACTION_POST,
			Args: []*tetragon.KprobeArgument{{Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{Protocol: "IPPROTO_TCP", Daddr: "10.0.0.9", Dport: 443, Saddr: "secret-source", Cookie: 999}}}}}}
	}
	return response
}

func TestLineageEventAllowlistedConversionReachesActualNormalizer(t *testing.T) {
	for _, kind := range []string{"exec", "exit", "file", "network", "accept"} {
		t.Run(kind, func(t *testing.T) {
			response := lineageProviderFixture(kind)
			unknown := protowire.AppendString(protowire.AppendTag(nil, 9999, protowire.BytesType), "secret-unknown")
			var process *tetragon.Process
			switch kind {
			case "exec":
				process = response.GetProcessExec().Process
			case "exit":
				process = response.GetProcessExit().Process
			default:
				process = response.GetProcessKprobe().Process
			}
			process.ProtoReflect().SetUnknown(unknown)
			process.Pod.ProtoReflect().SetUnknown(unknown)
			before, err := proto.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			line, err := sanitizeLineageEvent(response)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(line, []byte("secret-")) {
				t.Fatalf("secret reached spool: %s", line)
			}
			after, _ := proto.MarshalOptions{Deterministic: true}.Marshal(response)
			original := &tetragon.GetEventsResponse{}
			if err := proto.Unmarshal(before, original); err != nil {
				t.Fatal(err)
			}
			canonicalBefore, _ := proto.MarshalOptions{Deterministic: true}.Marshal(original)
			if !bytes.Equal(after, canonicalBefore) {
				t.Fatal("provider input mutated")
			}
			source := sensoradapter.LineageSource{Profile: "tetragon-local-stream-v1", GenerationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", EnrollmentBinding: strings.Repeat("b", 64), NodeName: "node-a", ClusterUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", NodeUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", BootID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}
			normalizer, err := sensoradapter.NewLineageNormalizer(8, source)
			if err != nil {
				t.Fatal(err)
			}
			event, err := normalizer.Normalize(line)
			if err != nil {
				t.Fatalf("normalize: %v, %s", err, line)
			}
			wantClass := map[string]string{"exec": "process", "exit": "process", "file": "file", "network": "network", "accept": "network"}[kind]
			wantAction := map[string]string{"exec": "exec", "exit": "exit", "file": "write", "network": "connect", "accept": "accept"}[kind]
			if event.Class != wantClass || event.Action != wantAction {
				t.Fatalf("wrong event semantics: %#v", event)
			}
			if event.ObservedLineage.BootID != source.BootID || event.ObservedLineage.ProcessID != "42" || event.EventTime != "2026-09-10T12:00:00.123Z" {
				t.Fatalf("event: %#v", event)
			}
			encoded, _ := json.Marshal(event)
			for _, raw := range []string{"secret-", "/etc/shadow", "10.0.0.9", "/usr/bin/agent"} {
				if bytes.Contains(encoded, []byte(raw)) {
					t.Fatalf("raw field in normalized event: %s", encoded)
				}
			}
		})
	}
}

func TestLineageEventRejectsMalformedAndUnsupportedWithoutBytes(t *testing.T) {
	for name, change := range map[string]func(*tetragon.GetEventsResponse){
		"nil-event":    func(r *tetragon.GetEventsResponse) { r.Event = nil },
		"nil-oneof":    func(r *tetragon.GetEventsResponse) { r.Event = (*tetragon.GetEventsResponse_ProcessExec)(nil) },
		"nil-payload":  func(r *tetragon.GetEventsResponse) { r.GetProcessExec().Process = nil },
		"nil-time":     func(r *tetragon.GetEventsResponse) { r.Time = nil },
		"invalid-time": func(r *tetragon.GetEventsResponse) { r.Time.Nanos = -1 },
		"aggregation":  func(r *tetragon.GetEventsResponse) { r.AggregationInfo = &tetragon.AggregationInfo{} },
		"unsupported-event": func(r *tetragon.GetEventsResponse) {
			r.Event = &tetragon.GetEventsResponse_ProcessUprobe{ProcessUprobe: &tetragon.ProcessUprobe{}}
		},
		"missing-start":   func(r *tetragon.GetEventsResponse) { r.GetProcessExec().Process.StartTime = nil },
		"nil-pid":         func(r *tetragon.GetEventsResponse) { r.GetProcessExec().Process.Pid = nil },
		"nil-container":   func(r *tetragon.GetEventsResponse) { r.GetProcessExec().Process.Pod.Container = nil },
		"oversize-binary": func(r *tetragon.GetEventsResponse) { r.GetProcessExec().Process.Binary = strings.Repeat("a", 4097) },
		"invalid-utf8":    func(r *tetragon.GetEventsResponse) { r.GetProcessExec().Process.Binary = string([]byte{255}) },
		"control-byte":    func(r *tetragon.GetEventsResponse) { r.NodeName = "node\n" },
		"missing-node":    func(r *tetragon.GetEventsResponse) { r.NodeName = "" },
	} {
		t.Run(name, func(t *testing.T) {
			r := lineageProviderFixture("exec")
			change(r)
			line, err := sanitizeLineageEvent(r)
			if err == nil || len(line) != 0 {
				t.Fatalf("accepted: %q, %v", line, err)
			}
		})
	}
	if line, err := sanitizeLineageEvent(nil); err == nil || len(line) != 0 {
		t.Fatal("nil accepted")
	}
	for name, change := range map[string]func(*tetragon.ProcessKprobe){
		"unsupported-function": func(p *tetragon.ProcessKprobe) { p.FunctionName = "arbitrary" },
		"unknown-action":       func(p *tetragon.ProcessKprobe) { p.Action = 9999 },
		"port-overflow":        func(p *tetragon.ProcessKprobe) { p.Args[0].GetSockArg().Dport = 65536 },
		"unknown-argument": func(p *tetragon.ProcessKprobe) {
			p.Args[0].Arg = nil
			p.Args[0].ProtoReflect().SetUnknown(protowire.AppendString(protowire.AppendTag(nil, 9999, protowire.BytesType), "secret-unknown"))
		},
		"unsupported-argument": func(p *tetragon.ProcessKprobe) {
			p.Args[0].Arg = &tetragon.KprobeArgument_BytesArg{BytesArg: []byte("secret-argument")}
		},
		"nil-argument":       func(p *tetragon.ProcessKprobe) { p.Args[0] = nil },
		"nil-socket":         func(p *tetragon.ProcessKprobe) { p.Args[0].Arg = &tetragon.KprobeArgument_SockArg{} },
		"typed-nil-argument": func(p *tetragon.ProcessKprobe) { p.Args[0].Arg = (*tetragon.KprobeArgument_SockArg)(nil) },
		"extra-argument":     func(p *tetragon.ProcessKprobe) { p.Args = append(p.Args, p.Args[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			r := lineageProviderFixture("network")
			change(r.GetProcessKprobe())
			line, err := sanitizeLineageEvent(r)
			if err == nil || len(line) != 0 {
				t.Fatalf("accepted: %q, %v", line, err)
			}
		})
	}
}

func TestLineageEventExclusionsHaveDistinctResult(t *testing.T) {
	for _, namespace := range []string{"", "cilium", "kube-system"} {
		r := lineageProviderFixture("exec")
		r.GetProcessExec().Process.Pod.Namespace = namespace
		if line, err := sanitizeLineageEvent(r); !errors.Is(err, errLineageEventFiltered) || len(line) != 0 {
			t.Fatalf("namespace %q: %q, %v", namespace, line, err)
		}
	}
	r := lineageProviderFixture("exec")
	r.GetProcessExec().Process.Pod.Container.MaybeExecProbe = true
	if line, err := sanitizeLineageEvent(r); !errors.Is(err, errLineageEventFiltered) || len(line) != 0 {
		t.Fatalf("probe: %q, %v", line, err)
	}
}

func TestLineageEventExcludesParentHealthChecks(t *testing.T) {
	for _, kind := range []string{"exec", "exit", "file"} {
		r := lineageProviderFixture(kind)
		parent := &tetragon.Process{Pod: &tetragon.Pod{Container: &tetragon.Container{MaybeExecProbe: true}}}
		switch kind {
		case "exec":
			r.GetProcessExec().Parent = parent
		case "exit":
			r.GetProcessExit().Parent = parent
		default:
			r.GetProcessKprobe().Parent = parent
		}
		if line, err := sanitizeLineageEvent(r); !errors.Is(err, errLineageEventFiltered) || len(line) != 0 {
			t.Fatalf("%s parent probe: %q, %v", kind, line, err)
		}
	}
}

func TestLineageSubscriberRequestHasFixedScopeAndFreshOwnedFilters(t *testing.T) {
	request := lineageSubscriptionRequest()
	wire, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &tetragon.GetEventsRequest{}
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.AggregationOptions != nil || len(decoded.AllowList) != 1 || len(decoded.DenyList) != 2 || len(decoded.FieldFilters) != 3 {
		t.Fatalf("request scope: %v", decoded)
	}
	if !proto.Equal(decoded.AllowList[0], &tetragon.Filter{EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_EXEC, tetragon.EventType_PROCESS_EXIT, tetragon.EventType_PROCESS_KPROBE}}) {
		t.Fatal("event scope widened")
	}
	if !proto.Equal(decoded.DenyList[0], &tetragon.Filter{HealthCheck: wrapperspb.Bool(true)}) || !proto.Equal(decoded.DenyList[1], &tetragon.Filter{Namespace: []string{"", "cilium", "kube-system"}}) {
		t.Fatal("exclusion changed")
	}
	common := []string{"process.exec_id", "process.pid", "process.binary", "process.start_time", "process.pod.namespace", "process.pod.name", "process.pod.uid", "process.pod.container.id", "process.pod.container.name", "process.pod.container.maybe_exec_probe", "parent.pod.container.maybe_exec_probe"}
	for index, event := range []tetragon.EventType{tetragon.EventType_PROCESS_EXEC, tetragon.EventType_PROCESS_EXIT, tetragon.EventType_PROCESS_KPROBE} {
		paths := append([]string(nil), common...)
		var message proto.Message = &tetragon.ProcessExec{}
		if index == 1 {
			paths = append(paths, "time")
			message = &tetragon.ProcessExit{}
		}
		if index == 2 {
			paths = append(paths, "function_name", "args", "action", "return_action", "policy_name")
			message = &tetragon.ProcessKprobe{}
		}
		want := &tetragon.FieldFilter{EventSet: []tetragon.EventType{event}, Fields: &fieldmaskpb.FieldMask{Paths: paths}, Action: tetragon.FieldFilterAction_INCLUDE}
		if !proto.Equal(decoded.FieldFilters[index], want) || !want.Fields.IsValid(message) {
			t.Fatalf("field filter %d: %v", index, decoded.FieldFilters[index])
		}
	}
	request.AllowList[0].EventSet[0] = tetragon.EventType_PROCESS_UPROBE
	request.DenyList[0].HealthCheck.Value = false
	request.FieldFilters[0].Fields.Paths[0] = "process"
	if !proto.Equal(lineageSubscriptionRequest(), decoded) {
		t.Fatal("caller mutation changed later subscription")
	}
}

func TestLineageEventPartialIdentityPreservesExactCacheKey(t *testing.T) {
	r := lineageProviderFixture("exec")
	execLine, err := sanitizeLineageEvent(r)
	if err != nil {
		t.Fatal(err)
	}
	normalizer, _ := sensoradapter.NewNormalizer(8)
	if _, err = normalizer.Normalize(execLine); err != nil {
		t.Fatal(err)
	}
	probe := lineageProviderFixture("file")
	probe.GetProcessKprobe().Process = &tetragon.Process{Pid: wrapperspb.UInt32(42), StartTime: r.Time}
	line, err := sanitizeLineageEvent(probe)
	if err != nil {
		t.Fatal(err)
	}
	if event, err := normalizer.Normalize(line); err != nil || event.Class != "file" {
		t.Fatalf("partial: %#v, %v", event, err)
	}
	empty, _ := sensoradapter.NewNormalizer(8)
	if _, err := empty.Normalize(line); err == nil {
		t.Fatal("uncached partial accepted")
	}
	probe.GetProcessKprobe().Process.StartTime = timestamppb.New(r.Time.AsTime().Add(time.Nanosecond))
	drift, err := sanitizeLineageEvent(probe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normalizer.Normalize(drift); err == nil {
		t.Fatal("same PID with changed precise start reused cache")
	}
	exit := lineageProviderFixture("exit")
	exit.GetProcessExit().Process = &tetragon.Process{Pid: wrapperspb.UInt32(42), StartTime: r.Time}
	exitLine, err := sanitizeLineageEvent(exit)
	if err != nil {
		t.Fatal(err)
	}
	if event, err := normalizer.Normalize(exitLine); err != nil || event.Action != "exit" {
		t.Fatalf("partial exit: %#v, %v", event, err)
	}
	if _, err := normalizer.Normalize(line); err == nil {
		t.Fatal("partial exit did not evict cached process")
	}
}

func TestLineageEventPreservesSubmillisecondStartWithoutRounding(t *testing.T) {
	r := lineageProviderFixture("exec")
	r.GetProcessExec().Process.StartTime = timestamppb.New(r.Time.AsTime().Add(time.Nanosecond))
	line, err := sanitizeLineageEvent(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"start_time":"2026-09-10T12:00:00.123000001Z"`)) {
		t.Fatalf("start precision lost: %s", line)
	}
	source := sensoradapter.LineageSource{Profile: "tetragon-local-stream-v1", GenerationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", EnrollmentBinding: strings.Repeat("b", 64), NodeName: "node-a", ClusterUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", NodeUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", BootID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}
	normalizer, err := sensoradapter.NewLineageNormalizer(8, source)
	if err != nil {
		t.Fatal(err)
	}
	event, err := normalizer.Normalize(line)
	if err != nil || event.ObservedLineage.BootID != source.BootID || event.ObservedLineage.ProcessID != "" || event.ObservedLineage.ProcessStartTime != "" {
		t.Fatalf("precision qualified incorrectly: %#v, %v", event, err)
	}
}

func TestLineageEventRejectsUnknownOneofHolderFields(t *testing.T) {
	// An older decoder can retain a known oneof and unknown newer oneof bytes
	// together. Never reinterpret that ambiguous object as the supported variant.
	unknown := protowire.AppendBytes(protowire.AppendTag(nil, 9999, protowire.BytesType), []byte("secret-new-variant"))
	for _, target := range []string{"event", "file-argument", "permission-argument", "socket-argument"} {
		t.Run(target, func(t *testing.T) {
			kind := "file"
			if target == "socket-argument" {
				kind = "network"
			}
			r := lineageProviderFixture(kind)
			if target == "event" {
				r.ProtoReflect().SetUnknown(unknown)
			} else {
				index := 0
				if target == "permission-argument" {
					index = 1
				}
				r.GetProcessKprobe().Args[index].ProtoReflect().SetUnknown(unknown)
			}
			if line, err := sanitizeLineageEvent(r); err == nil || len(line) != 0 {
				t.Fatalf("ambiguous %s accepted: %q, %v", target, line, err)
			}
		})
	}
}
