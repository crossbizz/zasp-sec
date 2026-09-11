package main

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	errLineageEvent         = errors.New("sensor lineage event rejected")
	errLineageEventFiltered = errors.New("sensor lineage event excluded")
)

// These are owned, closed records, not aliases of generated protobuf messages.
// The future trusted subscriber must enforce a bounded gRPC receive size before
// decoding. This converter never walks provider maps, ancestors or unknown bytes.
// Binary/file paths and destination addresses remain private normalization inputs;
// this is not a claim that spool records are safe to publish or log.
type lineageEventRecord struct {
	Exec    *lineageExecRecord  `json:"process_exec,omitempty"`
	Exit    *lineageExitRecord  `json:"process_exit,omitempty"`
	Probe   *lineageProbeRecord `json:"process_kprobe,omitempty"`
	Node    string              `json:"node_name"`
	Time    string              `json:"time"`
	Cluster string              `json:"cluster_name"`
	Labels  struct{}            `json:"node_labels"`
}

type lineageExecRecord struct {
	Process lineageProcessRecord `json:"process"`
}
type lineageExitRecord struct {
	Process lineageProcessRecord `json:"process"`
	Time    string               `json:"time"`
}
type lineageProbeRecord struct {
	Process      lineageProcessRecord    `json:"process"`
	Function     string                  `json:"function_name"`
	Args         []lineageArgumentRecord `json:"args"`
	Action       string                  `json:"action"`
	ReturnAction string                  `json:"return_action"`
	Policy       string                  `json:"policy_name"`
	Data         []lineageCgroupRecord   `json:"data,omitempty"`
}
type lineageCgroupRecord struct {
	Label string `json:"label"`
	Size  string `json:"size_arg"`
}
type lineageProcessRecord struct {
	Exec   string            `json:"exec_id,omitempty"`
	PID    uint32            `json:"pid"`
	Binary string            `json:"binary,omitempty"`
	Start  string            `json:"start_time"`
	Pod    *lineagePodRecord `json:"pod,omitempty"`
}
type lineagePodRecord struct {
	Namespace string                 `json:"namespace"`
	Name      string                 `json:"name"`
	UID       string                 `json:"uid"`
	Container lineageContainerRecord `json:"container"`
}
type lineageContainerRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type lineageArgumentRecord struct {
	File   *lineageFileRecord   `json:"file_arg,omitempty"`
	Int    *int64               `json:"int_arg,omitempty"`
	Socket *lineageSocketRecord `json:"sock_arg,omitempty"`
}
type lineageFileRecord struct {
	Path string `json:"path"`
}
type lineageSocketRecord struct {
	Protocol    string `json:"protocol"`
	Destination string `json:"daddr"`
	Port        uint16 `json:"dport"`
}

func sanitizeLineageEvent(event *tetragon.GetEventsResponse) ([]byte, error) {
	if event == nil || len(event.ProtoReflect().GetUnknown()) != 0 || event.AggregationInfo != nil || !lineageRecordText(event.NodeName, 253) || !lineageRecordText(event.ClusterName, 253) {
		return nil, errLineageEvent
	}
	stamp, err := lineageRecordTime(event.Time)
	if err != nil {
		return nil, err
	}
	record := lineageEventRecord{Node: event.NodeName, Cluster: event.ClusterName, Time: stamp}
	switch payload := event.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		if payload == nil || payload.ProcessExec == nil {
			return nil, errLineageEvent
		}
		if lineageParentProbe(payload.ProcessExec.Parent) {
			return nil, errLineageEventFiltered
		}
		process, err := sanitizeLineageProcess(payload.ProcessExec.Process, false)
		if err != nil {
			return nil, err
		}
		record.Exec = &lineageExecRecord{Process: process}
	case *tetragon.GetEventsResponse_ProcessExit:
		if payload == nil || payload.ProcessExit == nil {
			return nil, errLineageEvent
		}
		if lineageParentProbe(payload.ProcessExit.Parent) {
			return nil, errLineageEventFiltered
		}
		process, err := sanitizeLineageProcess(payload.ProcessExit.Process, true)
		if err != nil {
			return nil, err
		}
		exited, err := lineageRecordTime(payload.ProcessExit.Time)
		if err != nil {
			return nil, err
		}
		record.Exit = &lineageExitRecord{Process: process, Time: exited}
	case *tetragon.GetEventsResponse_ProcessKprobe:
		if payload == nil || payload.ProcessKprobe == nil {
			return nil, errLineageEvent
		}
		if lineageParentProbe(payload.ProcessKprobe.Parent) {
			return nil, errLineageEventFiltered
		}
		probe, err := sanitizeLineageProbe(payload.ProcessKprobe)
		if err != nil {
			return nil, err
		}
		record.Probe = &probe
	default:
		// Includes unknown/new oneof variants and rate-limit notifications. The
		// subscriber must account for rejected events/gaps, never silently drop.
		return nil, errLineageEvent
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > 256<<10 {
		return nil, errLineageEvent
	}
	return encoded, nil
}

func sanitizeLineageProcess(process *tetragon.Process, allowPartial bool) (lineageProcessRecord, error) {
	if process == nil || process.GetPid().GetValue() == 0 {
		return lineageProcessRecord{}, errLineageEvent
	}
	stamp, err := lineageRecordTime(process.StartTime)
	if err != nil {
		return lineageProcessRecord{}, err
	}
	record := lineageProcessRecord{PID: process.Pid.Value, Start: stamp}
	// An explicit pid/start-only probe or exit can resolve only through the
	// downstream generation's exact prior exec cache. Never fill in identity here.
	if allowPartial && process.Pod == nil && process.ExecId == "" && process.Binary == "" {
		return record, nil
	}
	if process.Pod == nil {
		return lineageProcessRecord{}, errLineageEvent
	}
	pod := process.Pod
	switch pod.Namespace {
	case "", "cilium", "kube-system":
		return lineageProcessRecord{}, errLineageEventFiltered
	}
	if pod.GetContainer().GetMaybeExecProbe() {
		return lineageProcessRecord{}, errLineageEventFiltered
	}
	if !lineageRecordText(process.ExecId, 256) || !lineageRecordText(process.Binary, 4096) || !lineageRecordText(pod.Namespace, 253) || !lineageRecordText(pod.Name, 253) || !lineageRecordText(pod.Uid, 128) || !lineageRecordText(pod.GetContainer().GetId(), 256) || !lineageRecordText(pod.GetContainer().GetName(), 253) {
		return lineageProcessRecord{}, errLineageEvent
	}
	record.Exec, record.Binary = process.ExecId, process.Binary
	record.Pod = &lineagePodRecord{Namespace: pod.Namespace, Name: pod.Name, UID: pod.Uid, Container: lineageContainerRecord{ID: pod.Container.Id, Name: pod.Container.Name}}
	return record, nil
}

func sanitizeLineageProbe(probe *tetragon.ProcessKprobe) (lineageProbeRecord, error) {
	// Older protobuf decoders can keep a known variant plus unknown bytes for a
	// newer oneof alternative. Reject unknowns on the oneof holder, including
	// when a supported variant is present. Other owned field selection ignores
	// non-oneof extensions (for example process environment variables).
	if len(probe.Args) > 2 {
		return lineageProbeRecord{}, errLineageEvent
	}
	for _, argument := range probe.Args {
		if argument == nil || len(argument.ProtoReflect().GetUnknown()) != 0 {
			return lineageProbeRecord{}, errLineageEvent
		}
	}
	process, err := sanitizeLineageProcess(probe.Process, true)
	if err != nil {
		return lineageProbeRecord{}, err
	}
	action, actionOK := tetragon.KprobeAction_name[int32(probe.Action)]
	returnAction, returnOK := tetragon.KprobeAction_name[int32(probe.ReturnAction)]
	if !actionOK || !returnOK || !lineageRecordText(probe.PolicyName, 256) {
		return lineageProbeRecord{}, errLineageEvent
	}
	record := lineageProbeRecord{Process: process, Function: probe.FunctionName, Action: action, ReturnAction: returnAction, Policy: probe.PolicyName}
	if len(probe.Data) != 0 {
		if probe.FunctionName != "security_file_permission" || probe.PolicyName != "zasp-sensitive-file" || len(probe.Data) != 1 || probe.Data[0] == nil || len(probe.Data[0].ProtoReflect().GetUnknown()) != 0 || probe.Data[0].Label != "zasp_cgroup_v2_id" {
			return lineageProbeRecord{}, errLineageEvent
		}
		value, ok := probe.Data[0].Arg.(*tetragon.KprobeArgument_SizeArg)
		if !ok || value == nil || value.SizeArg == 0 {
			return lineageProbeRecord{}, errLineageEvent
		}
		record.Data = []lineageCgroupRecord{{Label: "zasp_cgroup_v2_id", Size: strconv.FormatUint(value.SizeArg, 10)}}
	}
	switch probe.FunctionName {
	case "security_file_permission":
		if len(probe.Args) != 2 || probe.Args[0] == nil || probe.Args[1] == nil {
			return lineageProbeRecord{}, errLineageEvent
		}
		file, fileOK := probe.Args[0].Arg.(*tetragon.KprobeArgument_FileArg)
		permission, permissionOK := probe.Args[1].Arg.(*tetragon.KprobeArgument_IntArg)
		if !fileOK || file == nil || file.FileArg == nil || !permissionOK || permission == nil || !lineageRecordText(file.FileArg.Path, 4096) {
			return lineageProbeRecord{}, errLineageEvent
		}
		value := int64(permission.IntArg)
		record.Args = []lineageArgumentRecord{{File: &lineageFileRecord{Path: file.FileArg.Path}}, {Int: &value}}
	case "tcp_connect", "inet_csk_accept":
		if len(probe.Args) != 1 || probe.Args[0] == nil {
			return lineageProbeRecord{}, errLineageEvent
		}
		arg, ok := probe.Args[0].Arg.(*tetragon.KprobeArgument_SockArg)
		if !ok || arg == nil || arg.SockArg == nil {
			return lineageProbeRecord{}, errLineageEvent
		}
		socket := arg.SockArg
		if socket.Dport == 0 || socket.Dport > 65535 || !lineageRecordText(socket.Daddr, 256) || socket.Protocol != "IPPROTO_TCP" && socket.Protocol != "TCP" {
			return lineageProbeRecord{}, errLineageEvent
		}
		record.Args = []lineageArgumentRecord{{Socket: &lineageSocketRecord{Protocol: socket.Protocol, Destination: socket.Daddr, Port: uint16(socket.Dport)}}}
	default:
		return lineageProbeRecord{}, errLineageEvent
	}
	return record, nil
}

func lineageRecordText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func lineageParentProbe(process *tetragon.Process) bool {
	return process.GetPod().GetContainer().GetMaybeExecProbe()
}

func lineageRecordTime(stamp *timestamppb.Timestamp) (string, error) {
	if stamp == nil || stamp.CheckValid() != nil {
		return "", errLineageEvent
	}
	return stamp.AsTime().UTC().Format("2006-01-02T15:04:05.000000000Z"), nil
}
