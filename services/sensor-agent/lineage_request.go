package main

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// No caller-supplied filters or aggregation. A fresh owned request prevents one
// subscription from changing a subsequent generation's privacy boundary. Server
// field filters are defense in depth: the local converter still reconstructs
// records, because server filter errors can preserve unfiltered input.
func lineageSubscriptionRequest() *tetragon.GetEventsRequest {
	common := []string{
		"process.exec_id", "process.pid", "process.binary", "process.start_time",
		"process.pod.namespace", "process.pod.name", "process.pod.uid",
		"process.pod.container.id", "process.pod.container.name",
		"process.pod.container.maybe_exec_probe", "parent.pod.container.maybe_exec_probe",
	}
	filter := func(event tetragon.EventType, extra ...string) *tetragon.FieldFilter {
		paths := append(append([]string(nil), common...), extra...)
		return &tetragon.FieldFilter{EventSet: []tetragon.EventType{event}, Fields: &fieldmaskpb.FieldMask{Paths: paths}, Action: tetragon.FieldFilterAction_INCLUDE}
	}
	return &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{{EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_EXEC, tetragon.EventType_PROCESS_EXIT, tetragon.EventType_PROCESS_KPROBE}}},
		DenyList:  []*tetragon.Filter{{HealthCheck: wrapperspb.Bool(true)}, {Namespace: []string{"", "cilium", "kube-system"}}},
		FieldFilters: []*tetragon.FieldFilter{
			filter(tetragon.EventType_PROCESS_EXEC),
			filter(tetragon.EventType_PROCESS_EXIT, "time"),
			filter(tetragon.EventType_PROCESS_KPROBE, "function_name", "args", "action", "return_action", "policy_name", "data"),
		},
	}
}
