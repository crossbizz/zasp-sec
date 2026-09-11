package sensoradapter

import (
	"encoding/json"
	"strconv"
	"strings"
)

func (probe *providerKprobe) UnmarshalJSON(body []byte) error {
	var fields map[string]json.RawMessage
	if !uniqueJSON(body) || decodeClosed(body, &fields) != nil {
		return ErrAdapter
	}
	for key := range fields {
		if strings.EqualFold(key, "data") && key != "data" {
			return ErrAdapter
		}
	}
	type wire providerKprobe
	var value wire
	if decodeClosed(body, &value) != nil {
		return ErrAdapter
	}
	*probe = providerKprobe(value)
	return nil
}

// Membership belongs to this synchronous file hook's current task at event
// time. It is not a cgroup namespace inode, semantic sandbox, lifetime interval,
// or cgroup-v1 controller ID. In particular, never retain it in the exec cache
// or attach current-task data to a socket creator reported by a network hook.
func (source LineageSource) fileCgroup(probe *providerKprobe) (string, error) {
	if probe == nil || len(probe.Data) == 0 {
		return "", nil
	}
	if source.Profile != "tetragon-local-stream-v2" || probe.FunctionName != "security_file_permission" || probe.PolicyName != "zasp-sensitive-file" {
		return "", ErrAdapter
	}
	var data []map[string]string
	if decodeClosed(probe.Data, &data) != nil || len(data) != 1 || len(data[0]) != 2 || data[0]["label"] != "zasp_cgroup_v2_id" || len(data[0]["size_arg"]) < 1 || len(data[0]["size_arg"]) > 20 {
		return "", ErrAdapter
	}
	value, err := strconv.ParseUint(data[0]["size_arg"], 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != data[0]["size_arg"] {
		return "", ErrAdapter
	}
	return data[0]["size_arg"], nil
}
