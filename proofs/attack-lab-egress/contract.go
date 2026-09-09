package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

type egressRule struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// This reads the same source Terraform uses, not a separate fixture allowlist.
// Expectations are intentionally exact: expanding permissions requires review.
func readContract(source []byte) (map[string]egressRule, error) {
	var value struct {
		Schema           string                `json:"schema_version"`
		Rules            map[string]egressRule `json:"rules"`
		ImageLayerPolicy json.RawMessage       `json:"image_layer_policy"`
	}
	bad := errors.New("bounded production egress contract required")
	if len(source) == 0 || len(source) > 16384 {
		return nil, bad
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, bad
	}
	expected := map[string]egressRule{
		"proxy": {"tcp", 8443}, "ecr": {"tcp", 443}, "s3": {"tcp", 443},
		"control_plane": {"tcp", 443}, "dns_udp": {"udp", 53}, "dns_tcp": {"tcp", 53},
	}
	if value.Schema != "attack-lab-egress-v1" || !reflect.DeepEqual(value.Rules, expected) {
		return nil, bad
	}
	return value.Rules, nil
}
