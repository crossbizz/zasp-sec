package auditexportconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const policyJSON = `{"schema":"audit-export-policy-v1","policy_id":"pid_52000001-0000-4000-8000-000000000001","bucket":"audit-exports-owned","expected_bucket_owner":"123456789012","kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-4234-8234-123456789012","maximum_export_bytes":1073741824,"maximum_retained_bytes":10737418240,"maximum_inflight":2,"capture_timeout_seconds":120}`

func TestParsePoliciesTrustedRevisions(t *testing.T) {
	body := []byte("[" + policyJSON + "," + strings.ReplaceAll(policyJSON, "52000001", "52000002") + "]")
	before := append([]byte(nil), body...)
	policies, err := ParsePolicies(body)
	if err != nil || len(policies) != 2 {
		t.Fatal("valid trusted revisions rejected", err)
	}
	first := policies[0]
	if first.PolicyID != "pid_52000001-0000-4000-8000-000000000001" || first.ExpectedCurrentPolicyID != "" || first.Bucket != "audit-exports-owned" || first.ExpectedBucketOwner != "123456789012" || first.KMSKeyARN != "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-4234-8234-123456789012" || first.MaximumExportBytes != 1073741824 || first.MaximumRetainedBytes != 10737418240 || first.MaximumInflight != 2 || first.CaptureTimeoutSeconds != 120 || policies[1].PolicyID == first.PolicyID {
		t.Fatal("trusted revision changed")
	}
	if !bytes.Equal(before, body) {
		t.Fatal("parser mutated configuration input")
	}
	clear(body)
	if !reflect.DeepEqual(first, policies[0]) {
		t.Fatal("returned configuration aliases source buffer")
	}
	reordered := strings.Replace(policyJSON, `"schema":"audit-export-policy-v1",`, "", 1)
	reordered = strings.TrimSuffix(reordered, "}") + `,"schema":"audit-export-policy-v1"}`
	again, err := ParsePolicies([]byte(" \n[ " + reordered + " ]\t"))
	if err != nil || len(again) != 1 || !reflect.DeepEqual(first, again[0]) {
		t.Fatal("JSON field order changed policy semantics", err)
	}
	again[0].Bucket = "changed"
	if policies[0].Bucket != first.Bucket {
		t.Fatal("independent parser outputs share mutable state")
	}
}

func TestParsePoliciesRejectAmbiguityAndInvalidAuthority(t *testing.T) {
	cases := []string{"", "null", "{}", "[]", "[null]", "[[]]", "[true]", "[1]", "[\"policy\"]", "[" + policyJSON + "]{}", "[" + policyJSON + "," + policyJSON + "]", "[" + policyJSON + ",]"}
	for _, change := range [][2]string{
		{`"schema":"audit-export-policy-v1"`, `"schema":"other"`},
		{`"schema":`, `"Schema":`},
		{`"schema":"audit-export-policy-v1",`, ""},
		{`"schema":"audit-export-policy-v1"`, `"schema":null`},
		{`"schema":"audit-export-policy-v1"`, `"schema":"audit-export-policy-v1","schema":"audit-export-policy-v1"`},
		{`"schema":"audit-export-policy-v1"`, `"schema":"audit-export-policy-v1","\u0073chema":"audit-export-policy-v1"`},
		{`"schema":`, `"policy_digest":"00","schema":`},
		{`"schema":`, `"expected_current_policy_id":"","schema":`},
		{`"bucket":"audit-exports-owned"`, `"bucket":"bad/bucket"`},
		{`"expected_bucket_owner":"123456789012"`, `"expected_bucket_owner":"123"`},
		{`"policy_id":"pid_52000001-0000-4000-8000-000000000001"`, `"policy_id":"invalid"`},
		{`"capture_timeout_seconds":120`, `"capture_timeout_seconds":121`},
		{`"maximum_inflight":2`, `"maximum_inflight":0`},
		{`"maximum_inflight":2`, `"maximum_inflight":2147483648`},
		{`"maximum_export_bytes":1073741824`, `"maximum_export_bytes":9007199254740992`},
		{`"maximum_retained_bytes":10737418240`, `"maximum_retained_bytes":-1`},
	} {
		cases = append(cases, "["+strings.Replace(policyJSON, change[0], change[1], 1)+"]")
	}
	for _, field := range []string{"maximum_export_bytes", "maximum_retained_bytes", "maximum_inflight", "capture_timeout_seconds"} {
		start := strings.Index(policyJSON, `"`+field+`":`) + len(field) + 3
		end := start + strings.IndexAny(policyJSON[start:], ",}")
		for _, invalid := range []string{"null", "1.0", "1e1", "-0", "01", `"1"`, "true", "{}", "[]", "9223372036854775808"} {
			cases = append(cases, "["+policyJSON[:start]+invalid+policyJSON[end:]+"]")
		}
	}
	cases = append(cases, "["+strings.Replace(policyJSON, "audit-exports-owned", "audit-\xff-exports", 1)+"]")
	for index, value := range cases {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			got, err := ParsePolicies([]byte(value))
			if err != ErrConfiguration || got != nil {
				t.Fatal("ambiguous/invalid configuration accepted or returned partial authority")
			}
		})
	}
}

func TestParsePoliciesBounds(t *testing.T) {
	entries := make([]string, 65)
	for index := range entries {
		entries[index] = strings.ReplaceAll(policyJSON, "52000001", fmt.Sprintf("52%06d", index))
	}
	for _, count := range []int{1, 64, 65} {
		got, err := ParsePolicies([]byte("[" + strings.Join(entries[:count], ",") + "]"))
		if count <= 64 && (err != nil || len(got) != count) || count > 64 && (err != ErrConfiguration || got != nil) {
			t.Fatal("incorrect revision bound", count, err)
		}
	}
	base := "[" + policyJSON + "]"
	for _, size := range []int{128 << 10, (128 << 10) + 1} {
		body := []byte(base + strings.Repeat(" ", size-len(base)))
		got, err := ParsePolicies(body)
		if size == 128<<10 && (err != nil || len(got) != 1) || size > 128<<10 && (err != ErrConfiguration || got != nil) {
			t.Fatal("incorrect byte bound", size, err)
		}
	}
}

func TestParsePoliciesEveryFieldRequiredAndNonNull(t *testing.T) {
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(policyJSON), &fields) != nil {
		t.Fatal("invalid fixture")
	}
	for field, original := range fields {
		for _, mutation := range []string{"missing", "null", "case", "duplicate"} {
			t.Run(field+"/"+mutation, func(t *testing.T) {
				changed := make(map[string]json.RawMessage, len(fields))
				for key, value := range fields {
					changed[key] = value
				}
				switch mutation {
				case "missing":
					delete(changed, field)
				case "null":
					changed[field] = json.RawMessage("null")
				case "case":
					delete(changed, field)
					changed[strings.ToUpper(field)] = original
				}
				body, err := json.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "duplicate" {
					body = []byte(strings.TrimSuffix(string(body), "}") + `,"` + field + `":` + string(original) + "}")
				}
				// A valid first revision must not escape when the second is invalid.
				got, err := ParsePolicies([]byte("[" + policyJSON + "," + string(body) + "]"))
				if err != ErrConfiguration || got != nil {
					t.Fatal("invalid field returned partial authority")
				}
				got, err = ParsePolicies([]byte("[" + string(body) + "]"))
				if err != ErrConfiguration || got != nil {
					t.Fatal("invalid field accepted")
				}
			})
		}
	}
}
