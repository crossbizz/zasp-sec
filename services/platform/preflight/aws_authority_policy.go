package preflight

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

func exactObjectKeys(payload []byte, allowed ...string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil || object == nil {
		return nil, false
	}
	for key := range object {
		found := false
		for _, known := range allowed {
			found = found || key == known
		}
		if !found {
			return nil, false
		}
	}
	return object, true
}
func scalarPolicyString(raw json.RawMessage, expected string) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && value == expected
}
func exactPolicyString(raw json.RawMessage, expected string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == expected
	}
	var list []string
	return json.Unmarshal(raw, &list) == nil && len(list) == 1 && list[0] == expected
}
func exactIRSATrustPolicy(raw, issuer, subject, providerARN string) bool {
	if len(raw) == 0 || len(raw) > 65536 {
		return false
	}
	document := raw
	if !strings.HasPrefix(strings.TrimSpace(document), "{") {
		decoded, e := url.QueryUnescape(raw)
		if e != nil {
			return false
		}
		document = decoded
	}
	if len(document) > 32768 || !uniqueProviderJSON([]byte(document)) {
		return false
	}
	top, ok := exactObjectKeys([]byte(document), "Version", "Statement", "Id")
	if !ok || !scalarPolicyString(top["Version"], "2012-10-17") {
		return false
	}
	var statements []json.RawMessage
	if json.Unmarshal(top["Statement"], &statements) != nil || len(statements) != 1 {
		return false
	}
	statement, ok := exactObjectKeys(statements[0], "Sid", "Effect", "Action", "Principal", "Condition")
	if !ok || !scalarPolicyString(statement["Effect"], "Allow") || !exactPolicyString(statement["Action"], "sts:AssumeRoleWithWebIdentity") {
		return false
	}
	principal, ok := exactObjectKeys(statement["Principal"], "Federated")
	if !ok || !exactPolicyString(principal["Federated"], providerARN) {
		return false
	}
	condition, ok := exactObjectKeys(statement["Condition"], "StringEquals")
	if !ok {
		return false
	}
	prefix := strings.TrimPrefix(issuer, "https://")
	equals, ok := exactObjectKeys(condition["StringEquals"], prefix+":aud", prefix+":sub")
	return ok && len(equals) == 2 && exactPolicyString(equals[prefix+":aud"], "sts.amazonaws.com") && exactPolicyString(equals[prefix+":sub"], subject) && !bytes.Contains([]byte(subject), []byte("*"))
}
