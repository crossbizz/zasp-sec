// Package infraprovider validates infrastructure-wide provider choices before
// the API or a worker opens any external connections.
package infraprovider

import (
	"slices"
	"strings"
)

type setting struct {
	name    string
	choices []string
}

// These selectors name an infrastructure capability. A workload that uses
// the capability also validates its credential, encryption and ownership rules.
var settings = []setting{
	{"ZASP_SECRETS_PROVIDER", []string{"aws-secrets-manager"}},
	{"ZASP_CONNECTOR_SECRETS_PROVIDER", []string{"aws-secrets-manager", "openbao"}},
	{"ZASP_RECOVERY_SIGNING_PROVIDER", []string{"aws-kms", "openbao"}},
	{"ZASP_EVIDENCE_PROVIDER", []string{"s3"}},
	{"ZASP_EVIDENCE_ENCRYPTION", []string{"aws-kms", "provider-managed"}},
	{"ZASP_QUEUE_PROVIDER", []string{"sqs"}},
}

// SelectionError identifies the misconfigured setting without retaining its
// value, since operators can accidentally put a credential in any field.
type SelectionError struct {
	setting setting
}

func (err *SelectionError) Error() string {
	return "unsupported " + err.setting.name + " (supported: " + strings.Join(err.setting.choices, ", ") + ")"
}

// Validate preserves legacy defaults when selectors are omitted. The separate
// backup CLI owns its own selection and has no influence on runtime providers.
func Validate(getenv func(string) string) error {
	for _, spec := range settings {
		value := getenv(spec.name)
		if value == "" {
			continue
		}
		if !slices.Contains(spec.choices, value) {
			return &SelectionError{setting: spec}
		}
	}
	return nil
}
