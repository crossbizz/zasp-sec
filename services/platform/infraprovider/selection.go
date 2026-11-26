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

// A capability belongs here only when every consumer of the global setting
// can honor it. Narrower settings are validated by the workload that owns them.
var settings = []setting{
	{"ZASP_SECRETS_PROVIDER", []string{"aws-secrets-manager"}},
	{"ZASP_RECOVERY_SIGNING_PROVIDER", []string{"aws-kms"}},
	{"ZASP_EVIDENCE_PROVIDER", []string{"s3"}},
	{"ZASP_EVIDENCE_ENCRYPTION", []string{"aws-kms"}},
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
