package queuedefinition

import (
	"encoding/json"
	"errors"
)

const (
	KindBackground    Kind = "background"
	KindRuntimeEvents Kind = "runtime_events"
	KindTests         Kind = "tests"

	definitionVersion  = 1
	requiredFieldCount = 7
)

var ErrDefinitions = errors.New("queue definitions rejected")

type Kind string

type Settings struct {
	MessageRetentionSeconds            int
	DeadLetterRetentionSeconds         int
	VisibilityTimeoutSeconds           int
	DeadLetterVisibilityTimeoutSeconds int
	ReceiveWaitSeconds                 int
	MaximumMessageBytes                int
	DelaySeconds                       int
	MaxReceiveCount                    int
}

type Definition struct {
	kind               Kind
	name               string
	deadLetterName     string
	schemaID           string
	requiredFields     [requiredFieldCount]string
	requiredFieldCount uint8
	settings           Settings
}

func Definitions() []Definition {
	definitions := canonicalDefinitions()
	return append([]Definition(nil), definitions[:]...)
}

func canonicalDefinitions() [3]Definition {
	return [3]Definition{
		{
			kind:               KindBackground,
			name:               "agentsec-background",
			deadLetterName:     "agentsec-background-dlq",
			schemaID:           "agentsec.background.v1",
			requiredFields:     [requiredFieldCount]string{"version", "organization_id", "workspace_id", "environment_id", "job_id", "kind", "payload"},
			requiredFieldCount: requiredFieldCount,
			settings: Settings{
				MessageRetentionSeconds:            345600,
				DeadLetterRetentionSeconds:         1209600,
				VisibilityTimeoutSeconds:           300,
				DeadLetterVisibilityTimeoutSeconds: 30,
				ReceiveWaitSeconds:                 20,
				MaximumMessageBytes:                262144,
				DelaySeconds:                       0,
				MaxReceiveCount:                    5,
			},
		},
		{
			kind:               KindRuntimeEvents,
			name:               "agentsec-runtime-events",
			deadLetterName:     "agentsec-runtime-events-dlq",
			schemaID:           "agentsec.runtime-events.v1",
			requiredFields:     [requiredFieldCount]string{"version", "organization_id", "workspace_id", "environment_id", "batch_id", "event_count", "events"},
			requiredFieldCount: requiredFieldCount,
			settings: Settings{
				MessageRetentionSeconds:            345600,
				DeadLetterRetentionSeconds:         1209600,
				VisibilityTimeoutSeconds:           120,
				DeadLetterVisibilityTimeoutSeconds: 30,
				ReceiveWaitSeconds:                 20,
				MaximumMessageBytes:                262144,
				DelaySeconds:                       0,
				MaxReceiveCount:                    5,
			},
		},
		{
			kind:               KindTests,
			name:               "agentsec-tests",
			deadLetterName:     "agentsec-tests-dlq",
			schemaID:           "agentsec.tests.v1",
			requiredFields:     [requiredFieldCount]string{"version", "organization_id", "workspace_id", "environment_id", "test_run_id", "kind", "payload"},
			requiredFieldCount: requiredFieldCount,
			settings: Settings{
				MessageRetentionSeconds:            345600,
				DeadLetterRetentionSeconds:         1209600,
				VisibilityTimeoutSeconds:           900,
				DeadLetterVisibilityTimeoutSeconds: 30,
				ReceiveWaitSeconds:                 20,
				MaximumMessageBytes:                262144,
				DelaySeconds:                       0,
				MaxReceiveCount:                    5,
			},
		},
	}
}

func (definition Definition) Validate() error {
	for _, canonical := range canonicalDefinitions() {
		if definition.kind == canonical.kind {
			if definition == canonical {
				return nil
			}
			return ErrDefinitions
		}
	}
	return ErrDefinitions
}

func (definition Definition) Kind() Kind {
	if definition.Validate() != nil {
		return ""
	}
	return definition.kind
}

func (definition Definition) Name() string {
	if definition.Validate() != nil {
		return ""
	}
	return definition.name
}

func (definition Definition) DeadLetterName() string {
	if definition.Validate() != nil {
		return ""
	}
	return definition.deadLetterName
}

func (definition Definition) SchemaID() string {
	if definition.Validate() != nil {
		return ""
	}
	return definition.schemaID
}

func (definition Definition) RequiredFields() []string {
	if definition.Validate() != nil {
		return nil
	}
	return append([]string(nil), definition.requiredFields[:]...)
}

func (definition Definition) Settings() Settings {
	if definition.Validate() != nil {
		return Settings{}
	}
	return definition.settings
}

func JSON() ([]byte, error) {
	definitions := Definitions()
	document := jsonDocument{
		Version:     definitionVersion,
		Definitions: make([]jsonDefinition, 0, len(definitions)),
	}
	for _, definition := range definitions {
		if definition.Validate() != nil {
			return nil, ErrDefinitions
		}
		settings := definition.Settings()
		document.Definitions = append(document.Definitions, jsonDefinition{
			Kind:           definition.Kind(),
			Name:           definition.Name(),
			DeadLetterName: definition.DeadLetterName(),
			Schema: jsonSchema{
				ID:             definition.SchemaID(),
				RequiredFields: definition.RequiredFields(),
			},
			Settings: jsonSettings{
				MessageRetentionSeconds:            settings.MessageRetentionSeconds,
				DeadLetterRetentionSeconds:         settings.DeadLetterRetentionSeconds,
				VisibilityTimeoutSeconds:           settings.VisibilityTimeoutSeconds,
				DeadLetterVisibilityTimeoutSeconds: settings.DeadLetterVisibilityTimeoutSeconds,
				ReceiveWaitSeconds:                 settings.ReceiveWaitSeconds,
				MaximumMessageBytes:                settings.MaximumMessageBytes,
				DelaySeconds:                       settings.DelaySeconds,
				MaxReceiveCount:                    settings.MaxReceiveCount,
			},
		})
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, ErrDefinitions
	}
	return append(encoded, '\n'), nil
}

type jsonDocument struct {
	Version     int              `json:"version"`
	Definitions []jsonDefinition `json:"definitions"`
}

type jsonDefinition struct {
	Kind           Kind         `json:"kind"`
	Name           string       `json:"name"`
	DeadLetterName string       `json:"dead_letter_name"`
	Schema         jsonSchema   `json:"schema"`
	Settings       jsonSettings `json:"settings"`
}

type jsonSchema struct {
	ID             string   `json:"id"`
	RequiredFields []string `json:"required_fields"`
}

type jsonSettings struct {
	MessageRetentionSeconds            int `json:"message_retention_seconds"`
	DeadLetterRetentionSeconds         int `json:"dead_letter_retention_seconds"`
	VisibilityTimeoutSeconds           int `json:"visibility_timeout_seconds"`
	DeadLetterVisibilityTimeoutSeconds int `json:"dead_letter_visibility_timeout_seconds"`
	ReceiveWaitSeconds                 int `json:"receive_wait_seconds"`
	MaximumMessageBytes                int `json:"maximum_message_bytes"`
	DelaySeconds                       int `json:"delay_seconds"`
	MaxReceiveCount                    int `json:"max_receive_count"`
}
