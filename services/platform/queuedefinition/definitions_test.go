package queuedefinition

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

type expectedDefinition struct {
	kind           Kind
	name           string
	deadLetterName string
	schemaID       string
	requiredFields []string
	settings       Settings
}

var expectedDefinitions = []expectedDefinition{
	{
		kind:           KindBackground,
		name:           "agentsec-background",
		deadLetterName: "agentsec-background-dlq",
		schemaID:       "agentsec.background.v1",
		requiredFields: []string{"version", "organization_id", "workspace_id", "environment_id", "job_id", "kind", "payload"},
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
		kind:           KindRuntimeEvents,
		name:           "agentsec-runtime-events",
		deadLetterName: "agentsec-runtime-events-dlq",
		schemaID:       "agentsec.runtime-events.v1",
		requiredFields: []string{"version", "organization_id", "workspace_id", "environment_id", "batch_id", "event_count", "events"},
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
		kind:           KindTests,
		name:           "agentsec-tests",
		deadLetterName: "agentsec-tests-dlq",
		schemaID:       "agentsec.tests.v1",
		requiredFields: []string{"version", "organization_id", "workspace_id", "environment_id", "test_run_id", "kind", "payload"},
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

func TestDefinitionsExposeExactProductContract(t *testing.T) {
	definitions := Definitions()
	if len(definitions) != len(expectedDefinitions) {
		t.Fatalf("Definitions length = %d", len(definitions))
	}
	for index, expected := range expectedDefinitions {
		definition := definitions[index]
		if err := definition.Validate(); err != nil {
			t.Fatalf("definition %d Validate returned error: %v", index, err)
		}
		if definition.Kind() != expected.kind ||
			definition.Name() != expected.name ||
			definition.DeadLetterName() != expected.deadLetterName ||
			definition.SchemaID() != expected.schemaID ||
			!reflect.DeepEqual(definition.RequiredFields(), expected.requiredFields) ||
			definition.Settings() != expected.settings {
			t.Fatalf("definition %d does not match exact contract", index)
		}
	}
}

func TestZeroDefinitionRejectsAndExposesNoState(t *testing.T) {
	var definition Definition
	if err := definition.Validate(); err != ErrDefinitions {
		t.Fatalf("Validate error = %v, want ErrDefinitions", err)
	}
	if definition.Kind() != "" || definition.Name() != "" || definition.DeadLetterName() != "" ||
		definition.SchemaID() != "" || definition.RequiredFields() != nil || definition.Settings() != (Settings{}) {
		t.Fatal("zero Definition exposed state")
	}
	if ErrDefinitions.Error() != "queue definitions rejected" {
		t.Fatalf("ErrDefinitions text = %q", ErrDefinitions)
	}
}

func TestDefinitionsJSONIsExactDeterministicAndFresh(t *testing.T) {
	want := []byte("{\"version\":1,\"definitions\":[{\"kind\":\"background\",\"name\":\"agentsec-background\",\"dead_letter_name\":\"agentsec-background-dlq\",\"schema\":{\"id\":\"agentsec.background.v1\",\"required_fields\":[\"version\",\"organization_id\",\"workspace_id\",\"environment_id\",\"job_id\",\"kind\",\"payload\"]},\"settings\":{\"message_retention_seconds\":345600,\"dead_letter_retention_seconds\":1209600,\"visibility_timeout_seconds\":300,\"dead_letter_visibility_timeout_seconds\":30,\"receive_wait_seconds\":20,\"maximum_message_bytes\":262144,\"delay_seconds\":0,\"max_receive_count\":5}},{\"kind\":\"runtime_events\",\"name\":\"agentsec-runtime-events\",\"dead_letter_name\":\"agentsec-runtime-events-dlq\",\"schema\":{\"id\":\"agentsec.runtime-events.v1\",\"required_fields\":[\"version\",\"organization_id\",\"workspace_id\",\"environment_id\",\"batch_id\",\"event_count\",\"events\"]},\"settings\":{\"message_retention_seconds\":345600,\"dead_letter_retention_seconds\":1209600,\"visibility_timeout_seconds\":120,\"dead_letter_visibility_timeout_seconds\":30,\"receive_wait_seconds\":20,\"maximum_message_bytes\":262144,\"delay_seconds\":0,\"max_receive_count\":5}},{\"kind\":\"tests\",\"name\":\"agentsec-tests\",\"dead_letter_name\":\"agentsec-tests-dlq\",\"schema\":{\"id\":\"agentsec.tests.v1\",\"required_fields\":[\"version\",\"organization_id\",\"workspace_id\",\"environment_id\",\"test_run_id\",\"kind\",\"payload\"]},\"settings\":{\"message_retention_seconds\":345600,\"dead_letter_retention_seconds\":1209600,\"visibility_timeout_seconds\":900,\"dead_letter_visibility_timeout_seconds\":30,\"receive_wait_seconds\":20,\"maximum_message_bytes\":262144,\"delay_seconds\":0,\"max_receive_count\":5}}]}\n")

	first, err := JSON()
	if err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}
	if !bytes.Equal(first, want) {
		t.Fatalf("JSON = %s\nwant = %s", first, want)
	}
	decoded, err := decodeUniqueJSON(first)
	if err != nil {
		t.Fatalf("JSON did not pass duplicate-key decoder: %v", err)
	}
	document, ok := decoded.(map[string]any)
	if !ok || len(document) != 2 || document["version"] != json.Number("1") {
		t.Fatalf("decoded document = %#v", decoded)
	}
	definitions, ok := document["definitions"].([]any)
	if !ok || len(definitions) != 3 {
		t.Fatalf("decoded definitions = %#v", document["definitions"])
	}
	if _, err := decodeUniqueJSON([]byte("{\"version\":1,\"version\":1}")); err == nil {
		t.Fatal("duplicate-key test decoder accepted a duplicate")
	}

	for index := range first {
		first[index] = 0
	}
	second, err := JSON()
	if err != nil || !bytes.Equal(second, want) {
		t.Fatalf("second JSON = %s, %v", second, err)
	}
}

func TestDefinitionsReturnFreshIndependentValues(t *testing.T) {
	first := Definitions()
	for index := range first {
		first[index] = Definition{}
	}
	if second := Definitions(); len(second) != 3 || second[0].Validate() != nil || second[1].Validate() != nil || second[2].Validate() != nil {
		t.Fatalf("mutated definition slice escaped: %#v", second)
	}

	for index, definition := range Definitions() {
		fields := definition.RequiredFields()
		for fieldIndex := range fields {
			fields[fieldIndex] = "attacker"
		}
		if got := definition.RequiredFields(); !reflect.DeepEqual(got, expectedDefinitions[index].requiredFields) {
			t.Fatalf("mutated required fields %d escaped: %#v", index, got)
		}

		settings := definition.Settings()
		settings.MessageRetentionSeconds++
		settings.DeadLetterRetentionSeconds++
		settings.VisibilityTimeoutSeconds++
		settings.DeadLetterVisibilityTimeoutSeconds++
		settings.ReceiveWaitSeconds++
		settings.MaximumMessageBytes++
		settings.DelaySeconds++
		settings.MaxReceiveCount++
		if got := definition.Settings(); got != expectedDefinitions[index].settings {
			t.Fatalf("mutated settings %d escaped: %#v", index, got)
		}
	}
}

func TestDefinitionsRejectEveryForgedField(t *testing.T) {
	valid := Definitions()[0]
	invalidUTF8 := string([]byte{0xff})
	oversized := strings.Repeat("a", 257)
	tests := map[string]Definition{
		"zero":               {},
		"unknown kind":       mutateDefinition(valid, func(value *Definition) { value.kind = Kind("unknown") }),
		"source name":        mutateDefinition(valid, func(value *Definition) { value.name = "agentsec-background-forged" }),
		"dead letter name":   mutateDefinition(valid, func(value *Definition) { value.deadLetterName = "agentsec-background" }),
		"dead letter suffix": mutateDefinition(valid, func(value *Definition) { value.deadLetterName = "agentsec-background.dlq" }),
		"schema id":          mutateDefinition(valid, func(value *Definition) { value.schemaID = "agentsec.background.v2" }),
		"missing field":      mutateDefinition(valid, func(value *Definition) { value.requiredFields[6] = "" }),
		"extra field count":  mutateDefinition(valid, func(value *Definition) { value.requiredFieldCount = 8 }),
		"reordered fields": mutateDefinition(valid, func(value *Definition) {
			value.requiredFields[0], value.requiredFields[1] = value.requiredFields[1], value.requiredFields[0]
		}),
		"duplicate field":        mutateDefinition(valid, func(value *Definition) { value.requiredFields[6] = value.requiredFields[0] }),
		"dotted field":           mutateDefinition(valid, func(value *Definition) { value.requiredFields[6] = "payload.value" }),
		"control field":          mutateDefinition(valid, func(value *Definition) { value.requiredFields[6] = "payload\n" }),
		"invalid utf8 field":     mutateDefinition(valid, func(value *Definition) { value.requiredFields[6] = invalidUTF8 }),
		"oversized field":        mutateDefinition(valid, func(value *Definition) { value.requiredFields[6] = oversized }),
		"source retention":       mutateDefinition(valid, func(value *Definition) { value.settings.MessageRetentionSeconds++ }),
		"dead letter retention":  mutateDefinition(valid, func(value *Definition) { value.settings.DeadLetterRetentionSeconds++ }),
		"source visibility":      mutateDefinition(valid, func(value *Definition) { value.settings.VisibilityTimeoutSeconds++ }),
		"dead letter visibility": mutateDefinition(valid, func(value *Definition) { value.settings.DeadLetterVisibilityTimeoutSeconds++ }),
		"receive wait":           mutateDefinition(valid, func(value *Definition) { value.settings.ReceiveWaitSeconds-- }),
		"maximum message bytes":  mutateDefinition(valid, func(value *Definition) { value.settings.MaximumMessageBytes-- }),
		"delay":                  mutateDefinition(valid, func(value *Definition) { value.settings.DelaySeconds++ }),
		"maximum receive count":  mutateDefinition(valid, func(value *Definition) { value.settings.MaxReceiveCount++ }),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); err != ErrDefinitions {
				t.Fatalf("Validate error = %v, want ErrDefinitions", err)
			}
			if candidate.Kind() != "" || candidate.Name() != "" || candidate.DeadLetterName() != "" ||
				candidate.SchemaID() != "" || candidate.RequiredFields() != nil || candidate.Settings() != (Settings{}) {
				t.Fatal("invalid Definition exposed state")
			}
		})
	}

	for index, definition := range Definitions() {
		forged := mutateDefinition(definition, func(value *Definition) {
			value.name = expectedDefinitions[(index+1)%len(expectedDefinitions)].name
		})
		if err := forged.Validate(); err != ErrDefinitions {
			t.Fatalf("cross-kind forged definition %d error = %v", index, err)
		}
	}
}

func TestDefinitionsAreConcurrent(t *testing.T) {
	const workers = 64
	errorsByWorker := make(chan error, workers)
	for range workers {
		go func() {
			definitions := Definitions()
			if len(definitions) != 3 {
				errorsByWorker <- fmt.Errorf("definition count = %d", len(definitions))
				return
			}
			for _, definition := range definitions {
				if err := definition.Validate(); err != nil {
					errorsByWorker <- err
					return
				}
				fields := definition.RequiredFields()
				if definition.Kind() == "" || definition.Name() == "" || definition.DeadLetterName() == "" ||
					definition.SchemaID() == "" || len(fields) != 7 || definition.Settings() == (Settings{}) {
					errorsByWorker <- fmt.Errorf("invalid accessor state")
					return
				}
			}
			output, err := JSON()
			if err != nil || len(output) == 0 {
				errorsByWorker <- fmt.Errorf("JSON failed: %w", err)
				return
			}
			errorsByWorker <- nil
		}()
	}
	for range workers {
		if err := <-errorsByWorker; err != nil {
			t.Fatal(err)
		}
	}
}

func mutateDefinition(source Definition, mutate func(*Definition)) Definition {
	mutate(&source)
	return source
}

func decodeUniqueJSON(input []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	value, err := decodeUniqueJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON token %v: %w", token, err)
	}
	return value, nil
}

func decodeUniqueJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		result := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not text")
			}
			if _, duplicate := result[key]; duplicate {
				return nil, fmt.Errorf("duplicate object key")
			}
			value, err := decodeUniqueJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			return nil, fmt.Errorf("invalid object close")
		}
		return result, nil
	case '[':
		result := make([]any, 0)
		for decoder.More() {
			value, err := decodeUniqueJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			return nil, fmt.Errorf("invalid array close")
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter")
	}
}
