package eventindex

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/eventstore"
)

var expectedSessionRuntimeFields = []Field{
	{Name: "organization_id", Type: "keyword", IgnoreAbove: 40},
	{Name: "workspace_id", Type: "keyword", IgnoreAbove: 40},
	{Name: "environment_id", Type: "keyword", IgnoreAbove: 40},
	{Name: "event_id", Type: "keyword", IgnoreAbove: 40},
	{Name: "session_id", Type: "keyword", IgnoreAbove: 40},
	{Name: "agent_id", Type: "keyword", IgnoreAbove: 40},
	{Name: "source", Type: "keyword", IgnoreAbove: 32},
	{Name: "source_event_id", Type: "keyword", IgnoreAbove: 256},
	{Name: "event_class", Type: "keyword", IgnoreAbove: 32},
	{Name: "action", Type: "keyword", IgnoreAbove: 64},
	{Name: "decision", Type: "keyword", IgnoreAbove: 16},
	{Name: "event_time", Type: "date", Format: "strict_date_time"},
}

func TestSessionRuntimeTemplateMatchesDriverDocument(t *testing.T) {
	template := SessionRuntimeTemplate()
	if err := template.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if got := template.Pattern(); got != "zasp-session-runtime-events-v1-*" {
		t.Fatalf("Pattern = %q", got)
	}
	if got := template.Priority(); got != 100 {
		t.Fatalf("Priority = %d", got)
	}
	if got := template.Version(); got != 1 {
		t.Fatalf("Version = %d", got)
	}
	if got := template.Fields(); !reflect.DeepEqual(got, expectedSessionRuntimeFields) {
		t.Fatalf("Fields = %#v", got)
	}

	documentType := reflect.TypeOf(eventstore.DriverDocument{})
	wantDriverFields := []string{
		"OrganizationID", "WorkspaceID", "EnvironmentID", "EventID", "SessionID", "AgentID",
		"Source", "SourceEventID", "Class", "Action", "Decision", "EventTime",
	}
	if documentType.NumField() != len(wantDriverFields) {
		t.Fatalf("DriverDocument field count = %d", documentType.NumField())
	}
	for index, want := range wantDriverFields {
		if got := documentType.Field(index).Name; got != want {
			t.Fatalf("DriverDocument field %d = %q, want %q", index, got, want)
		}
	}
}

func TestSessionRuntimeTemplateJSONIsExactDeterministicAndFresh(t *testing.T) {
	template := SessionRuntimeTemplate()
	want := []byte("{\"index_patterns\":[\"zasp-session-runtime-events-v1-*\"],\"priority\":100,\"version\":1,\"template\":{\"settings\":{\"index.mapping.total_fields.limit\":12},\"mappings\":{\"dynamic\":\"strict\",\"_meta\":{\"zasp_contract\":\"session_runtime_events\",\"zasp_contract_version\":1},\"properties\":{\"action\":{\"type\":\"keyword\",\"ignore_above\":64},\"agent_id\":{\"type\":\"keyword\",\"ignore_above\":40},\"decision\":{\"type\":\"keyword\",\"ignore_above\":16},\"environment_id\":{\"type\":\"keyword\",\"ignore_above\":40},\"event_class\":{\"type\":\"keyword\",\"ignore_above\":32},\"event_id\":{\"type\":\"keyword\",\"ignore_above\":40},\"event_time\":{\"type\":\"date\",\"format\":\"strict_date_time\"},\"organization_id\":{\"type\":\"keyword\",\"ignore_above\":40},\"session_id\":{\"type\":\"keyword\",\"ignore_above\":40},\"source\":{\"type\":\"keyword\",\"ignore_above\":32},\"source_event_id\":{\"type\":\"keyword\",\"ignore_above\":256},\"workspace_id\":{\"type\":\"keyword\",\"ignore_above\":40}}}}}\n")

	first, err := template.JSON()
	if err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}
	if !bytes.Equal(first, want) {
		t.Fatalf("JSON = %s\nwant = %s", first, want)
	}
	first[0] = '['
	second, err := template.JSON()
	if err != nil || !bytes.Equal(second, want) {
		t.Fatalf("second JSON = %s, %v", second, err)
	}

	fields := template.Fields()
	for index := range fields {
		fields[index] = Field{Name: "attacker", Type: "object", IgnoreAbove: index + 1, Format: "epoch_millis"}
	}
	if got := template.Fields(); !reflect.DeepEqual(got, expectedSessionRuntimeFields) {
		t.Fatalf("mutated retained fields: %#v", got)
	}
}

func TestSessionRuntimeTemplateRejectsForgedState(t *testing.T) {
	valid := SessionRuntimeTemplate()
	tests := map[string]Template{
		"zero":        {},
		"pattern":     mutateTemplate(valid, func(value *Template) { value.pattern = "events-*" }),
		"priority":    mutateTemplate(valid, func(value *Template) { value.priority = 101 }),
		"version":     mutateTemplate(valid, func(value *Template) { value.version = 2 }),
		"field order": mutateTemplate(valid, func(value *Template) { value.fields[0], value.fields[1] = value.fields[1], value.fields[0] }),
		"field name":  mutateTemplate(valid, func(value *Template) { value.fields[0].Name = "organization.name" }),
		"field type":  mutateTemplate(valid, func(value *Template) { value.fields[0].Type = "text" }),
		"field limit": mutateTemplate(valid, func(value *Template) { value.fields[0].IgnoreAbove = 41 }),
		"date format": mutateTemplate(valid, func(value *Template) { value.fields[11].Format = "date_optional_time" }),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); err != ErrTemplate {
				t.Fatalf("Validate error = %v, want ErrTemplate", err)
			}
			if candidate.Pattern() != "" || candidate.Priority() != 0 || candidate.Version() != 0 || candidate.Fields() != nil {
				t.Fatalf("invalid accessors returned state")
			}
			if output, err := candidate.JSON(); err != ErrTemplate || output != nil {
				t.Fatalf("JSON = %q, %v; want nil, ErrTemplate", output, err)
			}
			if err := candidate.ValidateDocumentFields(fieldNames(expectedSessionRuntimeFields)); err != ErrDocument {
				t.Fatalf("ValidateDocumentFields error = %v, want ErrDocument", err)
			}
		})
	}
	if ErrTemplate.Error() != "event index template rejected" {
		t.Fatalf("ErrTemplate text = %q", ErrTemplate)
	}
}

func TestSessionRuntimeTemplateValidatesExactDocumentFieldSet(t *testing.T) {
	template := SessionRuntimeTemplate()
	valid := fieldNames(expectedSessionRuntimeFields)
	reversed := slices.Clone(valid)
	slices.Reverse(reversed)
	for name, fields := range map[string][]string{
		"canonical": valid,
		"reversed":  reversed,
	} {
		t.Run(name, func(t *testing.T) {
			if err := template.ValidateDocumentFields(fields); err != nil {
				t.Fatalf("ValidateDocumentFields returned error: %v", err)
			}
		})
	}

	invalidUTF8 := string([]byte{0xff})
	tests := map[string][]string{
		"nil":          nil,
		"missing":      valid[:len(valid)-1],
		"duplicate":    append(slices.Clone(valid[:len(valid)-1]), valid[0]),
		"unknown":      replaceField(valid, 0, "attacker_field"),
		"nested":       replaceField(valid, 0, "organization_id.value"),
		"control":      replaceField(valid, 0, "organization_id\n"),
		"invalid utf8": replaceField(valid, 0, invalidUTF8),
		"oversized":    replaceField(valid, 0, string(bytes.Repeat([]byte{'a'}, 257))),
	}
	for name, fields := range tests {
		t.Run(name, func(t *testing.T) {
			if err := template.ValidateDocumentFields(fields); err != ErrDocument {
				t.Fatalf("ValidateDocumentFields error = %v, want ErrDocument", err)
			}
		})
	}
	if ErrDocument.Error() != "event index document rejected" {
		t.Fatalf("ErrDocument text = %q", ErrDocument)
	}
}

func TestSessionRuntimeTemplateRejectsMappingExplosion(t *testing.T) {
	fields := fieldNames(expectedSessionRuntimeFields)
	for index := range 1024 {
		fields = append(fields, fmt.Sprintf("attacker_%04d", index))
	}
	if err := SessionRuntimeTemplate().ValidateDocumentFields(fields); err != ErrDocument {
		t.Fatalf("ValidateDocumentFields error = %v, want ErrDocument", err)
	}
}

func TestSessionRuntimeTemplateIsConcurrent(t *testing.T) {
	template := SessionRuntimeTemplate()
	const workers = 64
	errorsByWorker := make(chan error, workers)
	for range workers {
		go func() {
			if err := template.Validate(); err != nil {
				errorsByWorker <- err
				return
			}
			if _, err := template.JSON(); err != nil {
				errorsByWorker <- err
				return
			}
			errorsByWorker <- template.ValidateDocumentFields(fieldNames(expectedSessionRuntimeFields))
		}()
	}
	for range workers {
		if err := <-errorsByWorker; err != nil {
			t.Fatal(err)
		}
	}
}

func mutateTemplate(source Template, mutate func(*Template)) Template {
	mutate(&source)
	return source
}

func fieldNames(fields []Field) []string {
	names := make([]string, len(fields))
	for index, field := range fields {
		names[index] = field.Name
	}
	return names
}

func replaceField(source []string, index int, replacement string) []string {
	result := slices.Clone(source)
	result[index] = replacement
	return result
}
