package eventindex

import (
	"encoding/json"
	"errors"
	"unicode/utf8"
)

const (
	sessionRuntimePattern  = "zasp-session-runtime-events-v1-*"
	sessionRuntimePriority = 100
	sessionRuntimeVersion  = 1
	maximumFieldNameBytes  = 256
)

var (
	ErrTemplate = errors.New("event index template rejected")
	ErrDocument = errors.New("event index document rejected")
)

type Field struct {
	Name        string
	Type        string
	IgnoreAbove int
	Format      string
}

type Template struct {
	pattern  string
	priority int
	version  int
	fields   [12]Field
}

func SessionRuntimeTemplate() Template {
	return Template{
		pattern:  sessionRuntimePattern,
		priority: sessionRuntimePriority,
		version:  sessionRuntimeVersion,
		fields:   canonicalSessionRuntimeFields(),
	}
}

func (template Template) Validate() error {
	if template.pattern != sessionRuntimePattern ||
		template.priority != sessionRuntimePriority ||
		template.version != sessionRuntimeVersion ||
		template.fields != canonicalSessionRuntimeFields() {
		return ErrTemplate
	}
	return nil
}

func canonicalSessionRuntimeFields() [12]Field {
	return [12]Field{
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
}

func (template Template) Pattern() string {
	if template.Validate() != nil {
		return ""
	}
	return template.pattern
}

func (template Template) Priority() int {
	if template.Validate() != nil {
		return 0
	}
	return template.priority
}

func (template Template) Version() int {
	if template.Validate() != nil {
		return 0
	}
	return template.version
}

func (template Template) Fields() []Field {
	if template.Validate() != nil {
		return nil
	}
	return append([]Field(nil), template.fields[:]...)
}

func (template Template) JSON() ([]byte, error) {
	if template.Validate() != nil {
		return nil, ErrTemplate
	}
	properties := make(map[string]jsonField, len(template.fields))
	for _, field := range template.fields {
		properties[field.Name] = jsonField{
			Type:        field.Type,
			IgnoreAbove: field.IgnoreAbove,
			Format:      field.Format,
		}
	}
	payload := jsonTemplateDocument{
		IndexPatterns: []string{template.pattern},
		Priority:      template.priority,
		Version:       template.version,
		Template: jsonTemplate{
			Settings: map[string]int{"index.mapping.total_fields.limit": len(template.fields)},
			Mappings: jsonMappings{
				Dynamic: "strict",
				Metadata: jsonMetadata{
					Contract:        "session_runtime_events",
					ContractVersion: template.version,
				},
				Properties: properties,
			},
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrTemplate
	}
	return append(encoded, '\n'), nil
}

func (template Template) ValidateDocumentFields(fields []string) error {
	if template.Validate() != nil || len(fields) != len(template.fields) {
		return ErrDocument
	}
	allowed := make(map[string]struct{}, len(template.fields))
	for _, field := range template.fields {
		allowed[field.Name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if field == "" || len(field) > maximumFieldNameBytes || !utf8.ValidString(field) {
			return ErrDocument
		}
		if _, ok := allowed[field]; !ok {
			return ErrDocument
		}
		if _, duplicate := seen[field]; duplicate {
			return ErrDocument
		}
		seen[field] = struct{}{}
	}
	return nil
}

type jsonTemplateDocument struct {
	IndexPatterns []string     `json:"index_patterns"`
	Priority      int          `json:"priority"`
	Version       int          `json:"version"`
	Template      jsonTemplate `json:"template"`
}

type jsonTemplate struct {
	Settings map[string]int `json:"settings"`
	Mappings jsonMappings   `json:"mappings"`
}

type jsonMappings struct {
	Dynamic    string               `json:"dynamic"`
	Metadata   jsonMetadata         `json:"_meta"`
	Properties map[string]jsonField `json:"properties"`
}

type jsonMetadata struct {
	Contract        string `json:"zasp_contract"`
	ContractVersion int    `json:"zasp_contract_version"`
}

type jsonField struct {
	Type        string `json:"type"`
	IgnoreAbove int    `json:"ignore_above,omitempty"`
	Format      string `json:"format,omitempty"`
}
