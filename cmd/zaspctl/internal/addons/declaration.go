package addons

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Declaration describes structure only. It carries no executable content or
// bundle digest. A partial component cannot identify or approve a version.
type Declaration struct {
	ComponentKeys   []string `json:"component_keys,omitempty"`
	HandlerCount    int      `json:"handler_count,omitempty"`
	CommandHandlers int      `json:"command_handlers,omitempty"`
	DeclaresTools   bool     `json:"declares_tools,omitempty"`
}

var markdownName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.md$`)

// InspectDeclaration accepts one fixed class in a caller-pinned profile directory.
// It never resolves references found inside the inspected declaration.
func InspectDeclaration(root *os.Root, kind, name string) (*Declaration, string) {
	allowed := false
	switch kind {
	case "plugin":
		allowed = name == "plugin.json"
	case "hook":
		allowed = name == "hooks.json" || name == "settings.json" || name == "settings.local.json" || name == "managed-settings.json"
	case "subagent", "command":
		allowed = markdownName.MatchString(name) && portableName(name)
	}
	if !allowed {
		return nil, "unsupported_declaration_name"
	}
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "missing"
	}
	if err != nil {
		return nil, "unreadable"
	}
	if IsLink(info) || !info.Mode().IsRegular() {
		return nil, "unsupported_entry"
	}
	if info.Size() > 256<<10 {
		return nil, "file_size_limit"
	}
	data, why := readPinnedFile(root, name, info)
	if why != "" {
		return nil, why
	}
	if !utf8.Valid(data) {
		return nil, "invalid_text"
	}
	if kind == "command" || kind == "subagent" {
		return markdownDeclaration(kind, data)
	}
	var obj map[string]json.RawMessage
	if err = json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, "invalid_declaration"
	}
	if kind == "plugin" {
		var name string
		if json.Unmarshal(obj["name"], &name) != nil || strings.TrimSpace(name) == "" {
			return nil, "invalid_plugin_name"
		}
		d := &Declaration{}
		for _, key := range []string{"agents", "commands", "dependencies", "hooks", "lspServers", "mcpServers", "skills"} {
			if _, ok := obj[key]; ok {
				d.ComponentKeys = append(d.ComponentKeys, key)
			}
		}
		return d, ""
	}
	raw, ok := obj["hooks"]
	if !ok {
		return nil, ""
	}
	var events map[string][]struct {
		Hooks []struct {
			Type string `json:"type"`
		} `json:"hooks"`
	}
	if json.Unmarshal(raw, &events) != nil || events == nil {
		return nil, "invalid_hook_declaration"
	}
	d := &Declaration{}
	for _, groups := range events {
		for _, group := range groups {
			if len(group.Hooks) == 0 {
				return nil, "invalid_hook_declaration"
			}
			for _, handler := range group.Hooks {
				if handler.Type == "" {
					return nil, "invalid_hook_declaration"
				}
				d.HandlerCount++
				if handler.Type == "command" {
					d.CommandHandlers++
				}
			}
		}
	}
	if d.HandlerCount == 0 {
		return nil, ""
	}
	return d, ""
}

func markdownDeclaration(kind string, data []byte) (*Declaration, string) {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	header, body, ok := bytes.Cut(data, []byte("\n"))
	var fields yaml.Node
	if !ok || string(header) != "---" {
		if kind == "command" && len(bytes.TrimSpace(data)) > 0 {
			return &Declaration{}, ""
		}
		return nil, "missing_frontmatter"
	}
	lines := bytes.Split(body, []byte("\n"))
	end := slices.IndexFunc(lines, func(line []byte) bool { return string(line) == "---" })
	if end < 0 || end > 256 || yaml.Unmarshal(bytes.Join(lines[:end], []byte("\n")), &fields) != nil || len(fields.Content) != 1 || fields.Content[0].Kind != yaml.MappingNode {
		return nil, "invalid_frontmatter"
	}
	mapping := fields.Content[0].Content
	seen := map[string]bool{}
	hasName, hasDescription := false, false
	d := &Declaration{}
	for i := 0; i < len(mapping); i += 2 {
		key, value := mapping[i], mapping[i+1]
		if key.Kind != yaml.ScalarNode || seen[key.Value] || key.Value == "<<" {
			return nil, "invalid_frontmatter"
		}
		seen[key.Value] = true
		present := value.Kind == yaml.ScalarNode && value.Tag == "!!str" && strings.TrimSpace(value.Value) != ""
		switch key.Value {
		case "name":
			hasName = present
		case "description":
			hasDescription = present
		case "tools", "allowed-tools":
			d.DeclaresTools = true
		}
	}
	if kind == "subagent" && (!hasName || !hasDescription) {
		return nil, "missing_subagent_metadata"
	}
	return d, ""
}
