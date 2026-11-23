package aigateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const semanticSchemaVersion = "semantic.v1"

var semanticSchemas = buildSchemas()

func boundedString(n int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": n}
}
func enumeration(values ...string) map[string]any {
	return map[string]any{"type": "string", "enum": values}
}
func array(items any, limit int) map[string]any {
	return map[string]any{"type": "array", "items": items, "maxItems": limit, "uniqueItems": true}
}
func object(fields map[string]any) map[string]any {
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": fields, "required": names}
}

func buildSchemas() map[Purpose]*jsonschema.Schema {
	prob := map[string]any{"type": "number", "minimum": 0, "maximum": 1}
	refs := array(boundedString(128), 32)
	toolIDs := array(map[string]any{"type": "string", "pattern": "^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}, 64)
	score := map[string]any{"type": "number", "minimum": 0, "maximum": 100}
	defs := map[Purpose]map[string]any{
		PurposeInjectionScreen: {"malicious_probability": prob, "attack_family": boundedString(63), "confidence": prob},
		PurposeAlignment:       {"verdict": enumeration("aligned", "drift", "uncertain"), "violated_clause": enumeration("none", "purpose", "destination", "sequence", "data_access"), "confidence": prob},
		PurposeHeuristicVerify: {"verdict": enumeration("benign_context", "true_positive", "uncertain"), "confidence": prob, "reason_code": boundedString(63)},
		PurposeDiscoveryVerify: {"kind": enumeration("autonomous_agent", "simple_llm_app", "mcp_server", "skill_addon", "not_an_agent_fp"), "evidence_refs": refs},
		PurposeDraft:           {"allowed_tool_ids": toolIDs, "iam_mismatches": refs},
		PurposeAddonAudit:      {"threat_score": score, "risk_score": score, "tags": refs, "citations": refs},
		PurposeTriage:          {"summary": boundedString(2048), "evidence_ids": refs},
		PurposeRemediate:       {"steps": array(object(map[string]any{"action": boundedString(63), "target_id": boundedString(128), "rollback": boundedString(512)}), 6)},
	}
	result := make(map[Purpose]*jsonschema.Schema, len(defs))
	for p, fields := range defs {
		c := jsonschema.NewCompiler()
		raw, _ := json.Marshal(object(fields))
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			panic(err)
		}
		if err = c.AddResource("schema.json", doc); err != nil {
			panic(err)
		}
		result[p] = c.MustCompile("schema.json")
	}
	return result
}

// ValidateSemanticOutput checks the purpose's closed schema before a model
// response can reach a worker. Duplicate keys and trailing data are ambiguous.
func ValidateSemanticOutput(p Purpose, raw []byte) bool {
	schema := semanticSchemas[p]
	if schema == nil || len(raw) == 0 || len(raw) > 32*1024 {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if uniqueJSON(d, 0) != nil {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	return err == nil && schema.Validate(doc) == nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 12 {
		return ErrGeneration
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	kind, container := token.(json.Delim)
	if !container {
		return nil
	}
	keys := map[string]bool{}
	for d.More() {
		if kind == '{' {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || keys[name] {
				return errors.New("ambiguous model output")
			}
			keys[name] = true
		}
		if err := uniqueJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}
