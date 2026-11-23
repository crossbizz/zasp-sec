package delegation

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// MCPOperation derives authority from an unambiguous JSON-RPC body. Metadata
// supplied by the caller cannot change the operation being authorized.
func MCPOperation(raw []byte) string {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !uniqueValue(d, 0) {
		return ""
	}
	if _, err := d.Token(); err != io.EOF {
		return ""
	}
	var message struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id"`
		Params  struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &message) != nil || message.JSONRPC != "2.0" {
		return ""
	}
	switch message.Method {
	case "tools/call":
		if len(message.ID) == 0 || string(message.ID) == "null" || !label.MatchString(message.Params.Name) || strings.HasPrefix(message.Params.Name, "mcp:") {
			return ""
		}
		return message.Params.Name
	case "initialize", "tools/list", "notifications/initialized", "ping":
		return "mcp:" + message.Method
	}
	return ""
}

func uniqueValue(d *json.Decoder, depth int) bool {
	if depth > 64 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	open, ok := token.(json.Delim)
	if !ok {
		return true
	}
	keys := map[string]bool{}
	for d.More() {
		if open == '{' {
			v, err := d.Token()
			key, ok := v.(string)
			key = strings.ToLower(key)
			if err != nil || !ok || keys[key] {
				return false
			}
			keys[key] = true
		}
		if !uniqueValue(d, depth+1) {
			return false
		}
	}
	_, err = d.Token()
	return err == nil
}
