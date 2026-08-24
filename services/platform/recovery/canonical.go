package recovery

import (
	"bytes"
	"encoding/json"
	"io"
)

func uniqueManifestJSON(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if !consumeUniqueManifestJSON(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func consumeUniqueManifestJSON(decoder *json.Decoder, depth int) bool {
	if depth > 16 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, keyOK := keyToken.(string)
			if keyErr != nil || !keyOK || len(key) == 0 || len(key) > 128 {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			if len(seen) > 128 || !consumeUniqueManifestJSON(decoder, depth+1) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim('}')
	case '[':
		count := 0
		for decoder.More() {
			count++
			if count > maximumManifestArtifacts || !consumeUniqueManifestJSON(decoder, depth+1) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim(']')
	default:
		return false
	}
}
