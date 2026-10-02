package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// A present risk annotation must be canonical and known. The empty Go value is
// reserved for omission, not an accepted null/empty annotation from a caller.
func (value *Policy) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return ErrRejected
	}
	seenRisk := false
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return ErrRejected
		}
		var field json.RawMessage
		if decoder.Decode(&field) != nil {
			return ErrRejected
		}
		if strings.EqualFold(name, "risk") {
			if name != "risk" || seenRisk {
				return ErrRejected
			}
			seenRisk = true
			var risk string
			if json.Unmarshal(field, &risk) != nil || risk == "" || !validOptionalRisk(risk) {
				return ErrRejected
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return ErrRejected
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrRejected
	}
	type plain Policy
	var decoded plain
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil {
		return ErrRejected
	}
	*value = Policy(decoded)
	return nil
}
