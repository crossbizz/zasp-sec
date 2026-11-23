package guardrail

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// ContainsInstructionOverride is the offline scanner's narrow projection of
// the same instruction, role and decoded-directive checks used in Detect.
func ContainsInstructionOverride(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	if overrideText(text) || roleMarkerPattern.MatchString(text) {
		return true
	}
	for _, loc := range base64Pattern.FindAllStringIndex(text, 32) {
		candidate := strings.TrimRight(text[loc[0]:loc[1]], "=")
		if len(candidate) > 4096 {
			continue
		}
		decoded, err := base64.RawStdEncoding.DecodeString(candidate)
		if err == nil && utf8.Valid(decoded) && (overrideText(string(decoded)) || roleMarkerPattern.Match(decoded)) {
			return true
		}
	}
	return false
}
