package apiserver

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const securityAgentRationaleCredentialName = `(?:password|passwd|(?:access[_-]|refresh[_-])?token|secret|api[_-]?key|(?:secret[_-])?access[_-]?key)`

var securityAgentRationaleURL = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s]+`)
var securityAgentRationaleQueryKey = regexp.MustCompile(`(?i)^` + securityAgentRationaleCredentialName + `$`)
var securityAgentRationaleCredential = regexp.MustCompile(`(?i)\b(?:` + securityAgentRationaleCredentialName + `["']?\s*[:=]\s*|(?:bearer|basic)\s+)`)
var securityAgentRationaleSensitive = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`),
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	regexp.MustCompile(`(?i)\b(?:ghp_|sk-)[a-z0-9_-]+\b`),
}

// sanitizeSecurityAgentRationale is the private receipt-to-public text boundary.
// It recognizes the documented credential formats, not every possible secret.
// Failure never returns partial text or the original provider output.
func sanitizeSecurityAgentRationale(value string) (string, bool) {
	if value == "" || len(value) > 500 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return "", false
		}
	}
	upper := strings.ToUpper(value)
	if strings.Contains(upper, "-----BEGIN") && strings.Contains(upper, "PRIVATE KEY") {
		return "", false
	}
	valid := true
	value = securityAgentRationaleURL.ReplaceAllStringFunc(value, func(raw string) string {
		// Do not validate only a prefix before a delimiter in malformed
		// userinfo, leaving the credential suffix outside the redaction span.
		if strings.ContainsAny(raw, "<>\"'") || strings.HasSuffix(raw, ":") {
			valid = false
			return ""
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			valid = false
			return ""
		}
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			valid = false
			return ""
		}
		if parsed.User != nil {
			return "[REDACTED]"
		}
		for key := range query {
			if securityAgentRationaleQueryKey.MatchString(key) {
				return "[REDACTED]"
			}
		}
		return raw
	})
	if !valid {
		return "", false
	}
	var output strings.Builder
	for {
		match := securityAgentRationaleCredential.FindStringIndex(value)
		if match == nil {
			output.WriteString(value)
			break
		}
		end, ok := securityAgentRationaleValueEnd(value[match[1]:])
		if !ok {
			return "", false
		}
		output.WriteString(value[:match[1]])
		output.WriteString("[REDACTED]")
		value = value[match[1]+end:]
	}
	value = output.String()
	for _, pattern := range securityAgentRationaleSensitive {
		value = pattern.ReplaceAllString(value, "[REDACTED]")
	}
	if len(value) > 500 {
		return "", false
	}
	return value, true
}

func securityAgentRationaleValueEnd(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	if strings.HasPrefix(value, "[REDACTED]") {
		end := len("[REDACTED]")
		return end, securityAgentRationaleValueBoundary(value, end)
	}
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		for index := 1; index < len(value); index++ {
			if value[index] == '\\' {
				index++
				continue
			}
			if value[index] == quote {
				if index == 1 {
					return 0, false
				}
				return index + 1, securityAgentRationaleValueBoundary(value, index+1)
			}
		}
		return 0, false
	}
	for index, character := range value {
		if unicode.IsSpace(character) || strings.ContainsRune(",;)}]", character) {
			return index, index > 0
		}
		if strings.ContainsRune("\\\"'[{", character) {
			return 0, false
		}
	}
	return len(value), true
}

func securityAgentRationaleValueBoundary(value string, end int) bool {
	if end == len(value) {
		return true
	}
	character, _ := utf8.DecodeRuneInString(value[end:])
	return unicode.IsSpace(character) || strings.ContainsRune(",;)}]", character)
}
