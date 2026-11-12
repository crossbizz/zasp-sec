package baseline

import (
	"errors"
	"strings"
)

// Script returns the whole installation as an ordered list of single SQL
// statements. Executed in order inside ONE transaction on ONE session, as the
// operator, it performs exactly what Install performs, and its last statement
// raises an error (rolling the transaction back) unless the catalog sealed,
// is intact and passes the given readiness checks.
//
// It exists for transports that cannot carry a multi-statement script, such
// as an HTTPS SQL endpoint that accepts a batch of prepared statements. Use
// Install whenever a PostgreSQL connection is available: Install checks the
// preconditions and skips roles that already exist, which a static script
// cannot do. existingRoles names the product roles already present in the
// cluster; the caller reads them from pg_roles.
func Script(existingRoles []string, checks ...string) ([]string, error) {
	artifact, err := loadArtifact()
	if err != nil {
		return nil, err
	}
	steps, err := buildPlan(artifact)
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for _, role := range existingRoles {
		existing[role] = true
	}
	var script strings.Builder
	for _, line := range strings.Split(roleScript, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !roleStatement.MatchString(line) {
			return nil, errors.New("role script is malformed")
		}
		if match := createRole.FindStringSubmatch(line); match != nil && existing[match[1]] {
			continue
		}
		script.WriteString(line + "\n")
	}
	script.WriteString(steps.objects)
	script.WriteString("\nSELECT pg_catalog.set_config('zasp_baseline.owners', '" + strings.Join(steps.roles, ",") + "', true);\n")
	script.WriteString(grantScript + "\n" + strings.Join(steps.owners, "\n") + "\n" + revokeScript + "\n")
	script.WriteString("RESET search_path;\nRESET row_security;\nRESET check_function_bodies;\n")
	// seal() and the checks run as separate statements of the block: a STABLE
	// function reads with its caller's snapshot, so intact() would not see a
	// seal row written earlier in the same statement.
	conditions := []string{"zasp_baseline.intact()"}
	for _, check := range checks {
		if strings.ContainsAny(check, ";$") || strings.TrimSpace(check) == "" {
			return nil, errors.New("readiness check is malformed")
		}
		conditions = append(conditions, "("+check+")")
	}
	script.WriteString("DO $verify$ BEGIN PERFORM zasp_baseline.seal('" + Checksum() + "'); IF NOT COALESCE(" + strings.Join(conditions, " AND ") + ", false) THEN RAISE EXCEPTION 'baseline verification failed'; END IF; END $verify$;\n")
	return SplitStatements(script.String())
}

// SplitStatements splits a SQL script into statements at top-level
// semicolons. It understands quoted strings and identifiers, dollar-quoted
// bodies, and line and block comments, which is everything pg_dump emits.
// Statements are returned without their terminating semicolon; fragments that
// hold only whitespace and comments are dropped.
func SplitStatements(script string) ([]string, error) {
	var statements []string
	start, content := 0, false
	flush := func(end int) {
		if content {
			statements = append(statements, strings.TrimSpace(script[start:end]))
		}
		start, content = end+1, false
	}
	for i := 0; i < len(script); {
		c := script[i]
		switch {
		case c == '-' && i+1 < len(script) && script[i+1] == '-':
			for i < len(script) && script[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(script) && script[i+1] == '*':
			depth := 1
			i += 2
			for i < len(script) && depth > 0 {
				switch {
				case strings.HasPrefix(script[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(script[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			if depth != 0 {
				return nil, errors.New("unterminated block comment")
			}
		case c == '\'' || c == '"':
			// An E'...' string may escape a quote with a backslash.
			escapes := c == '\'' && i > 0 && (script[i-1] == 'E' || script[i-1] == 'e') && (i < 2 || !identifierByte(script[i-2]))
			content = true
			i++
			closed := false
			for i < len(script) {
				if escapes && script[i] == '\\' {
					i += 2
					continue
				}
				if script[i] == c {
					if i+1 < len(script) && script[i+1] == c {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, errors.New("unterminated quoted text")
			}
		case c == '$' && (i == 0 || !identifierByte(script[i-1])):
			end := i + 1
			for end < len(script) && identifierByte(script[end]) {
				end++
			}
			if end < len(script) && script[end] == '$' && (end == i+1 || !(script[i+1] >= '0' && script[i+1] <= '9')) {
				tag := script[i : end+1]
				close := strings.Index(script[end+1:], tag)
				if close < 0 {
					return nil, errors.New("unterminated dollar-quoted text")
				}
				content = true
				i = end + 1 + close + len(tag)
			} else {
				content = true
				i++
			}
		case c == ';':
			flush(i)
			i++
		default:
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				content = true
			}
			i++
		}
	}
	if content {
		statements = append(statements, strings.TrimSpace(script[start:]))
	}
	return statements, nil
}

func identifierByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}
