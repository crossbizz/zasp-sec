package apiserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type auditListFilters struct{ actorID, action, outcome, from, to string }
type auditListQuery struct {
	filters        auditListFilters
	limit          int
	cursor, digest string
}

var auditListActionPattern = regexp.MustCompile(`^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`)
var auditListTimePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`)

const auditListTimeLayout = "2006-01-02T15:04:05.000000Z"

func validAuditListAction(value string) bool {
	if len(value) < 1 || len(value) > 127 {
		return false
	}
	return auditListActionPattern.MatchString(value) || stringIn(value, "identity_provider.createSSOConnection", "identity_provider.deleteSSOConnection", "identity_provider.testSSOConnection", "identity_provider.createSCIMConnection", "identity_provider.deleteSCIMConnection")
}
func auditListTime(value string) (time.Time, bool) {
	if !auditListTimePattern.MatchString(value) {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, value)
	return at, err == nil && at.Year() >= 1 && at.Year() <= 9999 && at.Nanosecond()%1000 == 0
}
func auditListQueryText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func parseAuditListQuery(raw string, identity RequestIdentity) (auditListQuery, error) {
	var result auditListQuery
	if len(raw) > 2048 || !auditListQueryText(raw) {
		return result, ErrRepositoryOperation
	}
	if raw != "" {
		for _, part := range strings.Split(raw, "&") {
			if part == "" || !strings.Contains(part, "=") {
				return result, ErrRepositoryOperation
			}
		}
	}
	query, ok := exactWorkflowQuery(raw, map[string]int{"cursor": 512, "limit": 3, "actor_id": 40, "action": 127, "outcome": 9, "from": 27, "to": 27})
	if !ok {
		return result, ErrRepositoryOperation
	}
	for key, values := range query {
		if !auditListQueryText(key) || !auditListQueryText(values[0]) || values[0] == "" {
			return result, ErrRepositoryOperation
		}
	}
	result.limit, ok = workflowPageLimit(query)
	if !ok {
		return result, ErrRepositoryOperation
	}
	result.filters = auditListFilters{query.Get("actor_id"), query.Get("action"), query.Get("outcome"), query.Get("from"), query.Get("to")}
	if result.filters.actorID != "" && !validProductID(result.filters.actorID) || result.filters.action != "" && !validAuditListAction(result.filters.action) || result.filters.outcome != "" && !stringIn(result.filters.outcome, "succeeded", "denied", "failed") {
		return auditListQuery{}, ErrRepositoryOperation
	}
	for _, field := range []*string{&result.filters.from, &result.filters.to} {
		if *field != "" {
			at, ok := auditListTime(*field)
			if !ok {
				return auditListQuery{}, ErrRepositoryOperation
			}
			*field = at.UTC().Format(auditListTimeLayout)
		}
	}
	if result.filters.from != "" && result.filters.to != "" && result.filters.from >= result.filters.to {
		return auditListQuery{}, ErrRepositoryOperation
	}
	normalized := result.filters.values()
	normalized.Set("limit", strconv.Itoa(result.limit))
	digest := sha256.Sum256([]byte("audit-list-filters.v1\x00" + identity.PrincipalID.String() + "\x00" + normalized.Encode()))
	result.digest = base64.RawURLEncoding.EncodeToString(digest[:])
	result.cursor = query.Get("cursor")
	return result, nil
}
func (filters auditListFilters) values() url.Values {
	result := url.Values{}
	for key, value := range map[string]string{"actor_id": filters.actorID, "action": filters.action, "outcome": filters.outcome, "from": filters.from, "to": filters.to} {
		if value != "" {
			result.Set(key, value)
		}
	}
	return result
}
func (filters auditListFilters) bytes() []byte {
	values := map[string]string{}
	for key, value := range filters.values() {
		values[key] = value[0]
	}
	body, _ := json.Marshal(values)
	return body
}
