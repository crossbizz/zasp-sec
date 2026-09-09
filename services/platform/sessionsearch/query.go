// Package sessionsearch builds a closed structured query for correlated runtime
// evidence. Search results are candidates, never authorization decisions.
package sessionsearch

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
)

var ErrQuery = errors.New("runtime session query rejected")

type Filters struct {
	AgentID, PrincipalID, Tool, Process, File, Domain, Credential, Resource, Decision, RawQuery string
	From, To                                                                                    time.Time
}

// BuildQuery matches all selectors on the same event in one exact tenant scope.
// It emits only fixed field names, literal terms and bounded composite buckets;
// callers cannot provide OpenSearch query syntax or change the grouping. After
// is a validated investigation ID from a separately authenticated API cursor.
func BuildQuery(scope domain.Scope, filters Filters, after string, limit int) ([]byte, error) {
	if scope.Validate() != nil || filters.RawQuery != "" || limit < 1 || limit > 101 || !validInvestigationID(after) {
		return nil, ErrQuery
	}
	for _, id := range []string{filters.AgentID, filters.PrincipalID, filters.Credential} {
		if id != "" {
			if _, err := domain.ParseProductID(id); err != nil {
				return nil, ErrQuery
			}
		}
	}
	if filters.Tool != "" && !validLiteral(filters.Tool, 256) || filters.Decision != "" && filters.Decision != "allow" && filters.Decision != "monitor" && filters.Decision != "block" {
		return nil, ErrQuery
	}
	for _, timestamp := range []time.Time{filters.From, filters.To} {
		if !timestamp.IsZero() && (timestamp.Location() != time.UTC || timestamp.Year() < 1 || timestamp.Year() > 9999) {
			return nil, ErrQuery
		}
	}
	if !filters.From.IsZero() && !filters.To.IsZero() && filters.From.After(filters.To) {
		return nil, ErrQuery
	}
	type object = map[string]any
	clauses := make([]object, 0, 14)
	term := func(field, value string) {
		if value != "" {
			clauses = append(clauses, object{"term": object{field: value}})
		}
	}
	term("record_type", "runtime_session_event")
	term("organization_id", scope.OrganizationID().String())
	term("workspace_id", scope.WorkspaceID().String())
	term("environment_id", scope.EnvironmentID().String())
	term("agent_id", filters.AgentID)
	term("observed_principal_id", filters.PrincipalID)
	term("tool_id", filters.Tool)
	for _, selector := range []struct{ field, value string }{{"process", filters.Process}, {"file", filters.File}, {"domain", filters.Domain}, {"resource", filters.Resource}} {
		if selector.value == "" {
			continue
		}
		digest, err := runtimemetadata.DigestSelector(selector.field, selector.value)
		if err != nil {
			return nil, ErrQuery
		}
		term(selector.field+"_digest", digest)
	}
	term("credential_id", filters.Credential)
	term("decision", filters.Decision)
	dateRange := object{}
	if !filters.From.IsZero() {
		// Archived runtime events and this index have millisecond precision.
		// Round the inclusive lower bound up, never down into excluded events.
		lower := filters.From.Truncate(time.Millisecond)
		if !lower.Equal(filters.From) {
			lower = lower.Add(time.Millisecond)
		}
		if lower.Year() > 9999 {
			return nil, ErrQuery
		}
		dateRange["gte"] = lower.Format("2006-01-02T15:04:05.000Z")
	}
	if !filters.To.IsZero() {
		dateRange["lte"] = filters.To.Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	}
	if len(dateRange) != 0 {
		clauses = append(clauses, object{"range": object{"event_time": dateRange}})
	}
	composite := object{"size": limit, "sources": []object{{"investigation_id": object{"terms": object{"field": "investigation_id", "order": "asc"}}}}}
	if after != "" {
		composite["after"] = object{"investigation_id": after}
	}
	return json.Marshal(object{"size": 0, "track_total_hits": false, "query": object{"bool": object{"filter": clauses}}, "aggs": object{"sessions": object{"composite": composite}}})
}

func validInvestigationID(value string) bool {
	if value == "" || value == "unattributed" {
		return true
	}
	_, err := domain.ParseProductID(value)
	return err == nil
}

func validLiteral(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
