package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type stytchReadCredentials struct {
	ProjectID string `json:"project_id"`
	Secret    string `json:"secret"`
}
type selectedStytchSession struct {
	ID             string `json:"member_session_id"`
	MemberID       string `json:"member_id"`
	OrganizationID string `json:"organization_id"`
	StartedAt      string `json:"started_at"`
	LastAccessedAt string `json:"last_accessed_at"`
	ExpiresAt      string `json:"expires_at"`
}

func (r *Runner) observeStytch(ctx context.Context, report *Report, c *StytchConfig) {
	if c == nil {
		return
	}
	if ctx == nil || !validStytch(c) || r.http == nil {
		return
	}
	body, e := privateFile(c.CredentialFile, 16384)
	if e != nil {
		r.record(report, "stytch_project_reachable", false, "credentials_unavailable", "none", stytchTarget(r.config, c, false), false)
		return
	}
	defer clear(body)
	var credentials stytchReadCredentials
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	environment := "test"
	if c.Origin == "https://api.stytch.com" {
		environment = "live"
	}
	if !uniqueJSON(body) || d.Decode(&credentials) != nil || !validStytchID(credentials.ProjectID, "project", environment) || !validCredentialValue(credentials.Secret, 8, 4096) {
		r.record(report, "stytch_project_reachable", false, "credentials_unavailable", "none", stytchTarget(r.config, c, false), false)
		return
	}
	defer func() { credentials = stytchReadCredentials{} }()
	var organization struct {
		StatusCode   int `json:"status_code"`
		Organization struct {
			ID string `json:"organization_id"`
		} `json:"organization"`
	}
	outcome := r.stytchGET(ctx, c.Origin, "/v1/b2b/organizations/"+url.PathEscape(c.OrganizationID), "", credentials, &organization)
	if outcome == "" && (organization.StatusCode != 200 || organization.Organization.ID == "") {
		outcome = "malformed"
	}
	if outcome == "" && organization.Organization.ID != c.OrganizationID {
		outcome = "binding_mismatch"
	}
	target := stytchTarget(r.config, c, false)
	r.record(report, "stytch_project_reachable", outcome == "", "organization_read_unavailable", "operator", target, true)
	if outcome != "" {
		r.dependencyFailure(report, "stytch_project_reachable", "stytch:GetOrganization", target, outcome)
		return
	}
	dependencyCode(report, "stytch_project_reachable", "observed_selected_provider_organization")
	var response struct {
		StatusCode int                     `json:"status_code"`
		Sessions   []selectedStytchSession `json:"member_sessions"`
	}
	query := url.Values{"organization_id": []string{c.OrganizationID}, "member_id": []string{c.MemberID}}.Encode()
	outcome = r.stytchGET(ctx, c.Origin, "/v1/b2b/sessions", query, credentials, &response)
	if outcome == "" && (response.StatusCode != 200 || response.Sessions == nil || len(response.Sessions) > 128) {
		outcome = "malformed"
	}
	selected, seen := 0, map[string]bool{}
	now := time.Now().UTC()
	if outcome == "" {
		for _, session := range response.Sessions {
			if session.ID == "" || session.MemberID == "" || session.OrganizationID == "" || seen[session.ID] {
				outcome = "malformed"
				break
			}
			seen[session.ID] = true
			if !validStytchID(session.ID, "member-session", environment) || session.MemberID != c.MemberID || session.OrganizationID != c.OrganizationID {
				outcome = "binding_mismatch"
				break
			}
			started, se := time.Parse(time.RFC3339, session.StartedAt)
			last, le := time.Parse(time.RFC3339, session.LastAccessedAt)
			expires, ee := time.Parse(time.RFC3339, session.ExpiresAt)
			if se != nil || le != nil || ee != nil || !strings.HasSuffix(session.StartedAt, "Z") || !strings.HasSuffix(session.LastAccessedAt, "Z") || !strings.HasSuffix(session.ExpiresAt, "Z") {
				outcome = "malformed"
				break
			}
			if started.After(last) || last.After(now.Add(30*time.Second)) || !expires.After(now) || !expires.After(last) {
				outcome = "binding_mismatch"
				break
			}
			if session.ID == c.MemberSessionID {
				selected++
			}
		}
		if outcome == "" && selected != 1 {
			outcome = "binding_mismatch"
		}
	}
	target = stytchTarget(r.config, c, true)
	r.record(report, "stytch_session_reachable", outcome == "", "selected_session_read_unavailable", "operator", target, true)
	if outcome != "" {
		r.dependencyFailure(report, "stytch_session_reachable", "stytch:GetMemberSessions", target, outcome)
	} else {
		dependencyCode(report, "stytch_session_reachable", "observed_selected_provider_session")
	}
}
func stytchTarget(config Config, c *StytchConfig, session bool) any {
	if session {
		return struct {
			Scope        Scope  `json:"intended_scope"`
			Origin       string `json:"origin"`
			Organization string `json:"organization_id"`
			Member       string `json:"member_id"`
			Session      string `json:"member_session_id"`
		}{config.Scope, c.Origin, c.OrganizationID, c.MemberID, c.MemberSessionID}
	}
	return struct {
		Scope        Scope  `json:"intended_scope"`
		Origin       string `json:"origin"`
		Organization string `json:"organization_id"`
	}{config.Scope, c.Origin, c.OrganizationID}
}
func (r *Runner) stytchGET(ctx context.Context, origin, path, query string, credentials stytchReadCredentials, value any) string {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	target := origin + path
	if query != "" {
		target += "?" + query
	}
	req, e := http.NewRequestWithContext(bounded, http.MethodGet, target, nil)
	if e != nil {
		return "malformed"
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(credentials.ProjectID, credentials.Secret)
	response, e := r.http.Do(req)
	if e != nil || response == nil || response.Body == nil {
		return "unreachable"
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return "denied"
	}
	if response.StatusCode == 404 {
		return "binding_mismatch"
	}
	if response.StatusCode != 200 {
		return "unreachable"
	}
	content, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || content != "application/json" {
		return "malformed"
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	defer clear(raw)
	if e != nil || bounded.Err() != nil {
		return "unreachable"
	}
	if len(raw) > 65536 || !uniqueProviderJSON(raw) || !exactStytchAuthorityKeys(raw, path) || json.Unmarshal(raw, value) != nil {
		return "malformed"
	}
	return ""
}

// Provider optional fields may be null. Duplicate keys (including ignored
// fields), invalid nesting and trailing input still fail closed. Config uses
// the distinct stricter uniqueJSON predicate, which forbids null.
func uniqueProviderJSON(payload []byte) bool {
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	var read func(int) bool
	read = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, e := d.Token()
		if e != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				text, ok := key.(string)
				if e != nil || !ok || seen[text] {
					return false
				}
				seen[text] = true
				if !read(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !read(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		return false
	}
	if !read(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}

// Only exact documented binding keys can become authority. The typed decoder
// otherwise accepts casefold aliases. Unknown vendor fields, including nullable
// custom claims, remain ignored and cannot enter the interpreted binding.
func exactStytchAuthorityKeys(payload []byte, path string) bool {
	if strings.HasPrefix(path, "/v1/b2b/organizations/") {
		object, ok := providerAuthorityObject(payload, []string{"status_code", "organization"})
		if !ok {
			return false
		}
		_, ok = providerAuthorityObject(object["organization"], []string{"organization_id"})
		return ok
	}
	if path != "/v1/b2b/sessions" {
		return false
	}
	object, ok := providerAuthorityObject(payload, []string{"status_code", "member_sessions"})
	if !ok {
		return false
	}
	var sessions []json.RawMessage
	if json.Unmarshal(object["member_sessions"], &sessions) != nil || sessions == nil || len(sessions) > 128 {
		return false
	}
	for _, session := range sessions {
		if _, ok := providerAuthorityObject(session, []string{"member_session_id", "member_id", "organization_id", "started_at", "last_accessed_at", "expires_at"}); !ok {
			return false
		}
	}
	return true
}
func providerAuthorityObject(payload []byte, known []string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil || object == nil {
		return nil, false
	}
	for key := range object {
		for _, name := range known {
			if key != name && strings.EqualFold(key, name) {
				return nil, false
			}
		}
	}
	return object, true
}
