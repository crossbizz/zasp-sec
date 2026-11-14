package apiserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// The evidence pack of one agent, for an auditor: how the agent was found,
// its findings with their framework references, the Security Agent runs on
// those findings with their approvals, and the red team definitions and runs
// that target it, as one JSON document and a Markdown rendering of it.
//
// The pack is composed from the product's own read operations. Each part is
// read through the router as a request of its own, with the caller's
// credential: it is authenticated, authorized against the caller's current
// permissions and shaped exactly as when the caller asks for it directly, so
// the pack holds nothing the caller could not read one request at a time. A
// part the caller may not read is marked not_permitted instead of failing the
// pack, and a part that reaches its bound is marked truncated, so a reader
// knows what the document does not hold.
//
// It is a synchronous read: nothing is stored, so there is no retention to
// apply and no download grant. The export jobs (compliance and Security
// Agent evidence exports) are not available on the current catalog; a pack
// retained and signed by that machinery needs those jobs moved first.

const (
	agentEvidencePackSchema         = "agent-evidence-pack-v1"
	agentEvidencePackFindingPages   = 30
	agentEvidencePackFindings       = 200
	agentEvidencePackRunFindings    = 50
	agentEvidencePackRuns           = 50
	agentEvidencePackTestPages      = 10
	agentEvidencePackTestRuns       = 200
	agentEvidencePackPartBytes      = 4 << 20
	agentEvidencePackDocumentBytes  = 8 << 20
	evidencePackComplete            = "complete"
	evidencePackTruncated           = "truncated"
	evidencePackNotPermitted        = "not_permitted"
	evidencePackUnavailable         = "unavailable"
	evidencePackCredentialUnsuited  = "browser_session_required"
	agentEvidencePackMarkdownFormat = "markdown"
)

// AgentEvidencePackSection is one part of a pack. Status says whether Items
// is everything (complete), stops at a bound (truncated), or is empty
// because the caller may not read the part (not_permitted), the part needs a
// browser session (browser_session_required) or it could not be read
// (unavailable).
type AgentEvidencePackSection struct {
	Status string            `json:"status"`
	Items  []json.RawMessage `json:"items"`
}

type AgentEvidencePack struct {
	SchemaVersion  string          `json:"schema_version"`
	GeneratedAt    string          `json:"generated_at"`
	OrganizationID string          `json:"organization_id"`
	WorkspaceID    string          `json:"workspace_id"`
	EnvironmentID  string          `json:"environment_id"`
	Agent          json.RawMessage `json:"agent"`
	// Findings are the findings on the agent, each with its framework
	// references. SecurityAgentRuns are the runs related to those findings:
	// {"finding_ids": [...], "run": the run detail with plan, approvals,
	// execution and verification}. RedTeamTests are the red team definitions
	// whose target is the agent and RedTeamRuns their runs.
	Findings          AgentEvidencePackSection `json:"findings"`
	SecurityAgentRuns AgentEvidencePackSection `json:"security_agent_runs"`
	RedTeamTests      AgentEvidencePackSection `json:"red_team_tests"`
	RedTeamRuns       AgentEvidencePackSection `json:"red_team_runs"`
}

// productRouterContextKey carries the composed product router to the
// evidence pack handler, which the router mounts.
type productRouterContextKey struct{}

type agentEvidencePackHandler struct {
	now func() time.Time
}

type evidencePackWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	over   bool
}

func (writer *evidencePackWriter) Header() http.Header { return writer.header }
func (writer *evidencePackWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
}
func (writer *evidencePackWriter) Write(payload []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	if writer.body.Len()+len(payload) > agentEvidencePackPartBytes {
		writer.over = true
		return len(payload), nil
	}
	return writer.body.Write(payload)
}

// read performs one product read as the caller. The caller's credential and
// scope headers are the request's own; nothing else is carried over.
func (handler *agentEvidencePackHandler) read(parent *http.Request, path string, query url.Values) (int, []byte) {
	router, _ := parent.Context().Value(productRouterContextKey{}).(http.Handler)
	if nilInterface(router) {
		return http.StatusInternalServerError, nil
	}
	target := path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(parent.Context(), http.MethodGet, target, nil)
	if err != nil {
		return http.StatusInternalServerError, nil
	}
	for _, name := range []string{"Cookie", "Authorization", expectedScopeHeader} {
		for _, value := range parent.Header.Values(name) {
			request.Header.Add(name, value)
		}
	}
	request.RemoteAddr = parent.RemoteAddr
	writer := &evidencePackWriter{header: http.Header{}}
	router.ServeHTTP(writer, request)
	if writer.over {
		return http.StatusInternalServerError, nil
	}
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.status, writer.body.Bytes()
}

func evidencePackFailure(status int) string {
	switch status {
	case http.StatusForbidden, http.StatusNotFound:
		return evidencePackNotPermitted
	case http.StatusUnauthorized:
		return evidencePackCredentialUnsuited
	}
	return evidencePackUnavailable
}

// evidencePackPage decodes one page of a list operation. The product has two
// page shapes: page_info {next_cursor, has_more}, and a top-level next_cursor.
func evidencePackPage(payload []byte) ([]json.RawMessage, string, bool) {
	var page struct {
		Items    []json.RawMessage `json:"items"`
		PageInfo *struct {
			NextCursor *string `json:"next_cursor"`
			HasMore    bool    `json:"has_more"`
		} `json:"page_info"`
		NextCursor *string `json:"next_cursor"`
	}
	if json.Unmarshal(payload, &page) != nil || page.Items == nil {
		return nil, "", false
	}
	next := ""
	if page.PageInfo != nil && page.PageInfo.HasMore && page.PageInfo.NextCursor != nil {
		next = *page.PageInfo.NextCursor
	} else if page.PageInfo == nil && page.NextCursor != nil {
		next = *page.NextCursor
	}
	return page.Items, next, true
}

// list reads a list operation page by page and keeps the items keep accepts,
// up to the given bounds.
func (handler *agentEvidencePackHandler) list(parent *http.Request, path string, pages, maximum int, keep func(json.RawMessage) bool) AgentEvidencePackSection {
	section := AgentEvidencePackSection{Status: evidencePackComplete, Items: []json.RawMessage{}}
	cursor := ""
	for page := 0; ; page++ {
		if page == pages {
			section.Status = evidencePackTruncated
			return section
		}
		query := url.Values{"limit": {"100"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		status, payload := handler.read(parent, path, query)
		if status != http.StatusOK {
			return AgentEvidencePackSection{Status: evidencePackFailure(status), Items: []json.RawMessage{}}
		}
		items, next, ok := evidencePackPage(payload)
		if !ok {
			return AgentEvidencePackSection{Status: evidencePackUnavailable, Items: []json.RawMessage{}}
		}
		for _, item := range items {
			if !keep(item) {
				continue
			}
			if len(section.Items) == maximum {
				section.Status = evidencePackTruncated
				return section
			}
			section.Items = append(section.Items, item)
		}
		if next == "" {
			return section
		}
		cursor = next
	}
}

func evidencePackString(item json.RawMessage, key string) string {
	var fields map[string]json.RawMessage
	var value string
	if json.Unmarshal(item, &fields) != nil || json.Unmarshal(fields[key], &value) != nil {
		return ""
	}
	return value
}

func (handler *agentEvidencePackHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	route, routed := RoutedOperationFromRequest(request)
	agentID := route.PathParameters["id"]
	if handler == nil || !ok || !routed || route.OperationID != "getAgentEvidencePack" || request.Method != http.MethodGet || !validProductID(agentID) {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	query, valid := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"format": 8})
	format := query.Get("format")
	if !valid || !stringIn(format, "", "json", agentEvidencePackMarkdownFormat) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	// The agent itself: without it there is no pack.
	status, agent := handler.read(request, "/api/v1/agents/"+agentID, nil)
	switch {
	case status == http.StatusNotFound:
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	case status == http.StatusForbidden:
		writeProductionStatusError(writer, request, http.StatusForbidden, "request_forbidden", "Request forbidden", false)
		return
	case status != http.StatusOK || !json.Valid(agent):
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	now := time.Now
	if handler.now != nil {
		now = handler.now
	}
	pack := AgentEvidencePack{
		SchemaVersion: agentEvidencePackSchema, GeneratedAt: now().UTC().Format(time.RFC3339),
		OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(),
		Agent: json.RawMessage(agent),
	}
	pack.Findings = handler.list(request, "/api/v1/findings", agentEvidencePackFindingPages, agentEvidencePackFindings, func(item json.RawMessage) bool {
		return evidencePackString(item, "agent_id") == agentID
	})
	pack.SecurityAgentRuns = handler.securityAgentRuns(request, pack.Findings)
	pack.RedTeamTests = handler.list(request, "/api/v1/tests", agentEvidencePackTestPages, agentEvidencePackTestRuns, func(item json.RawMessage) bool {
		return evidencePackString(item, "target_id") == agentID
	})
	pack.RedTeamRuns = AgentEvidencePackSection{Status: pack.RedTeamTests.Status, Items: []json.RawMessage{}}
	if len(pack.RedTeamTests.Items) > 0 {
		definitions := map[string]bool{}
		for _, item := range pack.RedTeamTests.Items {
			definitions[evidencePackString(item, "id")] = true
		}
		pack.RedTeamRuns = handler.list(request, "/api/v1/test-runs", agentEvidencePackTestPages, agentEvidencePackTestRuns, func(item json.RawMessage) bool {
			return definitions[evidencePackString(item, "definition_id")]
		})
		if pack.RedTeamRuns.Status == evidencePackComplete && pack.RedTeamTests.Status == evidencePackTruncated {
			pack.RedTeamRuns.Status = evidencePackTruncated
		}
	}
	if request.Context().Err() != nil {
		writeProductionError(writer, request, request.Context().Err())
		return
	}
	markdown := renderAgentEvidencePack(pack)
	if format == agentEvidencePackMarkdownFormat {
		writer.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		writer.Header().Set("Content-Disposition", `attachment; filename="agent-evidence-`+agentID+`.md"`)
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(markdown))
		return
	}
	payload, err := json.Marshal(struct {
		Pack     AgentEvidencePack `json:"pack"`
		Markdown string            `json:"markdown"`
	}{pack, markdown})
	if err == nil && len(payload) > agentEvidencePackDocumentBytes {
		err = ErrRepositoryUnavailable
	}
	writeProductionResponse(writer, request, http.StatusOK, payload, err)
}

// securityAgentRuns reads the Security Agent runs related to the findings of
// the pack and each run's detail (plan, approvals, execution, verification).
// A run related to several findings is listed once, with all of them.
func (handler *agentEvidencePackHandler) securityAgentRuns(request *http.Request, findings AgentEvidencePackSection) AgentEvidencePackSection {
	section := AgentEvidencePackSection{Status: evidencePackComplete, Items: []json.RawMessage{}}
	if findings.Status != evidencePackComplete && findings.Status != evidencePackTruncated {
		// Without the findings their runs cannot be named.
		return AgentEvidencePackSection{Status: findings.Status, Items: []json.RawMessage{}}
	}
	if findings.Status == evidencePackTruncated || len(findings.Items) > agentEvidencePackRunFindings {
		section.Status = evidencePackTruncated
	}
	related := map[string][]string{}
	order := []string{}
	for index, finding := range findings.Items {
		if index == agentEvidencePackRunFindings {
			break
		}
		findingID := evidencePackString(finding, "id")
		if !validProductID(findingID) {
			return AgentEvidencePackSection{Status: evidencePackUnavailable, Items: []json.RawMessage{}}
		}
		runs := handler.list(request, "/api/v1/security-agent-activity/finding/"+findingID+"/runs", 3, 300, func(json.RawMessage) bool { return true })
		if runs.Status != evidencePackComplete && runs.Status != evidencePackTruncated {
			return AgentEvidencePackSection{Status: runs.Status, Items: []json.RawMessage{}}
		}
		if runs.Status == evidencePackTruncated {
			section.Status = evidencePackTruncated
		}
		for _, run := range runs.Items {
			runID := evidencePackString(run, "id")
			if !validProductID(runID) {
				return AgentEvidencePackSection{Status: evidencePackUnavailable, Items: []json.RawMessage{}}
			}
			if _, seen := related[runID]; !seen {
				order = append(order, runID)
			}
			if !slices.Contains(related[runID], findingID) {
				related[runID] = append(related[runID], findingID)
			}
		}
	}
	for index, runID := range order {
		if index == agentEvidencePackRuns {
			section.Status = evidencePackTruncated
			break
		}
		status, detail := handler.read(request, "/api/v1/security-agent-runs/"+runID, nil)
		if status != http.StatusOK || !json.Valid(detail) {
			return AgentEvidencePackSection{Status: evidencePackFailure(status), Items: []json.RawMessage{}}
		}
		item, err := json.Marshal(struct {
			FindingIDs []string        `json:"finding_ids"`
			Run        json.RawMessage `json:"run"`
		}{related[runID], detail})
		if err != nil {
			return AgentEvidencePackSection{Status: evidencePackUnavailable, Items: []json.RawMessage{}}
		}
		section.Items = append(section.Items, item)
	}
	return section
}

// markdownText keeps provider-supplied text on one line and out of the
// document's own structure.
func markdownText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "`", "'", "<", "&lt;", ">", "&gt;", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "#", `\#`).Replace(strings.TrimSpace(value))
}

var evidencePackStatusText = map[string]string{
	evidencePackComplete:           "",
	evidencePackTruncated:          "This section reached its bound and is not complete.",
	evidencePackNotPermitted:       "Not included: the requester may not read this section.",
	evidencePackCredentialUnsuited: "Not included: this section is read with a browser session, not an API token.",
	evidencePackUnavailable:        "Not included: this section could not be read when the pack was generated.",
}

// renderAgentEvidencePack renders the pack as Markdown. It reads only the
// members it prints and prints nothing it cannot decode.
func renderAgentEvidencePack(pack AgentEvidencePack) string {
	var text strings.Builder
	line := func(format string, values ...any) { fmt.Fprintf(&text, format+"\n", values...) }
	section := func(title string, part AgentEvidencePackSection) bool {
		line("\n## %s\n", title)
		if note := evidencePackStatusText[part.Status]; note != "" {
			line("%s\n", note)
		}
		if part.Status != evidencePackComplete && part.Status != evidencePackTruncated {
			return false
		}
		if len(part.Items) == 0 {
			line("None recorded.")
			return false
		}
		return true
	}
	var agent struct {
		Summary struct {
			ID              string  `json:"id"`
			Name            string  `json:"name"`
			Owner           string  `json:"owner"`
			Team            string  `json:"team"`
			Provider        string  `json:"provider"`
			SourceKind      string  `json:"source_kind"`
			ManagementState string  `json:"management_state"`
			ActivityState   string  `json:"activity_state"`
			LastActivityAt  *string `json:"last_activity_at"`
			FirstSeen       string  `json:"first_seen"`
			LastSeen        string  `json:"last_seen"`
			ObservedAt      string  `json:"observed_at"`
			Discovery       struct {
				Method   string   `json:"method"`
				Platform string   `json:"platform"`
				Signals  []string `json:"signals"`
			} `json:"discovery"`
		} `json:"summary"`
		Sources []struct {
			IntegrationID string `json:"integration_id"`
			Provider      string `json:"provider"`
			Source        string `json:"source"`
			SnapshotID    string `json:"snapshot_id"`
			EvidenceID    string `json:"evidence_id"`
			ObservedAt    string `json:"observed_at"`
			Winning       bool   `json:"winning"`
		} `json:"sources"`
		Evidence []struct {
			ID          string `json:"id"`
			Checksum    string `json:"checksum"`
			CollectedAt string `json:"collected_at"`
		} `json:"evidence"`
	}
	_ = json.Unmarshal(pack.Agent, &agent)
	summary := agent.Summary
	line("# Agent evidence pack: %s", markdownText(summary.Name))
	line("")
	line("- Agent: `%s`", summary.ID)
	line("- Generated: %s", pack.GeneratedAt)
	line("- Organization `%s`, Workspace `%s`, Environment `%s`", pack.OrganizationID, pack.WorkspaceID, pack.EnvironmentID)
	line("- Format: %s", pack.SchemaVersion)
	line("")
	line("This document holds what the requester could read when it was generated. A framework reference says a finding is relevant to a control; it does not say the control is met or failed.")
	line("\n## Discovery evidence\n")
	owner := "unowned"
	if summary.Owner != "" {
		owner = markdownText(summary.Owner)
		if summary.Team != "" {
			owner += " (" + markdownText(summary.Team) + ")"
		}
	}
	line("- Found by: %s, provider %s, kind %s, platform %s", markdownText(summary.Discovery.Method), markdownText(summary.Provider), markdownText(summary.SourceKind), markdownText(summary.Discovery.Platform))
	line("- Owner: %s; management state: %s", owner, markdownText(summary.ManagementState))
	line("- First seen %s, last seen %s, last observed %s", markdownText(summary.FirstSeen), markdownText(summary.LastSeen), markdownText(summary.ObservedAt))
	activity := markdownText(summary.ActivityState)
	if summary.LastActivityAt != nil {
		activity += ", last activity " + markdownText(*summary.LastActivityAt)
	}
	line("- Activity: %s", activity)
	if len(summary.Discovery.Signals) == 0 {
		line("- Signals: none (the provider's own record names the agent, or its owner declared it)")
	} else {
		line("- Signals:")
		for _, signal := range summary.Discovery.Signals {
			line("  - `%s`", markdownText(signal))
		}
	}
	if len(agent.Sources) > 0 {
		line("\n| Source | Provider | Integration | Snapshot | Evidence | Observed | Winning |")
		line("| --- | --- | --- | --- | --- | --- | --- |")
		for _, source := range agent.Sources {
			winning := "no"
			if source.Winning {
				winning = "yes"
			}
			line("| %s | %s | `%s` | `%s` | `%s` | %s | %s |", markdownText(source.Source), markdownText(source.Provider), source.IntegrationID, source.SnapshotID, source.EvidenceID, markdownText(source.ObservedAt), winning)
		}
	}
	if len(agent.Evidence) > 0 {
		line("\n| Evidence record | Checksum | Collected |")
		line("| --- | --- | --- |")
		for _, evidence := range agent.Evidence {
			line("| `%s` | `%s` | %s |", evidence.ID, markdownText(evidence.Checksum), markdownText(evidence.CollectedAt))
		}
	}
	if section("Findings", pack.Findings) {
		for _, raw := range pack.Findings.Items {
			var finding struct {
				ID         string `json:"id"`
				Rule       string `json:"rule"`
				Title      string `json:"title"`
				Severity   string `json:"severity"`
				Status     string `json:"status"`
				UpdatedAt  string `json:"updated_at"`
				Frameworks []struct {
					Framework string `json:"framework"`
					Control   string `json:"control"`
					Title     string `json:"title"`
				} `json:"frameworks"`
			}
			if json.Unmarshal(raw, &finding) != nil {
				continue
			}
			line("### %s\n", markdownText(finding.Title))
			line("- Finding `%s`, rule `%s`, severity %s, status %s, updated %s", finding.ID, markdownText(finding.Rule), markdownText(finding.Severity), markdownText(finding.Status), markdownText(finding.UpdatedAt))
			if len(finding.Frameworks) == 0 {
				line("- Framework references: none")
			} else {
				line("- Framework references:")
				for _, reference := range finding.Frameworks {
					line("  - %s %s: %s", markdownText(reference.Framework), markdownText(reference.Control), markdownText(reference.Title))
				}
			}
			line("")
		}
	}
	if section("Security Agent actions and approvals", pack.SecurityAgentRuns) {
		for _, raw := range pack.SecurityAgentRuns.Items {
			var item struct {
				FindingIDs []string `json:"finding_ids"`
				Run        struct {
					Run struct {
						ID      string `json:"id"`
						AgentID string `json:"agent_id"`
						State   string `json:"state"`
					} `json:"run"`
					Plan struct {
						Steps []struct {
							Index         int    `json:"index"`
							Action        string `json:"action"`
							Authorization string `json:"authorization"`
							State         string `json:"state"`
						} `json:"steps"`
					} `json:"plan"`
					Approvals []struct {
						ID             string `json:"id"`
						State          string `json:"state"`
						ExpectedEffect string `json:"expected_effect"`
					} `json:"approvals"`
				} `json:"run"`
			}
			if json.Unmarshal(raw, &item) != nil {
				continue
			}
			line("### Run `%s`\n", item.Run.Run.ID)
			line("- Security Agent `%s`, state %s, on finding %s", item.Run.Run.AgentID, markdownText(item.Run.Run.State), "`"+strings.Join(item.FindingIDs, "`, `")+"`")
			for _, step := range item.Run.Plan.Steps {
				line("- Step %d: %s, authorization %s, state %s", step.Index+1, markdownText(step.Action), markdownText(step.Authorization), markdownText(step.State))
			}
			if len(item.Run.Approvals) == 0 {
				line("- Approvals: none")
			}
			for _, approval := range item.Run.Approvals {
				line("- Approval `%s`: %s, for %s", approval.ID, markdownText(approval.State), markdownText(approval.ExpectedEffect))
			}
			line("")
		}
	}
	names := map[string]string{}
	if section("Red team definitions", pack.RedTeamTests) {
		line("| Definition | Name | Target kind | Categories |")
		line("| --- | --- | --- | --- |")
		for _, raw := range pack.RedTeamTests.Items {
			var test struct {
				ID         string   `json:"id"`
				Name       string   `json:"name"`
				TargetKind string   `json:"target_kind"`
				Categories []string `json:"categories"`
			}
			if json.Unmarshal(raw, &test) != nil {
				continue
			}
			names[test.ID] = test.Name
			line("| `%s` | %s | %s | %s |", test.ID, markdownText(test.Name), markdownText(test.TargetKind), markdownText(strings.Join(test.Categories, ", ")))
		}
	}
	if section("Red team results", pack.RedTeamRuns) {
		line("| Run | Definition | Status | Verdict | Completed |")
		line("| --- | --- | --- | --- | --- |")
		for _, raw := range pack.RedTeamRuns.Items {
			var run struct {
				ID           string `json:"id"`
				DefinitionID string `json:"definition_id"`
				Status       string `json:"status"`
				Verdict      string `json:"verdict"`
				CompletedAt  string `json:"completed_at"`
			}
			if json.Unmarshal(raw, &run) != nil {
				continue
			}
			definition := "`" + run.DefinitionID + "`"
			if name := names[run.DefinitionID]; name != "" {
				definition = markdownText(name)
			}
			verdict, completed := "none", "not completed"
			if run.Verdict != "" {
				verdict = markdownText(run.Verdict)
			}
			if run.CompletedAt != "" {
				completed = markdownText(run.CompletedAt)
			}
			line("| `%s` | %s | %s | %s | %s |", run.ID, definition, markdownText(run.Status), verdict, completed)
		}
	}
	return text.String()
}
