// Package evidencepack is the retained evidence pack of one agent: the
// document the compliance export job captures for a request that names an
// agent (completion.sql, section WS3-C2), its validation and its renderings.
// The export worker renders a captured pack; the API validates a stored one
// before it hands it out.
package evidencepack

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const SchemaVersion = "agent-evidence-pack-v1"

var ErrInvalid = errors.New("invalid agent evidence pack")

var productID = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Reference struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Title     string `json:"title"`
}

type Finding struct {
	ID         string      `json:"id"`
	Source     string      `json:"source"`
	Rule       string      `json:"rule"`
	Title      string      `json:"title"`
	Severity   string      `json:"severity"`
	Status     string      `json:"status"`
	Version    int64       `json:"version"`
	CreatedAt  string      `json:"created_at"`
	UpdatedAt  string      `json:"updated_at"`
	Frameworks []Reference `json:"frameworks"`
}

type Step struct {
	Index         int    `json:"index"`
	Action        string `json:"action"`
	Authorization string `json:"authorization"`
	State         string `json:"state"`
}

type Approval struct {
	ID          string `json:"id"`
	StepID      string `json:"step_id"`
	State       string `json:"state"`
	RequesterID string `json:"requester_id"`
	ApproverID  string `json:"approver_id"`
	DecidedAt   string `json:"decided_at"`
	ExpiresAt   string `json:"expires_at"`
}

type SecurityAgentRun struct {
	ID                string     `json:"id"`
	SecurityAgentID   string     `json:"security_agent_id"`
	DefinitionVersion int64      `json:"definition_version"`
	FindingID         string     `json:"finding_id"`
	State             string     `json:"state"`
	RequestedBy       string     `json:"requested_by"`
	CreatedAt         string     `json:"created_at"`
	UpdatedAt         string     `json:"updated_at"`
	Steps             []Step     `json:"steps"`
	Approvals         []Approval `json:"approvals"`
}

type RedTeamTest struct {
	ID         string   `json:"id"`
	Version    int64    `json:"version"`
	Name       string   `json:"name"`
	TargetKind string   `json:"target_kind"`
	Categories []string `json:"categories"`
	Enabled    bool     `json:"enabled"`
}

type RedTeamRun struct {
	ID                string `json:"id"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion int64  `json:"definition_version"`
	Status            string `json:"status"`
	Verdict           string `json:"verdict"`
	Attempt           int    `json:"attempt"`
	QueuedAt          string `json:"queued_at"`
	CompletedAt       string `json:"completed_at"`
}

// Agent is the inventory detail of the agent. Only the members the
// renderings print are decoded; the document keeps the whole detail.
type Agent struct {
	Summary struct {
		ID              string  `json:"id"`
		Name            string  `json:"name"`
		Kind            string  `json:"kind"`
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

// Pack is the decoded document. Statuses are "complete", "truncated" or, for
// the Security Agent runs, "partial": the export worker sees only the runs
// row security shows it, not those owned by the Temporal executor.
type Pack struct {
	Agent              Agent
	Findings           []Finding
	FindingsStatus     string
	Runs               []SecurityAgentRun
	RunsStatus         string
	RedTeamTests       []RedTeamTest
	RedTeamTestsStatus string
	RedTeamRuns        []RedTeamRun
	RedTeamRunsStatus  string
}

func closed(raw json.RawMessage, keys ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return nil, ErrInvalid
	}
	for _, key := range keys {
		if value, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrInvalid
		}
	}
	return fields, nil
}

func strict(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func section[T any](raw json.RawMessage, maximum int, statuses ...string) ([]T, string, error) {
	fields, err := closed(raw, "status", "items")
	if err != nil {
		return nil, "", err
	}
	var status string
	items := []T{}
	if json.Unmarshal(fields["status"], &status) != nil || strict(fields["items"], &items) != nil || items == nil || len(items) > maximum {
		return nil, "", ErrInvalid
	}
	for _, allowed := range statuses {
		if status == allowed {
			return items, status, nil
		}
	}
	return nil, "", ErrInvalid
}

func text(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func stamp(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && strings.HasSuffix(value, "Z")
}

// Decode validates a captured or stored pack and returns its contents. The
// pack must be the pack of one agent: every finding, run and test in it is
// bound to that agent or to a record of the pack.
func Decode(raw json.RawMessage) (Pack, error) {
	var pack Pack
	fields, err := closed(raw, "schema_version", "agent", "findings", "security_agent_runs", "red_team_tests", "red_team_runs")
	if err != nil {
		return Pack{}, err
	}
	var version string
	if json.Unmarshal(fields["schema_version"], &version) != nil || version != SchemaVersion {
		return Pack{}, ErrInvalid
	}
	if _, err := closed(fields["agent"], "summary", "sources", "evidence"); err != nil || json.Unmarshal(fields["agent"], &pack.Agent) != nil {
		return Pack{}, ErrInvalid
	}
	summary := pack.Agent.Summary
	if !productID.MatchString(summary.ID) || summary.Kind != "agent" || !text(summary.Name, 1, 256) || len(pack.Agent.Sources) < 1 || len(pack.Agent.Sources) > 64 || len(pack.Agent.Evidence) < 1 || len(pack.Agent.Evidence) > 64 {
		return Pack{}, ErrInvalid
	}
	if pack.Findings, pack.FindingsStatus, err = section[Finding](fields["findings"], 200, "complete", "truncated"); err != nil {
		return Pack{}, err
	}
	findings := map[string]bool{}
	for _, finding := range pack.Findings {
		if !productID.MatchString(finding.ID) || findings[finding.ID] || !text(finding.Source, 1, 64) || !text(finding.Rule, 0, 64) || !text(finding.Title, 1, 256) || !text(finding.Severity, 1, 16) || !text(finding.Status, 1, 32) || finding.Version < 1 || !stamp(finding.CreatedAt, false) || !stamp(finding.UpdatedAt, false) || finding.Frameworks == nil || len(finding.Frameworks) > 32 {
			return Pack{}, ErrInvalid
		}
		for _, reference := range finding.Frameworks {
			if !text(reference.Framework, 1, 64) || !text(reference.Control, 1, 64) || !text(reference.Title, 1, 256) {
				return Pack{}, ErrInvalid
			}
		}
		findings[finding.ID] = true
	}
	if pack.Runs, pack.RunsStatus, err = section[SecurityAgentRun](fields["security_agent_runs"], 50, "partial"); err != nil {
		return Pack{}, err
	}
	runs := map[string]bool{}
	for _, run := range pack.Runs {
		if !productID.MatchString(run.ID) || runs[run.ID] || !productID.MatchString(run.SecurityAgentID) || !findings[run.FindingID] || run.DefinitionVersion < 1 || !text(run.State, 1, 32) || !productID.MatchString(run.RequestedBy) || !stamp(run.CreatedAt, false) || !stamp(run.UpdatedAt, false) || run.Steps == nil || len(run.Steps) > 100 || run.Approvals == nil || len(run.Approvals) > 100 {
			return Pack{}, ErrInvalid
		}
		for _, step := range run.Steps {
			if step.Index < 0 || step.Index > 99 || !text(step.Action, 1, 128) || !text(step.Authorization, 1, 32) || !text(step.State, 1, 32) {
				return Pack{}, ErrInvalid
			}
		}
		for _, approval := range run.Approvals {
			if !productID.MatchString(approval.ID) || !productID.MatchString(approval.StepID) || !text(approval.State, 1, 32) || !productID.MatchString(approval.RequesterID) || approval.ApproverID != "" && !productID.MatchString(approval.ApproverID) || !stamp(approval.DecidedAt, true) || !stamp(approval.ExpiresAt, false) {
				return Pack{}, ErrInvalid
			}
		}
		runs[run.ID] = true
	}
	if pack.RedTeamTests, pack.RedTeamTestsStatus, err = section[RedTeamTest](fields["red_team_tests"], 200, "complete", "truncated"); err != nil {
		return Pack{}, err
	}
	tests := map[string]bool{}
	for _, test := range pack.RedTeamTests {
		if !productID.MatchString(test.ID) || tests[test.ID] || test.Version < 1 || !text(test.Name, 1, 128) || !text(test.TargetKind, 1, 32) || test.Categories == nil || len(test.Categories) > 16 {
			return Pack{}, ErrInvalid
		}
		for _, category := range test.Categories {
			if !text(category, 1, 64) {
				return Pack{}, ErrInvalid
			}
		}
		tests[test.ID] = true
	}
	if pack.RedTeamRuns, pack.RedTeamRunsStatus, err = section[RedTeamRun](fields["red_team_runs"], 200, "complete", "truncated"); err != nil {
		return Pack{}, err
	}
	seen := map[string]bool{}
	for _, run := range pack.RedTeamRuns {
		if !productID.MatchString(run.ID) || seen[run.ID] || !tests[run.DefinitionID] || run.DefinitionVersion < 1 || !text(run.Status, 1, 32) || !text(run.Verdict, 0, 32) || run.Attempt < 0 || run.Attempt > 5 || !stamp(run.QueuedAt, false) || !stamp(run.CompletedAt, true) {
			return Pack{}, ErrInvalid
		}
		seen[run.ID] = true
	}
	return pack, nil
}

// markdownText keeps recorded text on one line and out of the document's own
// structure.
func markdownText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "`", "'", "<", "&lt;", ">", "&gt;", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "#", `\#`).Replace(strings.TrimSpace(value))
}

// codeText is recorded text inside a code span: one line, no backtick, no
// table separator.
func codeText(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '`' || r == '|' {
			return ' '
		}
		return r
	}, value)
}

var statusNote = map[string]string{
	"truncated": "This section reached its bound and is not complete.",
	"partial":   "This section holds the runs the export worker can read. Runs owned by the Temporal executor are not in a retained pack; the pack generated on request from the agent detail reads them through the API.",
}

// Markdown renders the pack for a reader. snapshotAt is when the export job
// captured it.
func Markdown(pack Pack, organization, workspace, environment string, snapshotAt time.Time) string {
	var out strings.Builder
	line := func(format string, values ...any) { fmt.Fprintf(&out, format+"\n", values...) }
	head := func(title, status string, empty bool) bool {
		line("\n## %s\n", title)
		if note := statusNote[status]; note != "" {
			line("%s\n", note)
		}
		if empty {
			line("None recorded.")
		}
		return !empty
	}
	summary := pack.Agent.Summary
	line("# Agent evidence pack: %s", markdownText(summary.Name))
	line("")
	line("- Agent: `%s`", summary.ID)
	line("- Captured: %s", snapshotAt.UTC().Format(time.RFC3339))
	line("- Organization `%s`, Workspace `%s`, Environment `%s`", organization, workspace, environment)
	line("- Format: %s (retained export)", SchemaVersion)
	line("")
	line("This document holds what the export captured for its requester. A framework reference says a finding is relevant to a control; it does not say the control is met or failed.")
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
			line("  - `%s`", codeText(signal))
		}
	}
	line("\n| Source | Provider | Integration | Snapshot | Evidence | Observed | Winning |")
	line("| --- | --- | --- | --- | --- | --- | --- |")
	for _, source := range pack.Agent.Sources {
		winning := "no"
		if source.Winning {
			winning = "yes"
		}
		line("| %s | %s | `%s` | `%s` | `%s` | %s | %s |", markdownText(source.Source), markdownText(source.Provider), codeText(source.IntegrationID), codeText(source.SnapshotID), codeText(source.EvidenceID), markdownText(source.ObservedAt), winning)
	}
	line("\n| Evidence record | Checksum | Collected |")
	line("| --- | --- | --- |")
	for _, evidence := range pack.Agent.Evidence {
		line("| `%s` | `%s` | %s |", codeText(evidence.ID), codeText(evidence.Checksum), markdownText(evidence.CollectedAt))
	}
	if head("Findings", pack.FindingsStatus, len(pack.Findings) == 0) {
		for _, finding := range pack.Findings {
			line("### %s\n", markdownText(finding.Title))
			line("- Finding `%s`, rule `%s`, severity %s, status %s, updated %s", finding.ID, codeText(finding.Rule), markdownText(finding.Severity), markdownText(finding.Status), finding.UpdatedAt)
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
	if head("Security Agent actions and approvals", pack.RunsStatus, len(pack.Runs) == 0) {
		for _, run := range pack.Runs {
			line("### Run `%s`\n", run.ID)
			line("- Security Agent `%s`, state %s, on finding `%s`, requested by `%s`", run.SecurityAgentID, markdownText(run.State), run.FindingID, run.RequestedBy)
			for _, step := range run.Steps {
				line("- Step %d: %s, authorization %s, state %s", step.Index+1, markdownText(step.Action), markdownText(step.Authorization), markdownText(step.State))
			}
			if len(run.Approvals) == 0 {
				line("- Approvals: none")
			}
			for _, approval := range run.Approvals {
				decided := "not decided"
				if approval.ApproverID != "" {
					decided = "decided by `" + approval.ApproverID + "` at " + approval.DecidedAt
				}
				line("- Approval `%s`: %s, requested by `%s`, %s", approval.ID, markdownText(approval.State), approval.RequesterID, decided)
			}
			line("")
		}
	}
	names := map[string]string{}
	if head("Red team definitions", pack.RedTeamTestsStatus, len(pack.RedTeamTests) == 0) {
		line("| Definition | Name | Target kind | Categories |")
		line("| --- | --- | --- | --- |")
		for _, test := range pack.RedTeamTests {
			names[test.ID] = test.Name
			line("| `%s` | %s | %s | %s |", test.ID, markdownText(test.Name), markdownText(test.TargetKind), markdownText(strings.Join(test.Categories, ", ")))
		}
	}
	if head("Red team results", pack.RedTeamRunsStatus, len(pack.RedTeamRuns) == 0) {
		line("| Run | Definition | Status | Verdict | Completed |")
		line("| --- | --- | --- | --- | --- |")
		for _, run := range pack.RedTeamRuns {
			verdict, completed := "none", "not completed"
			if run.Verdict != "" {
				verdict = markdownText(run.Verdict)
			}
			if run.CompletedAt != "" {
				completed = run.CompletedAt
			}
			line("| `%s` | %s | %s | %s | %s |", run.ID, markdownText(names[run.DefinitionID]), markdownText(run.Status), verdict, completed)
		}
	}
	return out.String()
}

// csvCell neutralizes a cell a spreadsheet would evaluate.
func csvCell(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

// CSV lists every record of the pack, one per row.
func CSV(pack Pack) ([]byte, error) {
	var out bytes.Buffer
	writer := csv.NewWriter(&out)
	rows := [][]string{{"record", "id", "related_id", "name", "state", "detail", "at"}}
	summary := pack.Agent.Summary
	rows = append(rows, []string{"agent", summary.ID, "", summary.Name, summary.ActivityState, summary.Discovery.Method + " " + summary.Discovery.Platform, summary.ObservedAt})
	for _, finding := range pack.Findings {
		references := make([]string, 0, len(finding.Frameworks))
		for _, reference := range finding.Frameworks {
			references = append(references, reference.Framework+" "+reference.Control)
		}
		rows = append(rows, []string{"finding", finding.ID, summary.ID, finding.Title, finding.Status, finding.Severity + " " + finding.Rule + " [" + strings.Join(references, "; ") + "]", finding.UpdatedAt})
	}
	for _, run := range pack.Runs {
		rows = append(rows, []string{"security_agent_run", run.ID, run.FindingID, run.SecurityAgentID, run.State, fmt.Sprintf("%d steps", len(run.Steps)), run.UpdatedAt})
		for _, approval := range run.Approvals {
			rows = append(rows, []string{"approval", approval.ID, run.ID, approval.ApproverID, approval.State, "requested by " + approval.RequesterID, approval.DecidedAt})
		}
	}
	for _, test := range pack.RedTeamTests {
		rows = append(rows, []string{"red_team_test", test.ID, summary.ID, test.Name, map[bool]string{true: "enabled", false: "disabled"}[test.Enabled], strings.Join(test.Categories, "; "), ""})
	}
	for _, run := range pack.RedTeamRuns {
		rows = append(rows, []string{"red_team_run", run.ID, run.DefinitionID, "", run.Status, run.Verdict, run.CompletedAt})
	}
	for _, row := range rows {
		for index := range row {
			row[index] = csvCell(row[index])
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return out.Bytes(), writer.Error()
}
