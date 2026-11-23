package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/browserlink"
)

var guardrailPolicyID = regexp.MustCompile("^policy-[a-z0-9][a-z0-9-]{0,120}$")
var guardrailAgentID = regexp.MustCompile("^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")

func simulateGuardrail(args []string, out, errs io.Writer) int {
	client := &http.Client{Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return runReplay(args, out, errs, client, time.Now().UTC().Truncate(time.Millisecond))
}
func runReplay(args []string, out, errs io.Writer, client *http.Client, now time.Time) int {
	if len(args) == 0 {
		fmt.Fprintln(errs, "Specify POLICY@REVISION, --agent and --since.")
		return 2
	}
	flags := flag.NewFlagSet("guardrails simulate", flag.ContinueOnError)
	flags.SetOutput(errs)
	policyFlag := flags.String("policy", "", "policy ID for a numeric revision")
	agent := flags.String("agent", "", "scoped agent ID")
	since := flags.String("since", "", "inclusive RFC3339 time")
	until := flags.String("until", now.Format(time.RFC3339Nano), "exclusive RFC3339 end or continuation timestamp")
	before := flags.String("before-event-id", "", "continue a truncated replay at the returned event ID")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	policy, revision, joined := strings.Cut(args[0], "@")
	if !joined {
		revision = args[0]
		policy = *policyFlag
	} else if *policyFlag != "" {
		fmt.Fprintln(errs, "Select the policy once.")
		return 2
	}
	n, err := strconv.ParseInt(revision, 10, 64)
	from, e1 := time.Parse(time.RFC3339Nano, *since)
	to, e2 := time.Parse(time.RFC3339Nano, *until)
	host, ok := browserlink.Origin(os.Getenv("ZASP_API_URL"))
	token := os.Getenv("ZASP_API_TOKEN")
	if !ok || token == "" || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") {
		fmt.Fprintln(errs, "Set ZASP_API_URL to your HTTPS deployment and ZASP_API_TOKEN to a scoped credential with manage_workflows access.")
		return 2
	}
	if !guardrailPolicyID.MatchString(policy) || err != nil || n < 1 || strconv.FormatInt(n, 10) != revision || !guardrailAgentID.MatchString(*agent) || e1 != nil || e2 != nil || from.After(to) || from.Equal(to) && *before == "" || to.After(now) || to.Sub(from) > 30*24*time.Hour || from.Nanosecond()%1_000_000 != 0 || to.Nanosecond()%1_000_000 != 0 || *before != "" && !guardrailAgentID.MatchString(*before) {
		fmt.Fprintln(errs, "Use POLICY@REVISION, an agent ID and a replay window of up to 30 days with millisecond precision.")
		return 2
	}
	body := map[string]any{"schema_version": 2, "policy_revision": n, "agent_id": *agent, "from": from.UTC(), "to": to.UTC()}
	if *before != "" {
		body["before_event_id"] = *before
	}
	encoded, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, host+"/api/v1/policies/"+policy+"/simulate", bytes.NewReader(encoded))
	if err != nil {
		return 2
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(errs, "The replay service is unavailable.")
		return 3
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Fprintf(errs, "Replay did not complete (HTTP %d). Check scope, policy revision and indexed history.\n", resp.StatusCode)
		return 3
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16+1))
	var result struct {
		Examples   []string `json:"example_session_ids"`
		Matches    *int     `json:"matches"`
		WouldBlock *int     `json:"would_block"`
		Replay     struct {
			Revision  int64              `json:"policy_revision"`
			Agent     string             `json:"agent_id"`
			From      time.Time          `json:"from"`
			To        time.Time          `json:"to"`
			Evaluated *int               `json:"evaluated"`
			Count     *int               `json:"examined_count"`
			Eligible  *int               `json:"eligible_count"`
			Coverage  string             `json:"coverage"`
			Truncated bool               `json:"truncated"`
			Next      *time.Time         `json:"next_window_to"`
			ID        *string            `json:"next_before_event_id"`
			Rates     map[string]float64 `json:"would_block_rate"`
		} `json:"replay"`
	}
	if err != nil || len(data) > 1<<16 || !validReplayResponse(data, &result) {
		fmt.Fprintln(errs, "Invalid replay response.")
		return 3
	}
	r := result.Replay
	if r.Revision != n || r.Agent != *agent || !r.From.Equal(from) || !r.To.Equal(to) || r.Coverage != "indexed_events_only" || r.Count == nil || r.Evaluated == nil || *r.Count != *r.Evaluated || len(result.Examples) > 5 || result.Examples == nil || r.Eligible == nil || result.WouldBlock == nil || result.Matches == nil || *r.Count < 0 || *r.Count > 5000 || *r.Eligible < 0 || *r.Eligible > *r.Count || *result.WouldBlock < 0 || *result.WouldBlock > *result.Matches || *result.Matches > *r.Eligible || r.Rates == nil || (r.Next == nil) != (r.ID == nil) || r.Truncated != (r.Next != nil) || r.ID != nil && !guardrailAgentID.MatchString(*r.ID) {
		fmt.Fprintln(errs, "Replay response does not match the requested scope, revision or bounded window.")
		return 3
	}
	for _, id := range result.Examples {
		if !guardrailAgentID.MatchString(id) {
			fmt.Fprintln(errs, "Invalid replay example.")
			return 3
		}
	}
	for surface, rate := range r.Rates {
		if !slicesContainsTrigger(surface) || rate < 0 || rate > 1 {
			fmt.Fprintln(errs, "Invalid replay surface rate.")
			return 3
		}
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, data, "", "  ") != nil {
		return 3
	}
	fmt.Fprintln(out, pretty.String())
	return 0
}
func validReplayResponse(b []byte, v any) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v) == nil && d.Decode(new(any)) == io.EOF
}

func slicesContainsTrigger(s string) bool {
	return s == "tool" || s == "file" || s == "runtime" || s == "network" || s == "credential"
}
