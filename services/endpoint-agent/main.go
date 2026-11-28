package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

const defaultSocket = "/Library/Application Support/Zasp/run/endpoint.sock"

type permissionResponse struct {
	Event    string `json:"hookEventName"`
	Decision string `json:"permissionDecision"`
	Reason   string `json:"permissionDecisionReason"`
}

func hook(socket, failureMode string, input io.Reader, out io.Writer, diag io.Writer) error {
	return hookVia("claude", socket, failureMode, input, out, diag)
}
func hookVia(harness, socket, failureMode string, input io.Reader, out, diag io.Writer) error {
	return managedHook(harness, socket, failureMode, false, input, out, diag)
}

func managedHook(harness, socket, failureMode string, require bool, input io.Reader, out, diag io.Writer) error {
	token := os.Getenv("ZASP_TASK_DELEGATION")
	if require || token != "" {
		failureMode = "deny"
	}
	data, err := boundedRead(input, wireLimit)
	var r response
	if err == nil && json.Valid(data) {
		r, err = call(socket, request{Operation: "pre-tool", Hook: data, Harness: harness, Delegation: token, RequireDelegation: require})
	}
	reason := ""
	message := ""
	if err != nil || r.Decision == nil || r.Decision.Verdict == "unavailable" {
		fmt.Fprintln(diag, "Zasp endpoint control unavailable. Run zasp-endpoint status.")
		if failureMode == "deny" {
			reason = "Zasp could not verify a decision for this managed action. Contact your endpoint administrator."
		}
	} else if r.Decision.Verdict == "deny" {
		reason = "Zasp stopped the configured ticket action. Use an approved destination or contact your endpoint administrator."
		if r.Decision.Reason == "delegation_unverified" || r.Decision.Reason == "delegation_denied" {
			reason = "This action requires a valid task delegation for its tool and destination."
		}
		if r.Decision.Revision > 0 {
			detail, _ := json.Marshal(map[string]any{"action_id": r.Decision.ReceiptID, "rule_id": r.Decision.RuleID, "policy_revision": r.Decision.Revision, "reason_code": r.Decision.Reason, "next_step_hint": r.Decision.NextStep})
			reason = string(detail)
			message = fmt.Sprintf("Zasp stopped this action under endpoint policy revision %d (%s). Contact your endpoint administrator.", r.Decision.Revision, r.Decision.Reason)
		}
		if r.Decision.Reason == "action_id_conflict" || r.Decision.Reason == "action_replayed" {
			reason = "Zasp stopped a reused action identifier. Start a new action."
		}
		if r.Decision.Revision == 0 && r.Decision.ReceiptID != "" {
			reason += " Decision " + r.Decision.ReceiptID + "."
		}
	} else if r.Decision.Verdict != "continue" {
		return errInvalid
	}
	if reason != "" {
		reply := map[string]any{"hookSpecificOutput": permissionResponse{Event: "PreToolUse", Decision: "deny", Reason: reason}}
		if message != "" {
			reply["systemMessage"] = message
		}
		return json.NewEncoder(out).Encode(reply)
	}
	// Empty output lets the harness apply its normal permission checks.
	return json.NewEncoder(out).Encode(struct{}{})
}

func run(ctx context.Context, args []string, in io.Reader, out, diag io.Writer) error {
	if len(args) == 0 {
		return errInvalid
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(diag)
	switch args[0] {
	case "watch-skills":
		socket := f.String("socket", defaultSocket, "assigned endpoint socket")
		project := f.String("project", "", "scan only this assigned project root")
		if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
			return errInvalid
		}
		return watchInstalledSkills(ctx, *socket, installedScanner, *project)
	case "watch-ticket":
		return watchTicket(ctx, args[1:], out, diag)
	case "prove-ticket":
		return proveTicket(ctx, args[1:], out, diag)
	case "init-device-key":
		account := f.String("account", "", "managed device keychain account")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 {
			return errInvalid
		}
		pub, err := initializeDeviceKey(*account)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"device_public_key": []byte(pub)})
	case "serve":
		path := f.String("config", "/Library/Application Support/Zasp/endpoint.json", "managed configuration")
		if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
			return errInvalid
		}
		return serve(ctx, *path)
	case "codex-pre-tool", "claude-pre-tool", "status", "export", "archive", "inventory", "sync-now":
		requireDelegation := f.Bool("require-delegation", false, "require a verified task grant and deny if the endpoint is unavailable")
		socket := f.String("socket", defaultSocket, "endpoint socket path")
		fail := f.String("on-unavailable", "continue", "continue or deny if the decision is unavailable")
		project := f.String("project", "", "absolute project root used for this inventory")
		archive := f.String("out", "", "new, durable file for archive")
		if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 || (*fail != "continue" && *fail != "deny") {
			return errInvalid
		}
		if args[0] == "claude-pre-tool" || args[0] == "codex-pre-tool" {
			harness := "claude"
			if args[0] == "codex-pre-tool" {
				harness = "codex"
			}
			return managedHook(harness, *socket, *fail, *requireDelegation, in, out, diag)
		}
		if args[0] == "archive" {
			return archiveReceipts(*socket, *archive)
		}
		req := request{Operation: args[0]}
		if args[0] == "inventory" {
			raw, err := boundedRead(in, wireLimit)
			if err != nil || !json.Valid(raw) {
				return errInvalid
			}
			req.Hook = raw
			req.Project = *project
		}
		r, err := call(*socket, req)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(r)
	}
	return errInvalid
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Zasp endpoint command failed:", err)
		os.Exit(1)
	}
}
