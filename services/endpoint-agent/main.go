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
	data, err := boundedRead(input, wireLimit)
	var r response
	if err == nil && json.Valid(data) {
		r, err = call(socket, request{Operation: "pre-tool", Hook: data})
	}
	reason := ""
	if err != nil || r.Decision == nil || r.Decision.Verdict == "unavailable" {
		fmt.Fprintln(diag, "Zasp endpoint control unavailable. Run zasp-endpoint status.")
		if failureMode == "deny" {
			reason = "Zasp could not verify a decision for this managed action. Contact your endpoint administrator."
		}
	} else if r.Decision.Verdict == "deny" {
		reason = "Zasp stopped the configured ticket action. Use an approved destination or contact your endpoint administrator."
		if r.Decision.Reason == "action_id_conflict" || r.Decision.Reason == "action_replayed" {
			reason = "Zasp stopped a reused action identifier. Start a new action."
		}
		if r.Decision.ReceiptID != "" {
			reason += " Decision " + r.Decision.ReceiptID + "."
		}
	} else if r.Decision.Verdict != "continue" {
		return errInvalid
	}
	if reason != "" {
		return json.NewEncoder(out).Encode(map[string]any{"hookSpecificOutput": permissionResponse{Event: "PreToolUse", Decision: "deny", Reason: reason}})
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
	case "claude-pre-tool", "status", "export", "archive", "inventory", "sync-now":
		socket := f.String("socket", defaultSocket, "endpoint socket path")
		fail := f.String("on-unavailable", "continue", "continue or deny if the decision is unavailable")
		project := f.String("project", "", "absolute project root used for this inventory")
		archive := f.String("out", "", "new, durable file for archive")
		if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 || (*fail != "continue" && *fail != "deny") {
			return errInvalid
		}
		if args[0] == "claude-pre-tool" {
			return hook(*socket, *fail, in, out, diag)
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
