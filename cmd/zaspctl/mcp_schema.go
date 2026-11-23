package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/mcpschema"
)

func mcpSchema(args []string, input io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "snapshot" && args[0] != "rescan") {
		fmt.Fprintln(stderr, "Use mcp snapshot or mcp rescan with saved tools/list request/response pairs on stdin.")
		return 2
	}
	flags := flag.NewFlagSet("mcp "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var scope mcpschema.Scope
	flags.StringVar(&scope.Environment, "environment", "", "Zasp Environment ID")
	flags.StringVar(&scope.Server, "server", "", "registered MCP gateway server ID")
	flags.StringVar(&scope.View, "view", "", "operator-selected policy and caller view")
	machine := flags.Bool("json", false, "emit a JSON review receipt")
	var destination, baseline, hash string
	var fail bool
	if args[0] == "snapshot" {
		flags.StringVar(&destination, "out", "", "new private baseline file")
	} else {
		flags.StringVar(&baseline, "baseline", "", "existing reviewed baseline file")
		flags.StringVar(&hash, "baseline-sha256", "", "independently retained SHA-256 of baseline bytes")
		flags.BoolVar(&fail, "fail-on-change", false, "exit 10 if this complete capture needs review")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !scope.Valid() || (args[0] == "snapshot" && destination == "") || (args[0] == "rescan" && (baseline == "" || hash == "")) {
		fmt.Fprintln(stderr, "Provide --environment ID --server ID --view LABEL, then --out NEW_FILE for snapshot or --baseline FILE --baseline-sha256 sha256:DIGEST for rescan.")
		return 2
	}
	var previous mcpschema.Snapshot
	if args[0] == "rescan" {
		f, err := mcpschema.OpenBaseline(baseline)
		if err != nil {
			fmt.Fprintln(stderr, "Unable to open a bounded regular baseline file.")
			return 2
		}
		defer f.Close()
		previous, err = mcpschema.Load(f, hash, scope)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
	}
	current, err := mcpschema.Capture(scope, input)
	if err != nil {
		fmt.Fprintln(stderr, "Incomplete MCP observation:", err)
		return 3
	}
	result := struct {
		Status    string             `json:"status"`
		ToolCount int                `json:"tools_in_view"`
		Hash      string             `json:"snapshot_sha256"`
		Changes   []mcpschema.Change `json:"changes"`
		Source    string             `json:"source"`
	}{ToolCount: len(current.Tools), Source: current.Source, Changes: []mcpschema.Change{}}
	document, err := current.Bytes()
	if err != nil {
		fmt.Fprintln(stderr, "Could not encode snapshot.")
		return 2
	}
	result.Hash = mcpschema.Digest(document)
	if args[0] == "snapshot" {
		f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintln(stderr, "Choose a new writable baseline file.")
			return 2
		}
		_, writeErr := f.Write(document)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			os.Remove(destination)
			fmt.Fprintln(stderr, "Could not finish the baseline file.")
			return 2
		}
		result.Status = "snapshot_saved"
	} else {
		result.Changes = mcpschema.Diff(previous, current)
		result.Status = "unchanged"
		if len(result.Changes) > 0 {
			result.Status = "review_needed"
		}
	}
	out := bufio.NewWriter(stdout)
	if *machine {
		if json.NewEncoder(out).Encode(result) != nil {
			return 2
		}
	} else {
		fmt.Fprintf(out, "%s · %d tools in this view\n%s\n", result.Status, result.ToolCount, result.Hash)
		for _, change := range result.Changes {
			fmt.Fprintf(out, "  %s: %s\n", change.Name, strings.Join(change.Fields, ", "))
		}
	}
	if out.Flush() != nil {
		return 2
	}
	if fail && len(result.Changes) > 0 {
		return 10
	}
	return 0
}
