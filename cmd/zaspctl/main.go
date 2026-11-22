package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/cliauth"
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/device"
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/share"
)

const usage = `zaspctl — local agent add-on inventory and static scans

  zaspctl mcp snapshot --environment ID --server ID --view LABEL --out NEW_FILE [--json] < captured-pages.jsonl
  zaspctl mcp rescan --environment ID --server ID --view LABEL --baseline FILE --baseline-sha256 sha256:DIGEST [--fail-on-change] [--json] < captured-pages.jsonl
  zaspctl evidence export --environment ID (--cohort LABEL | --device ID [--session REF]) [--no-open]
  zaspctl device status|doctor [--json]
  zaspctl auth login --environment ID [--no-open]
  zaspctl addons attest RECEIPT --environment ID --credential-id ID --repository OWNER/REPO --commit SHA --bundle DIR --key-file FILE [--repo-dir DIR]
  zaspctl addons submit REPORT --mode findings-only --environment ID
  zaspctl addons inventory --local [--project DIR] [--scope all|personal|managed|project] [--harness claude-code|codex|all] [--codex-cwd RELATIVE_DIR] [--declarations] [--json] [--report-html FILE]
  zaspctl addons scan-archive --local --size BYTES --sha256 sha256:DIGEST < BUNDLE.zip
  zaspctl addons scan PATH --local [--json] [--report-html FILE] [--fail-on low|medium|high|critical] [--advisory-snapshot FILE --advisory-sha256 sha256:DIGEST]

Use a skill directory, its SKILL.md, or a supported MCP declaration as PATH.
Local commands run without an account, network access or add-on execution.
A report file must be a new file. Exit 3 means coverage was partial.
A completed scan exits 10 only if it meets an explicit --fail-on threshold.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if len(args) >= 1 && args[0] == "mcp" {
		return mcpSchema(args[1:], os.Stdin, stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "evidence" && args[1] == "export" {
		return evidenceLink(args[2:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "device" {
		return device.Status(args[1:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "auth" && args[1] == "login" {
		return cliauth.Login(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "addons" && args[1] == "attest" {
		return share.Attest(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "addons" && args[1] == "scan-archive" {
		return scanArchiveCommand(args[2:], os.Stdin, stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "addons" && args[1] == "submit" {
		return share.Submit(args[2:], stdout, stderr)
	}
	if len(args) < 2 || args[0] != "addons" || (args[1] != "scan" && args[1] != "inventory") {
		fmt.Fprint(stderr, usage)
		return 2
	}
	command := args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	local := flags.Bool("local", false, "work offline")
	asJSON := flags.Bool("json", false, "print a machine-readable report")
	htmlPath := flags.String("report-html", "", "write a self-contained local report")
	var project, scope, harness, codexCWD, failOn, advisoryPath, advisoryDigest string
	var declarations bool
	if command == "inventory" {
		flags.StringVar(&project, "project", "", "include this project")
		flags.BoolVar(&declarations, "declarations", false, "include supported Claude Code declaration files")
		flags.StringVar(&harness, "harness", "claude-code", "selected discovery profile")
		flags.StringVar(&codexCWD, "codex-cwd", ".", "selected directory below the approved project root")
		flags.StringVar(&scope, "scope", "all", "restrict which locations are read")
	} else {
		flags.StringVar(&advisoryPath, "advisory-snapshot", "", "offline exact-release advisory catalog")
		flags.StringVar(&advisoryDigest, "advisory-sha256", "", "trusted catalog digest")
		flags.StringVar(&failOn, "fail-on", "", "minimum severity for CI failure")
	}
	positional, err := parseFlags(flags, args[2:])
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if err != nil || !*local {
		fmt.Fprint(stderr, "Invalid arguments. Specify --local for a local scan.\n", usage)
		return 2
	}

	var report localReport
	exitCode := 0
	switch command {
	case "inventory":
		if len(positional) != 0 || !validScope(scope, project) {
			fmt.Fprintln(stderr, "Choose a supported --scope. Project scope requires --project DIR.")
			return 2
		}
		if !validProfile(harness, codexCWD, project) || (declarations && harness == "codex") {
			fmt.Fprintln(stderr, "Use --harness claude-code, codex or all. A Codex working directory must be a bounded relative path under --project.")
			return 2
		}
		report = inventory(project, scope, harness, codexCWD, declarations)
	case "scan":
		if len(positional) != 1 || positional[0] == "" || (failOn != "" && severity(failOn) == 0) {
			fmt.Fprintln(stderr, "Provide one skill or MCP path. --fail-on accepts low, medium, high or critical.")
			return 2
		}
		scan := addons.Scan(positional[0])
		if advisoryPath != "" || advisoryDigest != "" {
			if err := addons.ApplyAdvisories(&scan, advisoryPath, advisoryDigest, time.Now()); err != nil {
				fmt.Fprintln(stderr, "Could not verify the requested advisory snapshot. Supply its trusted SHA-256 digest and a valid catalog.")
				return 2
			}
			if scan.AdvisoryStatus != "evaluated_exact_releases" {
				exitCode = 3
			}
			if failOn != "" {
				for _, match := range scan.AdvisoryCoverage.Matches {
					if severity(match.Severity) >= severity(failOn) {
						exitCode = 10
						break
					}
				}
			}
		}
		report = scanEnvelope(scan)
		if failOn != "" {
			for _, finding := range scan.Findings {
				if severity(finding.Severity) >= severity(failOn) {
					exitCode = 10
					break
				}
			}
		}
	}

	if *htmlPath != "" {
		if err := writeHTML(*htmlPath, report); err != nil {
			fmt.Fprintln(stderr, "Could not create the private HTML report. Choose a new file in a writable directory.")
			return 2
		}
	}
	if err := writeOutput(stdout, *asJSON, report); err != nil {
		fmt.Fprintln(stderr, "Could not write the report.")
		return 2
	}
	if report.Status == "partial" {
		return 3
	}
	return exitCode
}

// The documented CLI accepts options both before and after a path.
func parseFlags(flags *flag.FlagSet, args []string) ([]string, error) {
	var positional, literal []string
	if i := slices.Index(args, "--"); i >= 0 {
		literal, args = args[i+1:], args[:i]
	}
	for len(args) > 0 {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		args = flags.Args()
		if len(args) > 0 {
			positional = append(positional, args[0])
			args = args[1:]
		}
	}
	return append(positional, literal...), nil
}

func validScope(scope, project string) bool {
	switch scope {
	case "all":
		return true
	case "project":
		return project != ""
	case "personal", "managed":
		return project == ""
	default:
		return false
	}
}

func severity(value string) int {
	switch strings.ToLower(value) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}
