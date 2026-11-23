// Command verify-ticket evaluates previously collected evidence for a synthetic staging ticket.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

const usage = `Usage: verify-ticket SCENARIO.json ADAPTER.json RECORDER.json
Compare a pinned synthetic-ticket scenario with the adapter decisions and the independent
recorder export. Obtain both exports from their authenticated sources before running this
local command. A fixture run only evaluates fixture evidence. This command never contacts
a target or certifies live coverage. See services/platform/cmd/verify-ticket/README.md.
Source signing: verify-ticket sign-source ROLE KEY_ID PRIVATE_KEY.pem SCENARIO.json SOURCE.json
Exit: 0 passed, 1 unexpected effect, 2 invalid input, 3 inconclusive or unsupported.`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now())) }

func run(args []string, stdout, stderr io.Writer, now time.Time) int {
	if len(args) > 0 && args[0] == "sign-source" {
		return signSource(args[1:], stdout, stderr, now)
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	if len(args) != 3 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var scenario redteam.TicketScenario
	var adapter redteam.TicketAdapterEvidence
	var recorder redteam.TicketRecorderEvidence
	for i, item := range []struct {
		name string
		dest any
	}{{"scenario", &scenario}, {"adapter", &adapter}, {"recorder", &recorder}} {
		if err := readExport(args[i], item.dest); err != nil {
			fmt.Fprintf(stderr, "Invalid %s export. Expected one local JSON object under 64 KiB.\n", item.name)
			return 2
		}
	}
	result, err := redteam.VerifyTicketProof(scenario, adapter, recorder, now)
	if err != nil {
		fmt.Fprintln(stderr, "Invalid ticket verification scenario or evidence.")
		return 2
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 2
	}
	switch result.Verdict {
	case "passed":
		return 0
	case "unexpected_effect":
		return 1
	default:
		return 3
	}
}

func readExport(path string, output any) error {
	const limit = 64 * 1024
	invalid := errors.New("invalid export")
	// Refuse special files before opening so a named pipe cannot block startup.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() >= limit {
		return invalid
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil || len(data) == limit {
		return invalid
	}
	return redteam.DecodeTicketExport(data, output)
}
