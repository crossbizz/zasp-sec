// The installed API test uses the endpoint's employee-report decoder on Linux
// and macOS without provisioning an OS keychain or starting a privileged broker.
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/inventoryreport"
)

func main() {
	var input struct {
		Project  string
		Seed     []byte
		Sequence uint64
		Report   json.RawMessage
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		log.Fatal(err)
	}
	snapshots, _, err := inventoryreport.Parse(input.Report, input.Project, input.Seed, input.Sequence)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(snapshots); err != nil {
		log.Fatal(err)
	}
}
