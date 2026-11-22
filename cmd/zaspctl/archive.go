package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

// The private worker can pipe an authorized archive into this process without
// materializing a source file. Aggregate output contains no member names.
func scanArchiveCommand(args []string, input io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scan-archive", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	local := flags.Bool("local", false, "read a private static ZIP from stdin")
	size := flags.Int64("size", 0, "expected compressed byte length")
	digest := flags.String("sha256", "", "expected sha256-prefixed archive digest")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !*local || *size <= 0 || *size > addons.MaxArchiveBytes || len(*digest) != 71 {
		fmt.Fprintln(stderr, "Use addons scan-archive --local --size BYTES --sha256 sha256:DIGEST with ZIP bytes on stdin.")
		return 2
	}
	r := addons.ScanArchive(input, *size, *digest)
	out := r.PrivateSummary()
	if json.NewEncoder(stdout).Encode(out) != nil {
		return 2
	}
	if r.Status != "complete" {
		return 3
	}
	return 0
}
