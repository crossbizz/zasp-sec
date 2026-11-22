package main

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/browserlink"
)

var environmentID = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var cohort = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var sessionRef = regexp.MustCompile(`^[a-f0-9]{64}$`)

func evidenceLink(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("evidence export", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	env := f.String("environment", "", "Environment ID")
	group := f.String("cohort", "", "managed pilot cohort")
	device := f.String("device", "", "endpoint device ID")
	session := f.String("session", "", "device-bound endpoint session reference")
	noOpen := f.Bool("no-open", false, "print the first-party browser link")
	origin, ok := browserlink.Origin(os.Getenv("ZASP_API_URL"))
	if f.Parse(args) != nil || f.NArg() != 0 || !ok || !environmentID.MatchString(*env) ||
		(!cohort.MatchString(*group) && !environmentID.MatchString(*device)) ||
		(*group != "" && (*device != "" || *session != "")) || (*session != "" && !sessionRef.MatchString(*session)) {
		fmt.Fprintln(stderr, "Set the HTTPS ZASP_API_URL, select --environment ID and choose --cohort LABEL or --device ID. A device may include --session followed by its 64-character endpoint session reference.")
		return 2
	}
	fields := url.Values{"pilot_environment": {*env}}
	if *group != "" {
		fields.Set("pilot_cohort", *group)
	} else {
		fields.Set("device_id", *device)
	}
	if *session != "" {
		fields.Set("endpoint_session_ref", *session)
	}
	link := origin + "/compliance/evidence#" + fields.Encode()
	fmt.Fprintln(stdout, "Review the selector in the browser and request the retained export.")
	fmt.Fprintln(stdout, link)
	if !*noOpen {
		browserlink.Open(link)
	}
	return 0
}
