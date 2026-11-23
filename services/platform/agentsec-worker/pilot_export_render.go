package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type pilotDevice struct {
	ID         string     `json:"id"`
	Cohort     string     `json:"cohort"`
	State      string     `json:"state"`
	LastSeen   *time.Time `json:"last_seen"`
	Connection string     `json:"connection"`
	Issued     uint64     `json:"issued_revision"`
	Reported   uint64     `json:"reported_revision"`
	Ack        *bool      `json:"acknowledged"`
}
type pilotObservation struct {
	Device     string    `json:"device_id"`
	Generation uint64    `json:"generation"`
	Action     string    `json:"action_ref"`
	Session    string    `json:"session_ref"`
	Received   time.Time `json:"received_at"`
	Revision   uint64    `json:"policy_revision"`
	Mode       string    `json:"mode"`
	Verdict    string    `json:"verdict"`
	WouldBlock *bool     `json:"would_block"`
}
type pilotInstall struct {
	Device     string  `json:"device_id"`
	ID         string  `json:"installation_ref"`
	Generation uint64  `json:"generation"`
	Digest     *string `json:"manifest_digest"`
}
type pilotPack struct {
	Schema    string    `json:"schema_version"`
	Org       string    `json:"organization_id"`
	Work      string    `json:"workspace_id"`
	Env       string    `json:"environment_id"`
	At        time.Time `json:"captured_at"`
	Selection struct {
		Cohort  string `json:"pilot_cohort,omitempty"`
		Device  string `json:"device_id,omitempty"`
		Session string `json:"endpoint_session_ref,omitempty"`
	} `json:"selection"`
	Assigned          string             `json:"assigned_fleet"`
	External          string             `json:"external_verification"`
	Effect            string             `json:"target_effect"`
	Usage             string             `json:"skill_usage"`
	DevicesTruncated  *bool              `json:"devices_truncated"`
	ActionsTruncated  *bool              `json:"actions_truncated"`
	InstallsTruncated *bool              `json:"installations_truncated"`
	Devices           []pilotDevice      `json:"devices"`
	Actions           []pilotObservation `json:"observations"`
	Installs          []pilotInstall     `json:"installations"`
}

var pilotLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var manifestHash = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func productIDValid(s string) bool {
	id, err := domain.ParseProductID(s)
	return err == nil && !id.IsZero()
}

func (p *pilotPack) valid(s complianceFrozenSnapshot) bool {
	if p.Schema != "managed-pilot-evidence.v1" || p.Org != s.Organization || p.Work != s.Workspace || p.Env != s.Environment || !p.At.Equal(s.At) ||
		p.Assigned != "unknown" || p.External != "unknown" || p.Effect != "unknown" || p.Usage != "unknown" ||
		p.DevicesTruncated == nil || p.ActionsTruncated == nil || p.InstallsTruncated == nil || p.Devices == nil || p.Actions == nil || p.Installs == nil ||
		len(p.Devices) > 100 || len(p.Actions) > 100 || len(p.Installs) > 100 {
		return false
	}
	sel := p.Selection
	if sel.Cohort != "" {
		if !pilotLabel.MatchString(sel.Cohort) || sel.Device != "" || sel.Session != "" {
			return false
		}
	} else if !productIDValid(sel.Device) || (sel.Session != "" && !complianceToken.MatchString(sel.Session)) {
		return false
	}
	selected := map[string]bool{}
	for _, d := range p.Devices {
		if !productIDValid(d.ID) || selected[d.ID] || !pilotLabel.MatchString(d.Cohort) || d.Ack == nil ||
			!slices.Contains([]string{"pending", "active", "retired"}, d.State) || !slices.Contains([]string{"never_seen", "online", "stale", "retired"}, d.Connection) ||
			(sel.Device != "" && d.ID != sel.Device) || (sel.Cohort != "" && d.Cohort != sel.Cohort) {
			return false
		}
		selected[d.ID] = true
	}
	for _, a := range p.Actions {
		if !selected[a.Device] || a.Generation == 0 || a.Received.IsZero() || !complianceToken.MatchString(a.Action) || !complianceToken.MatchString(a.Session) || (sel.Session != "" && a.Session != sel.Session) ||
			!slices.Contains([]string{"", "monitor", "enforce"}, a.Mode) || !slices.Contains([]string{"continue", "deny", "unavailable"}, a.Verdict) || a.WouldBlock == nil {
			return false
		}
	}
	for _, i := range p.Installs {
		if !selected[i.Device] || !complianceToken.MatchString(i.ID) || i.Generation == 0 || (i.Digest != nil && !manifestHash.MatchString(*i.Digest)) {
			return false
		}
	}
	return true
}

func renderPilotPackage(l complianceExportLease, s complianceFrozenSnapshot) (compliancePreparedArtifact, error) {
	var stored struct {
		pilotPack
		Tickets         []pilotTicketInput `json:"ticket_proof_inputs"`
		ProofsTruncated *bool              `json:"ticket_proofs_truncated"`
		ProofsAmbiguous *bool              `json:"ticket_proofs_ambiguous"`
	}
	decoder := json.NewDecoder(bytes.NewReader(s.PilotEvidencePack))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF || !stored.pilotPack.valid(s) {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	p := stored.pilotPack
	if (stored.Tickets == nil) != (stored.ProofsTruncated == nil) || (stored.Tickets == nil) != (stored.ProofsAmbiguous == nil) {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	checks, valid := pilotTicketChecks(p, stored.Tickets)
	if !valid {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	if len(checks) > 0 {
		p.External = "see_independent_ticket_checks"
	}
	for _, check := range checks {
		if check.Effect != "unknown" {
			p.Effect = "see_independent_ticket_checks"
			break
		}
	}
	// Count only the registered records included in this frozen snapshot.
	// A truncated page and an unknown MDM assignment have different meanings.
	type shownCounts struct {
		Registered   int `json:"registered"`
		Enrolled     int `json:"enrolled"`
		Online       int `json:"online"`
		Acknowledged int `json:"acknowledged"`
	}
	counts := shownCounts{Registered: len(p.Devices)}
	for _, device := range p.Devices {
		if device.State == "active" {
			counts.Enrolled++
		}
		if device.Connection == "online" {
			counts.Online++
		}
		if *device.Ack {
			counts.Acknowledged++
		}
	}
	document, err := json.Marshal(struct {
		pilotPack
		Shown           shownCounts        `json:"shown_device_counts"`
		Checks          []pilotTicketCheck `json:"independent_ticket_checks,omitempty"`
		ProofsTruncated *bool              `json:"ticket_proofs_truncated,omitempty"`
		ProofsAmbiguous *bool              `json:"ticket_proofs_ambiguous,omitempty"`
	}{p, counts, checks, stored.ProofsTruncated, stored.ProofsAmbiguous})
	if err != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	var readable, records bytes.Buffer
	writer := csv.NewWriter(&records)
	writer.Write([]string{"section", "device_id", "reference", "field", "value"})
	fmt.Fprintf(&readable, "# Managed pilot evidence\n\nEnvironment %s. Captured %s.\n\n", p.Env, p.At.UTC().Format(time.RFC3339))
	if p.Selection.Cohort != "" {
		fmt.Fprintf(&readable, "Pilot cohort %s.\n\n", p.Selection.Cohort)
	} else {
		fmt.Fprintf(&readable, "Device %s.\n", p.Selection.Device)
		if p.Selection.Session != "" {
			fmt.Fprintf(&readable, "Device-bound session %s.\n", p.Selection.Session)
		}
	}
	if len(checks) == 0 {
		fmt.Fprint(&readable, "The following facts were reported to this Environment. The assigned fleet, external verification, target effects and skill usage are unknown.\n\n")
	} else {
		fmt.Fprint(&readable, "Independent checks apply to the linked synthetic ticket actions and observation windows only. The assigned fleet, other target effects and skill usage are unknown.\n\n")
	}
	writer.Write([]string{"coverage", "", "", "assigned_fleet", p.Assigned})
	writer.Write([]string{"coverage", "", "", "external_verification", p.External})
	writer.Write([]string{"coverage", "", "", "target_effect", p.Effect})
	writer.Write([]string{"coverage", "", "", "skill_usage", p.Usage})
	fmt.Fprintf(&readable, "Among the %d registered devices shown, %d enrolled devices are active, %d are online and %d acknowledged their current policy.\n\n", counts.Registered, counts.Enrolled, counts.Online, counts.Acknowledged)
	fmt.Fprintf(&readable, "## Registered devices (%d shown)\n\n", len(p.Devices))
	for _, d := range p.Devices {
		fmt.Fprintf(&readable, "- %s · %s · %s · %s · issued revision %d, reported %d, acknowledged %t\n", d.ID, d.Cohort, d.State, d.Connection, d.Issued, d.Reported, *d.Ack)
		row := func(field, value string) { writer.Write([]string{"device", d.ID, "", field, value}) }
		row("cohort", d.Cohort)
		row("state", d.State)
		row("connection", d.Connection)
		row("issued_revision", strconv.FormatUint(d.Issued, 10))
		row("reported_revision", strconv.FormatUint(d.Reported, 10))
		row("policy_acknowledged", strconv.FormatBool(*d.Ack))
	}
	fmt.Fprintf(&readable, "\n## Endpoint observations (%d shown)\n\n", len(p.Actions))
	for _, a := range p.Actions {
		stamp := a.Received.UTC().Format(time.RFC3339)
		fmt.Fprintf(&readable, "- %s · %s · session %s · action %s · policy %d · %s %s · would block %t\n", stamp, a.Device, a.Session, a.Action, a.Revision, a.Mode, a.Verdict, *a.WouldBlock)
		row := func(field, value string) { writer.Write([]string{"observation", a.Device, a.Action, field, value}) }
		row("received_at", stamp)
		row("session_ref", a.Session)
		row("policy_revision", strconv.FormatUint(a.Revision, 10))
		row("mode", a.Mode)
		row("verdict", a.Verdict)
		row("would_block", strconv.FormatBool(*a.WouldBlock))
	}
	if stored.Tickets != nil {
		fmt.Fprintf(&readable, "\n## Independent synthetic ticket checks (%d shown)\n\n", len(checks))
		fmt.Fprint(&readable, "Only receipt-backed completed tests with matching device, generation, cohort, policy, session, protected action and observation window are eligible. Missing or ambiguous evidence leaves the target effect unknown. A passed result also requires the signed positive control from that session.\n")
		for _, r := range checks {
			start, end := r.WindowStart.UTC().Format(time.RFC3339Nano), r.WindowEnd.UTC().Format(time.RFC3339Nano)
			effect := "The protected write could not be verified."
			switch r.Effect {
			case "no_protected_write_in_verified_window":
				effect = "The recorder saw the allowed control write and no protected write during this window."
			case "protected_write_recorded":
				effect = "The recorder saw a protected write."
			}
			fmt.Fprintf(&readable, "- Run %s · %s (%s). %s Window %s to %s. Cohort %s · device %s generation %d · session %s · action %s · revision %d · submitted %s · evidence SHA-256 %s\n", r.Run, r.Verdict, strings.ReplaceAll(r.Reason, "_", " "), effect, start, end, r.Cohort, r.Device, r.Generation, r.Session, r.Action, r.Revision, r.At.UTC().Format(time.RFC3339), r.Digest)
			for _, v := range [][2]string{{"run_id", r.Run}, {"cohort", r.Cohort}, {"window_start", start}, {"window_end", end}, {"session_ref", r.Session}, {"generation", strconv.FormatUint(r.Generation, 10)}, {"policy_revision", strconv.FormatUint(r.Revision, 10)}, {"evidence_source", r.Source}, {"submitted_at", r.At.UTC().Format(time.RFC3339)}, {"verdict", r.Verdict}, {"reason", r.Reason}, {"protected_ticket_effect", r.Effect}, {"evidence_sha256", r.Digest}} {
				writer.Write([]string{"ticket_check", r.Device, r.Action, v[0], v[1]})
			}
		}
		for _, v := range []struct {
			k string
			b bool
		}{{"ticket_proofs_truncated", *stored.ProofsTruncated}, {"ticket_proofs_ambiguous", *stored.ProofsAmbiguous}} {
			writer.Write([]string{"coverage", "", "", v.k, strconv.FormatBool(v.b)})
		}
		fmt.Fprintf(&readable, "Additional matching checks omitted: %t. Ambiguous matches omitted: %t.\n", *stored.ProofsTruncated, *stored.ProofsAmbiguous)
	}
	fmt.Fprintf(&readable, "\n## Observed installations (%d shown)\n\n", len(p.Installs))
	for _, i := range p.Installs {
		value := "unknown"
		if i.Digest != nil {
			value = *i.Digest
		}
		fmt.Fprintf(&readable, "- %s · installation %s · generation %d · digest %s\n", i.Device, i.ID, i.Generation, value)
		writer.Write([]string{"installation", i.Device, i.ID, "manifest_digest", value})
		writer.Write([]string{"installation", i.Device, i.ID, "generation", strconv.FormatUint(i.Generation, 10)})
	}
	fmt.Fprintf(&readable, "\nTruncated device list: %t. Truncated observations: %t. Truncated installation list: %t.\n", *p.DevicesTruncated, *p.ActionsTruncated, *p.InstallsTruncated)
	for _, row := range []struct {
		k string
		v bool
	}{{"devices_truncated", *p.DevicesTruncated}, {"actions_truncated", *p.ActionsTruncated}, {"installations_truncated", *p.InstallsTruncated}} {
		writer.Write([]string{"coverage", "", "", row.k, strconv.FormatBool(row.v)})
	}
	writer.Flush()
	if writer.Error() != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	return buildSectionPackage(l, document, records.Bytes(), readable.String())
}
