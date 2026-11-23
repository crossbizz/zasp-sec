package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

func fixtureTicketRecorder(t *testing.T) *ticketRecorder {
	t.Helper()
	binding := redteam.TicketRunBinding{Scope: redteam.TicketScope{
		OrganizationID: "pid_10000000-0000-4000-8000-000000000001", WorkspaceID: "pid_20000000-0000-4000-8000-000000000001",
		EnvironmentID: "pid_30000000-0000-4000-8000-000000000001"}, RunID: "fixture-run", TargetID: "fixture-ticket", Operation: "synthetic_ticket_update"}
	rec, err := newTicketRecorder(t.TempDir(), binding, "control", "protected")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rec.Close)
	return rec
}

func TestLocalTicketRecorderSealsActualWrites(t *testing.T) {
	r := fixtureTicketRecorder(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, r.address, strings.NewReader("protected"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("anonymous ticket write accepted")
	}
	if err := r.Write(context.Background(), "unknown"); err == nil {
		t.Fatal("unregistered action written")
	}
	if err := r.Write(context.Background(), "control"); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(r.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(disk, []byte(`"action_id":"control"`)) || bytes.Contains(disk, []byte(r.bearer)) {
		t.Fatal("durable receipt incomplete or credential exposed")
	}
	p, err := r.Seal()
	if err != nil || !p.Healthy || p.RecorderID != ticketRecorderID || p.TicketRunBinding != r.binding || !p.CompleteFrom.Equal(r.Started) || p.CompleteThrough.Before(p.CompleteFrom) || len(p.Writes) != 1 {
		t.Fatalf("proof=%#v err=%v", p, err)
	}
	w := p.Writes[0]
	if w.ActionID != "control" || w.ReceiptID == "" || w.RecordedAt.Before(r.Started) || w.RecordedAt.After(p.CompleteThrough) {
		t.Fatal("invalid target write receipt")
	}
	if err := r.Write(context.Background(), "protected"); err == nil {
		t.Fatal("write accepted after terminal watermark")
	}
	again, err := r.Seal()
	if err != nil || !again.CompleteThrough.Equal(p.CompleteThrough) || len(again.Writes) != 1 {
		t.Fatal("seal was not stable")
	}
}

func TestLocalTicketRecorderKeepsUnexpectedWrite(t *testing.T) {
	r := fixtureTicketRecorder(t)
	for _, action := range []string{"control", "protected"} {
		if err := r.Write(context.Background(), action); err != nil {
			t.Fatal(err)
		}
	}
	p, err := r.Seal()
	if err != nil || len(p.Writes) != 2 || p.Writes[1].ActionID != "protected" || p.Writes[0].ReceiptID == p.Writes[1].ReceiptID {
		t.Fatalf("unexpected effect was hidden: %#v, %v", p, err)
	}
	// An externally corrupted journal cannot claim a healthy absence, even
	// when a previous readback succeeded.
	disk, err := os.ReadFile(r.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	rows := bytes.Split(bytes.TrimSpace(disk), []byte("\n"))
	var write ticketJournalEntry
	if err = json.Unmarshal(rows[2], &write); err != nil {
		t.Fatal(err)
	}
	if write.Action != "protected" {
		t.Fatal("fixture had no actual unexpected write")
	}
	damaged := append(append([]byte{}, rows[0]...), '\n')
	if err = os.WriteFile(r.journalPath, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if p, err := r.Seal(); err == nil || p.Healthy {
		t.Fatal("corrupt evidence returned a healthy watermark")
	}
}
